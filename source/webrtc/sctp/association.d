/**
 * SCTP association — the state machine that brings up and runs a single SCTP
 * association over which WebRTC data channels flow. This module currently covers
 * the four-way handshake (RFC 4960 §5.1); the data-transfer path (DATA/SACK,
 * congestion control) is added incrementally on top.
 *
 * Laundered from webrtc-rs's rtc-sctp `association/mod.rs`, distilled to the
 * protocol logic. rust wraps this in an Endpoint with event/stream plumbing; we
 * expose a leaner sans-io surface fit for a vibe driver: feed inbound packets
 * with `handleInbound`, drain outbound packets with `gatherOutbound`, and drive
 * timers with `now` (caller-supplied ms) — no OS clock, deterministic.
 *
 * SCTP ports are fixed at 5000 for WebRTC. Verification tag and initial TSN are
 * supplied by the caller (the endpoint) so the state machine stays testable.
 */
module webrtc.sctp.association;

import libsodium : randombytes_buf;

import webrtc.sctp.packet : Packet, Chunk, CT_INIT, CT_INIT_ACK, CT_COOKIE_ECHO, CT_COOKIE_ACK;
import webrtc.sctp.chunk.init : InitChunk;
import webrtc.sctp.param : Param, PARAM_STATE_COOKIE, PARAM_SUPPORTED_EXTENSIONS,
	PARAM_FORWARD_TSN_SUPPORTED;
import webrtc.sctp.timer : RtoManager, TimerTable, TimerConfig, Timer;

/// Which end initiated the association.
enum Side
{
	client, // initiator
	server, // acceptor
}

/// Association handshake / lifecycle state (RFC 4960).
enum AssociationState
{
	closed,
	cookieWait,
	cookieEchoed,
	established,
	shutdownPending,
	shutdownSent,
	shutdownReceived,
	shutdownAckSent,
}

private enum ushort SCTP_PORT = 5000; // WebRTC fixes both SCTP ports at 5000.
private enum size_t COOKIE_SIZE = 32;
private enum uint DEFAULT_RWND = 1024 * 1024;

/// A single SCTP association.
final class Association
{
	private Side side;
	private AssociationState state_ = AssociationState.closed;
	private bool handshakeCompleted;

	private uint myVerificationTag;
	private uint peerVerificationTag;
	private uint myNextTsn;
	private uint peerLastTsn;
	private uint cumulativeTsnAckPoint;

	private ushort sourcePort = SCTP_PORT;
	private ushort destinationPort = SCTP_PORT;
	private ushort myMaxInboundStreams = 1024;
	private ushort myMaxOutboundStreams = 1024;
	private uint maxReceiveBufferSize = DEFAULT_RWND;
	private uint rwnd;
	private uint ssthresh;
	private uint cwnd;

	private ubyte[] myCookie; // server: the cookie we minted (to verify the echo)
	private InitChunk storedInit; // client: the INIT we sent (for retransmit)
	private bool hasStoredInit;
	private ubyte[] storedCookieEcho; // client: the cookie to echo
	private bool useForwardTsn;

	private Packet[] controlQueue; // outbound control packets awaiting send

	RtoManager rtoMgr;
	private TimerTable timers;

	/// Create an association. `verificationTag` and `initialTsn` come from the
	/// endpoint (non-zero). A client immediately queues its INIT.
	this(Side side, uint verificationTag, uint initialTsn, long now)
	{
		this.side = side;
		this.myVerificationTag = verificationTag;
		this.myNextTsn = initialTsn == 0 ? 1 : initialTsn;
		this.cumulativeTsnAckPoint = this.myNextTsn - 1;
		this.rtoMgr = RtoManager.init;
		this.rtoMgr.rto = 3000;
		this.timers = TimerTable(TimerConfig());
		immutable mtu = 1200;
		this.cwnd = clampCwnd(2 * mtu);

		if (side == Side.client)
		{
			InitChunk init;
			init.initiateTag = myVerificationTag;
			init.advertisedReceiverWindowCredit = maxReceiveBufferSize;
			init.numOutboundStreams = myMaxOutboundStreams;
			init.numInboundStreams = myMaxInboundStreams;
			init.initialTsn = myNextTsn;
			init.params ~= supportedExtensionsParam();
			storedInit = init;
			hasStoredInit = true;
			setState(AssociationState.cookieWait);
			sendInit();
			timers.start(Timer.t1Init, now, rtoMgr.getRto());
		}
	}

	AssociationState state() const @safe pure nothrow @nogc
	{
		return state_;
	}

	bool isEstablished() const @safe pure nothrow @nogc
	{
		return state_ == AssociationState.established;
	}

	/// Feed a received SCTP packet in. Control responses are queued for the next
	/// `gatherOutbound`.
	void handleInbound(scope const(ubyte)[] raw, long now)
	{
		auto p = Packet.unmarshal(raw);
		foreach (ref c; p.chunks)
			handleChunk(p, c, now);
	}

	/// Drain the packets the association wants to send, marshaled and ready for
	/// the wire.
	ubyte[][] gatherOutbound(long now)
	{
		ubyte[][] outs;
		foreach (ref pkt; controlQueue)
			outs ~= pkt.marshal;
		controlQueue = [];
		return outs;
	}

	// ---- chunk dispatch --------------------------------------------------------

	private void handleChunk(ref Packet p, ref Chunk c, long now)
	{
		switch (c.typ)
		{
		case CT_INIT:
			handleInit(p, InitChunk.fromChunk(c));
			break;
		case CT_INIT_ACK:
			handleInitAck(p, InitChunk.fromChunk(c), now);
			break;
		case CT_COOKIE_ECHO:
			handleCookieEcho(c.value);
			break;
		case CT_COOKIE_ACK:
			handleCookieAck();
			break;
		default:
			break; // DATA/SACK/etc. handled once the data path lands
		}
	}

	// Server: got INIT → reply INIT ACK carrying a fresh state cookie.
	private void handleInit(ref Packet p, InitChunk i)
	{
		if (state_ != AssociationState.closed && state_ != AssociationState.cookieWait
			&& state_ != AssociationState.cookieEchoed)
			return;

		adoptPeer(i, p);

		InitChunk ack;
		ack.isAck = true;
		ack.initiateTag = myVerificationTag;
		ack.advertisedReceiverWindowCredit = maxReceiveBufferSize;
		ack.numOutboundStreams = myMaxOutboundStreams;
		ack.numInboundStreams = myMaxInboundStreams;
		ack.initialTsn = myNextTsn;
		if (myCookie.length == 0)
			myCookie = randomBytes(COOKIE_SIZE);
		ack.params ~= Param(PARAM_STATE_COOKIE, myCookie.dup);
		ack.params ~= supportedExtensionsParam();

		controlQueue ~= createPacket([ack.toChunk()]);
	}

	// Client: got INIT ACK → send COOKIE ECHO, move to COOKIE-ECHOED.
	private void handleInitAck(ref Packet p, InitChunk i, long now)
	{
		if (state_ != AssociationState.cookieWait)
			return;
		adoptPeer(i, p);
		timers.stop(Timer.t1Init);
		hasStoredInit = false;

		ubyte[] cookie;
		foreach (ref prm; i.params)
			if (prm.typ == PARAM_STATE_COOKIE)
				cookie = prm.value.dup;
		if (cookie.length == 0)
			return; // ErrInitAckNoCookie

		storedCookieEcho = cookie;
		controlQueue ~= createPacket([Chunk(CT_COOKIE_ECHO, 0, cookie.dup)]);
		timers.start(Timer.t1Cookie, now, rtoMgr.getRto());
		setState(AssociationState.cookieEchoed);
	}

	// Server: got COOKIE ECHO → verify cookie, become Established, reply ACK.
	private void handleCookieEcho(scope const(ubyte)[] cookie)
	{
		if (myCookie.length == 0 || myCookie != cookie)
			return;
		if (state_ == AssociationState.closed || state_ == AssociationState.cookieWait
			|| state_ == AssociationState.cookieEchoed)
		{
			timers.stop(Timer.t1Init);
			timers.stop(Timer.t1Cookie);
			hasStoredInit = false;
			setState(AssociationState.established);
			handshakeCompleted = true;
		}
		controlQueue ~= createPacket([Chunk(CT_COOKIE_ACK, 0, [])]);
	}

	// Client: got COOKIE ACK → become Established.
	private void handleCookieAck()
	{
		if (state_ != AssociationState.cookieEchoed)
			return;
		timers.stop(Timer.t1Cookie);
		setState(AssociationState.established);
		handshakeCompleted = true;
	}

	// ---- helpers ---------------------------------------------------------------

	// Adopt peer parameters from an INIT / INIT ACK.
	private void adoptPeer(ref InitChunk i, ref Packet p)
	{
		if (i.numInboundStreams < myMaxInboundStreams)
			myMaxInboundStreams = i.numInboundStreams;
		if (i.numOutboundStreams < myMaxOutboundStreams)
			myMaxOutboundStreams = i.numOutboundStreams;
		peerVerificationTag = i.initiateTag;
		sourcePort = p.destinationPort;
		destinationPort = p.sourcePort;
		peerLastTsn = i.initialTsn == 0 ? uint.max : i.initialTsn - 1;
		rwnd = i.advertisedReceiverWindowCredit;
		ssthresh = rwnd;
		foreach (ref prm; i.params)
			if (prm.typ == PARAM_SUPPORTED_EXTENSIONS)
				foreach (t; prm.value)
					if (t == 192) // CT_FORWARD_TSN
						useForwardTsn = true;
	}

	private void sendInit()
	{
		controlQueue ~= createPacket([storedInit.toChunk()]);
	}

	private Packet createPacket(Chunk[] chunks)
	{
		Packet p;
		p.sourcePort = sourcePort;
		p.destinationPort = destinationPort;
		p.verificationTag = peerVerificationTag;
		p.chunks = chunks;
		return p;
	}

	private void setState(AssociationState s) @safe pure nothrow @nogc
	{
		state_ = s;
	}
}

private Param supportedExtensionsParam() @safe pure nothrow
{
	// Advertise FORWARD-TSN (192) and RE-CONFIG (130) support.
	return Param(PARAM_SUPPORTED_EXTENSIONS, cast(ubyte[])[192, 130]);
}

private uint clampCwnd(uint v) @safe pure nothrow @nogc
{
	// RFC 4960 §7.2.1: min(4*MTU, max(2*MTU, 4380)).
	if (v < 4380)
		return 4380;
	return v;
}

private ubyte[] randomBytes(size_t n) @trusted
{
	auto b = new ubyte[n];
	randombytes_buf(b.ptr, n);
	return b;
}
