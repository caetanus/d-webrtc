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

import std.algorithm : min;
import std.typecons : Nullable, nullable;

import libsodium : randombytes_buf;

import webrtc.sctp.packet : Packet, Chunk, CT_INIT, CT_INIT_ACK, CT_COOKIE_ECHO, CT_COOKIE_ACK,
	CT_PAYLOAD_DATA, CT_SACK;
import webrtc.sctp.chunk.init : InitChunk;
import webrtc.sctp.chunk.data : DataChunk;
import webrtc.sctp.chunk.sack : SackChunk, GapAckBlock;
import webrtc.sctp.param : Param, PARAM_STATE_COOKIE, PARAM_SUPPORTED_EXTENSIONS,
	PARAM_FORWARD_TSN_SUPPORTED;
import webrtc.sctp.queue.payload : PayloadData, PayloadQueue;
import webrtc.sctp.queue.pending : PendingQueue;
import webrtc.sctp.reassembly : ReassemblyQueue, Chunks;
import webrtc.sctp.sna : sna32lt, sna32lte, sna32gt, sna32gte;
import webrtc.sctp.timer : RtoManager, TimerTable, TimerConfig, Timer;

/// A user message reassembled from a peer's data channel, ready for delivery.
struct InboundMessage
{
	ushort streamId;
	uint ppid; // payload protocol identifier
	ubyte[] data;
}

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

	// ---- data path -----------------------------------------------------------
	private uint mtu = 1200;
	private uint maxPayloadSize; // largest user-data fragment that fits one DATA chunk
	private PendingQueue pendingQueue; // outbound, not yet assigned a TSN
	private PayloadQueue inflightQueue; // outbound, sent but not yet SACKed
	private PayloadQueue payloadQueue; // inbound TSN accounting (gap-acks, dups)
	private ReassemblyQueue[ushort] streams; // per-stream inbound reassembly
	private ushort[ushort] nextSSN; // per-stream outbound sequence number (ordered)
	private uint partialBytesAcked; // congestion-avoidance accounting
	private uint minTsn2measureRtt; // Karn's algorithm: lowest TSN eligible for RTT
	private bool ackImmediate; // a SACK is owed on the next gatherOutbound
	private InboundMessage[] inbound; // reassembled messages awaiting receive()

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
		this.cwnd = clampCwnd(2 * mtu);
		// One DATA chunk = common header (12) + DATA header (16) of overhead.
		this.maxPayloadSize = mtu - 12 - 16;
		this.minTsn2measureRtt = this.myNextTsn;

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
	/// the wire: pending control packets first, then (once Established) any DATA
	/// the send window allows and a SACK if one is owed.
	ubyte[][] gatherOutbound(long now)
	{
		ubyte[][] outs;
		foreach (ref pkt; controlQueue)
			outs ~= pkt.marshal;
		controlQueue = [];

		if (state_ == AssociationState.established)
		{
			gatherOutboundData(outs, now);
			gatherOutboundSack(outs);
		}
		return outs;
	}

	/// Queue a user message on `streamId` for sending. `ppid` is the payload
	/// protocol identifier (e.g. PPID_STRING). `ordered` selects ordered vs
	/// unordered delivery. The message is fragmented to the path MTU and pushed
	/// to the pending queue; the fragments go on the wire on the next
	/// `gatherOutbound` as the congestion/receive windows allow.
	void send(ushort streamId, uint ppid, scope const(ubyte)[] data, bool ordered)
	{
		immutable unordered = !ordered;
		immutable ssn = unordered ? cast(ushort) 0 : nextSSN.get(streamId, cast(ushort) 0);

		size_t off;
		immutable total = data.length;
		bool first = true;
		do
		{
			immutable fragLen = min(maxPayloadSize, total - off);
			PayloadData p;
			p.data.streamIdentifier = streamId;
			p.data.payloadType = ppid;
			p.data.unordered = unordered;
			p.data.beginningFragment = first;
			p.data.endingFragment = (off + fragLen == total);
			p.data.streamSequenceNumber = ssn;
			p.data.userData = data[off .. off + fragLen].dup;
			pendingQueue.push(p);
			off += fragLen;
			first = false;
		}
		while (off < total);

		// RFC 4960 §6.6: the SSN only advances for ordered messages.
		if (!unordered)
			nextSSN[streamId] = cast(ushort)(ssn + 1);
	}

	/// Pop the next fully reassembled inbound message, or null if none is ready.
	Nullable!InboundMessage receive() @safe pure nothrow
	{
		if (inbound.length == 0)
			return Nullable!InboundMessage.init;
		auto m = inbound[0];
		inbound = inbound[1 .. $];
		return nullable(m);
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
		case CT_PAYLOAD_DATA:
			handleData(DataChunk.fromChunk(c));
			break;
		case CT_SACK:
			handleSack(SackChunk.fromChunk(c), now);
			break;
		default:
			break; // heartbeat/shutdown/reconfig/forward-tsn not yet handled
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

	// ---- data transfer --------------------------------------------------------

	// Receiver: got a DATA chunk. Track its TSN for SACK, hand it to the stream's
	// reassembly, advance the cumulative point over now-contiguous TSNs, and note
	// that a SACK is owed. (RFC 4960 §6.2 / §6.9.)
	private void handleData(DataChunk d)
	{
		PayloadData pd;
		pd.data = d;
		immutable canPush = payloadQueue.canPush(pd, peerLastTsn);
		if (canPush && getMyReceiverWindowCredit() > 0)
		{
			payloadQueue.push(pd, peerLastTsn);
			auto rq = getOrCreateStream(d.streamIdentifier);
			if (rq.push(d))
				drainReadable(d.streamIdentifier);
		}
		// else: receive buffer full or duplicate — drop; sender retransmits.

		// Advance peer_last_tsn across every now-contiguous received TSN.
		while (!payloadQueue.pop(peerLastTsn + 1).isNull)
			peerLastTsn += 1;

		// Simplified acking: no delayed-ack timer — a SACK is owed for every DATA
		// (RFC 4960 permits delaying, but immediate acking is always correct).
		ackImmediate = true;
	}

	// Sender: got a SACK. Release cumulatively-acked in-flight chunks, mark
	// gap-acked ones, advance the cumulative ack point, run congestion control,
	// and recompute rwnd. (RFC 4960 §6.2.1.)
	private void handleSack(SackChunk d, long now)
	{
		if (state_ != AssociationState.established)
			return;
		// Drop an out-of-order SACK older than our cumulative point.
		if (sna32gt(cumulativeTsnAckPoint, d.cumulativeTsnAck))
			return;

		long totalBytesAcked;

		// Pop every in-flight chunk up to and including the cumulative ack.
		uint i = cumulativeTsnAckPoint + 1;
		while (sna32lte(i, d.cumulativeTsnAck))
		{
			auto c = inflightQueue.pop(i);
			if (!c.isNull)
			{
				if (!c.get.acked)
				{
					if (i == cumulativeTsnAckPoint + 1)
						timers.stop(Timer.t3RTX);
					totalBytesAcked += c.get.data.userData.length;
					measureRtt(c.get, now);
				}
			}
			i += 1;
		}

		// Mark selectively-acked (gap block) chunks.
		foreach (ref g; d.gapAckBlocks)
			for (uint off = g.start; off <= g.end; off++)
			{
				immutable tsn = d.cumulativeTsnAck + off;
				if (auto c = inflightQueue.get(tsn))
					if (!c.acked)
					{
						totalBytesAcked += inflightQueue.markAsAcked(tsn);
						measureRtt(*c, now);
					}
			}

		if (sna32lt(cumulativeTsnAckPoint, d.cumulativeTsnAck))
		{
			cumulativeTsnAckPoint = d.cumulativeTsnAck;
			onCumulativeTsnAckPointAdvanced(totalBytesAcked, now);
		}

		// RFC 4960 §6.2.1 D-ii: rwnd = a_rwnd − bytes still outstanding.
		immutable outstanding = cast(uint) inflightQueue.getNumBytes();
		rwnd = outstanding >= d.advertisedReceiverWindowCredit
			? 0 : d.advertisedReceiverWindowCredit - outstanding;
	}

	// Move as much pending data onto the wire as cwnd/rwnd allow, assigning TSNs,
	// and bundle the resulting DATA chunks into MTU-bounded packets.
	private void gatherOutboundData(ref ubyte[][] outs, long now)
	{
		DataChunk[] chunks;
		while (true)
		{
			auto peek = pendingQueue.peek();
			if (peek.isNull)
				break;
			immutable dataLen = peek.get.data.userData.length;
			immutable begin = peek.get.data.beginningFragment;
			immutable unordered = peek.get.data.unordered;

			// One chunk may always fly if nothing is in flight (zero-window probe);
			// otherwise respect cwnd and rwnd.
			immutable haveInflight = !inflightQueue.isEmpty;
			if (haveInflight)
			{
				if (inflightQueue.getNumBytes() + dataLen > cwnd)
					break;
				if (dataLen > rwnd)
					break;
			}
			if (dataLen <= rwnd)
				rwnd -= cast(uint) dataLen;

			auto popped = pendingQueue.pop(begin, unordered);
			if (popped.isNull)
				break;
			PayloadData c = popped.get;
			c.data.tsn = generateNextTsn();
			c.since = now;
			c.nSent = 1;
			inflightQueue.pushNoCheck(c);
			chunks ~= c.data;
		}

		if (chunks.length == 0)
			return;

		timers.restartIfStale(Timer.t3RTX, now, rtoMgr.getRto());

		// Bundle DATA chunks into packets bounded by the path MTU.
		DataChunk[] bundle;
		uint bundleBytes = 12; // common header
		foreach (ref dc; chunks)
		{
			immutable wire = 16 + cast(uint) dc.userData.length;
			if (bundle.length && bundleBytes + wire > mtu)
			{
				outs ~= dataPacket(bundle).marshal;
				bundle = [];
				bundleBytes = 12;
			}
			bundle ~= dc;
			bundleBytes += wire;
		}
		if (bundle.length)
			outs ~= dataPacket(bundle).marshal;
	}

	// Emit a SACK if one is owed (RFC 4960 §6.2).
	private void gatherOutboundSack(ref ubyte[][] outs)
	{
		if (!ackImmediate)
			return;
		ackImmediate = false;
		SackChunk sack;
		sack.cumulativeTsnAck = peerLastTsn;
		sack.advertisedReceiverWindowCredit = getMyReceiverWindowCredit();
		sack.gapAckBlocks = payloadQueue.getGapAckBlocks(peerLastTsn);
		sack.duplicateTsn = payloadQueue.popDuplicates();
		outs ~= createPacket([sack.toChunk()]).marshal;
	}

	// Congestion control on a cumulative-ack advance (RFC 4960 §7.2.1/§7.2.2).
	private void onCumulativeTsnAckPointAdvanced(long totalBytesAcked, long now)
	{
		if (inflightQueue.isEmpty)
			timers.stop(Timer.t3RTX);
		else
			timers.restartIfStale(Timer.t3RTX, now, rtoMgr.getRto());

		if (cwnd <= ssthresh)
		{
			// Slow start: grow by the lesser of bytes acked and cwnd (TCP style),
			// only while the window is being filled.
			if (!pendingQueue.isEmpty)
				cwnd += min(cast(uint) totalBytesAcked, cwnd);
		}
		else
		{
			// Congestion avoidance: grow by one MTU per cwnd bytes acked.
			partialBytesAcked += cast(uint) totalBytesAcked;
			if (partialBytesAcked >= cwnd && !pendingQueue.isEmpty)
			{
				partialBytesAcked -= cwnd;
				cwnd += mtu;
			}
		}
	}

	// Karn's algorithm: take an RTT sample only from a first transmission whose
	// TSN is at or past the eligibility threshold (RFC 4960 §6.3.1 C4/C5).
	private void measureRtt(ref PayloadData c, long now)
	{
		if (c.nSent == 1 && c.since >= 0 && sna32gte(c.data.tsn, minTsn2measureRtt))
		{
			minTsn2measureRtt = myNextTsn;
			immutable rtt = now - c.since;
			if (rtt >= 0)
				rtoMgr.setNewRtt(cast(ulong) rtt);
		}
	}

	private uint getMyReceiverWindowCredit() const @safe pure nothrow
	{
		size_t queued;
		foreach (ref rq; streams)
			queued += rq.nBytes;
		return queued >= maxReceiveBufferSize ? 0 : maxReceiveBufferSize - cast(uint) queued;
	}

	private ReassemblyQueue* getOrCreateStream(ushort si) @safe nothrow
	{
		if (auto s = si in streams)
			return s;
		streams[si] = ReassemblyQueue(si);
		return si in streams;
	}

	// Drain every complete message a stream can now deliver into the inbound queue.
	private void drainReadable(ushort si) @safe nothrow
	{
		auto rq = si in streams;
		if (rq is null)
			return;
		while (rq.isReadable)
		{
			auto set = rq.read();
			if (set.isNull)
				break;
			inbound ~= InboundMessage(si, set.get.ppi, set.get.toPayload());
		}
	}

	private uint generateNextTsn() @safe pure nothrow @nogc
	{
		immutable tsn = myNextTsn;
		myNextTsn += 1;
		return tsn;
	}

	private Packet dataPacket(DataChunk[] chunks)
	{
		Chunk[] cs;
		foreach (ref dc; chunks)
			cs ~= dc.toChunk();
		return createPacket(cs);
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
