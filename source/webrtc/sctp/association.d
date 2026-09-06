/**
 * The SCTP association handshake (RFC 4960 §5), sans-io. This layer brings an
 * association up and names its end; DATA/SACK reliability and the teardown
 * chunks are built on top of it in later steps.
 *
 * The four-way handshake, from the initiator's side:
 *   → INIT           (our Initiate Tag; common header verification tag 0)
 *   ← INIT ACK       (their tag; a State Cookie we must echo back verbatim)
 *   → COOKIE ECHO    (the cookie; common header tag now theirs)
 *   ← COOKIE ACK     established
 * The responder is stateless until the cookie returns: it signs the negotiated
 * parameters into the cookie (HMAC-SHA256 under a per-association secret) and
 * reconstructs the association from the echoed cookie, rejecting one whose MAC
 * does not verify or that has outlived its lifespan. A forged or stale cookie is
 * dropped, not honoured.
 *
 * Verification tags are checked on every inbound packet (RFC 4960 §8.5): a
 * packet not carrying the tag we chose is discarded, INIT (tag 0) and the
 * cookie-bearing exchange being the defined exceptions.
 *
 * Sans-io: `now` (a long of ms) is passed in; connect() and handleTimeout()
 * drive the T1-init / T1-cookie retransmission schedule, and after
 * Max.Init.Retransmits with no answer the association reaches Failed rather than
 * waiting forever.
 */
module webrtc.sctp.association;

import std.digest.hmac : HMAC;
import std.digest.sha : SHA256;
import std.exception : enforce;

import libsodium.randombytes : randombytes_buf;

import webrtc.sctp.packet;

enum Role
{
	client, // the initiator (in libp2p webrtc-direct, the DTLS client / dialer)
	server, // the responder
}

enum AssocState
{
	closed,
	cookieWait, // INIT sent, awaiting INIT ACK
	cookieEchoed, // COOKIE ECHO sent, awaiting COOKIE ACK
	established,
	shutdownPending, // local close requested; draining outstanding data first
	shutdownSent, // SHUTDOWN sent, awaiting SHUTDOWN ACK
	shutdownReceived, // peer's SHUTDOWN seen; draining our data, then SHUTDOWN ACK
	shutdownAckSent, // SHUTDOWN ACK sent, awaiting SHUTDOWN COMPLETE
	failed,
}

// RFC 4960 §15 timers. RTO.Initial and the cap on INIT/COOKIE retransmits before
// the association is abandoned.
private enum long rtoInitialMs = 3000;
private enum size_t maxInitRetransmits = 8; // Max.Init.Retransmits
private enum size_t assocMaxRetrans = 10; // Association.Max.Retrans (RFC 4960 §15)
// A state cookie older than this is stale and refused (RFC 4960 §5.1.5 Valid.Cookie.Life).
private enum long cookieLifeMs = 60_000;

// DATA payload per chunk — small enough that a one-DATA SCTP packet fits inside a
// DTLS record on the 1200-byte link we set — and the per-message reassembly bound.
private enum size_t maxPayload = 1024;
private enum size_t maxMessage = 256 * 1024; // RFC 8831 / DESIGN.md reassembly bound
private enum size_t dataHeaderLen = 12; // TSN(4) + stream(2) + SSN(2) + PPID(4)
private enum size_t initialCwnd = 4 * mtu; // RFC 4960 §7.2.1
private enum size_t maxCwnd = 1024 * 1024; // cap congestion-window growth
private enum size_t recvWindow = 128 * 1024; // our advertised a_rwnd and hard receive cap
private enum size_t sendBufferCap = 1024 * 1024; // app-queued bytes we will hold before refusing
private enum size_t maxGapBlocks = 32; // keep a SACK inside one DTLS record
private enum size_t maxDupTsns = 32;

// RFC 4960 §6.3.1 retransmission timeout bounds and the fast-retransmit trigger.
private enum long rtoMinMs = 1000;
private enum long rtoMaxMs = 60_000;
private enum size_t fastRtxThreshold = 4; // missing reports before a fast retransmit
private enum size_t mtu = 1200; // congestion-window unit
private enum long hbIntervalMs = 30_000; // HB.interval (RFC 4960 §8.3)
private enum ushort paramHeartbeatInfo = 1; // Heartbeat Info parameter type
private enum size_t maxHeartbeatInfo = 64; // a real Heartbeat Info is a handful of bytes

// RFC 6525 RE-CONFIG stream reset.
private enum ushort paramOutgoingReset = 13; // Outgoing SSN Reset Request
private enum ushort paramReconfigResponse = 16; // Re-configuration Response
private enum uint reconfigSuccessNothing = 0; // Success - Nothing to do
private enum uint reconfigSuccessPerformed = 1; // Success - Performed
private enum size_t maxResetStreams = 256; // cap streams per request (bound the parse)

// INIT / INIT ACK carry these fixed fields before their parameters.
private struct InitFields
{
	uint initiateTag;
	uint aRwnd;
	ushort outStreams;
	ushort inStreams;
	uint initialTsn;
}

private enum ushort paramStateCookie = 7;

final class Association
{
	private Role role;
	private ushort localPort;
	private ushort remotePort;
	private AssocState st = AssocState.closed;

	private uint localTag; // our Initiate Tag; the peer must echo it in every packet
	private uint peerTag; // their Initiate Tag; we put it in every packet we send
	private uint localArwnd = 128 * 1024;
	private uint peerArwnd;
	private ushort localOutStreams = 1024;
	private ushort localInStreams = 1024;
	private ushort negotiatedOut;
	private ushort negotiatedIn;
	private uint localInitialTsn;
	private uint peerInitialTsn;

	private ubyte[32] cookieSecret; // server: signs and verifies the state cookie

	// T1 (init / cookie): the chunk in flight is re-sent on the schedule.
	private long t1SentAt;
	private size_t t1Tries;
	private ubyte[] t1Packet; // the exact datagram to retransmit while T1 runs

	private ubyte[][] outbox;

	// --- data transfer state (RFC 4960 §6) --------------------------------------------------
	private uint nextTsn; // next outbound DATA TSN
	private ushort[ushort] nextSsn; // next outbound stream sequence number, per stream
	private uint peerRwnd; // the peer's remaining advertised receive window
	private size_t outstandingBytes; // unacked payload in flight
	private Outstanding[] outstanding; // sent-but-unacked DATA, oldest TSN first
	private Chunk[] sendQueue; // DATA chunks built but not yet sent (window-blocked)

	private uint cumAckTsn; // highest TSN below which everything has been received
	private bool[uint] received; // TSNs received above the initial point (for SACK)
	private Frag[uint] frags; // received fragments not yet reassembled and delivered
	private Message[ushort][ushort] orderedHold; // reassembled ordered messages, by stream then SSN
	private ushort[ushort] expectedSsn; // next in-order SSN to deliver, per stream
	private Message[] inbox; // messages reassembled and ready for the application
	private uint[] dupTsns; // duplicate TSNs to report in the next SACK
	private bool sackPending;
	private size_t cwnd = initialCwnd;
	private size_t ssthresh = size_t.max; // slow-start threshold (RFC 4960 §7.2.1)
	private size_t recvBuffered; // bytes held in the receive path (frags + held + inbox)
	private size_t sendQueuedBytes; // app payload queued but not yet handed to the wire

	// T3-rtx (RFC 4960 §6.3): one retransmission timer, plus the RTT estimator.
	private bool t3Running;
	private long t3StartedAt;
	private long rto = rtoInitialMs;
	private long srtt;
	private long rttvar;
	private bool haveRtt;

	// T2-shutdown (RFC 4960 §9.2): retransmits the in-flight SHUTDOWN / SHUTDOWN ACK.
	private bool t2Running;
	private long t2StartedAt;
	private size_t t2Tries;
	private ubyte[] t2Packet;

	private size_t assocErrorCount; // consecutive retransmit failures (RFC 4960 §8.1)
	private bool shutdownAckPending; // a coalesced SHUTDOWN ACK to (re)send

	// HEARTBEAT (RFC 4960 §8.3): a periodic probe of an idle path.
	private bool hbOutstanding;
	private long hbSentAt;
	private long lastHbSent;
	private ubyte[] hbValue; // the Heartbeat Info parameter we last sent, echoed back on ACK
	private bool hbAckPending; // a coalesced HEARTBEAT ACK to send (one per datagram)
	private ubyte[] hbAckInfo; // the info to echo in it

	// RFC 6525 stream reset. One outgoing request at a time; the rest queue.
	private uint reconfigReqSeq; // our next request sequence number
	private uint reconfigExpectedInSeq; // the next inbound request sequence we expect
	private bool reconfigPending; // a request is in flight
	private uint reconfigPendingSeq; // its sequence number
	private ushort[] reconfigPendingStreams; // the streams it resets
	private ushort[] resetQueue; // streams awaiting a request while one is pending
	private ubyte[] lastReconfigResponse; // cached, to answer a duplicate request
	private ushort[] resetInbound; // streams the peer reset, drained by the caller
	private bool reconfigRunning;
	private long reconfigStartedAt;
	private size_t reconfigTries;
	private ubyte[] reconfigPacket; // the in-flight RE-CONFIG, for retransmission

	this(Role role, ushort localPort, ushort remotePort) @trusted
	{
		this.role = role;
		this.localPort = localPort;
		this.remotePort = remotePort;
		this.localTag = randomTag();
		this.localInitialTsn = randomTag();
		if (role == Role.server)
			randombytes_buf(cookieSecret.ptr, cookieSecret.length);
	}

	// --- observation ------------------------------------------------------------------------

	AssocState state() const @safe pure nothrow @nogc
	{
		return st;
	}

	bool isEstablished() const @safe pure nothrow @nogc
	{
		return st == AssocState.established;
	}

	/// Our Initiate Tag — the tag a peer must echo in every packet it sends us. It
	/// travels in the clear in INIT, so it is observable, not secret.
	uint localInitiateTag() const @safe pure nothrow @nogc
	{
		return localTag;
	}

	/// Unacknowledged payload currently in flight (observability for flow control).
	size_t bytesInFlight() const @safe pure nothrow @nogc
	{
		return outstandingBytes;
	}

	/// The receive window we would advertise now — the cap minus what we hold. It
	/// is what a peer sees in our SACK, so it is observable.
	size_t receiveWindowBytes() const @safe pure nothrow @nogc
	{
		return recvWindow > recvBuffered ? recvWindow - recvBuffered : 0;
	}

	/// Congestion control state, exposed read-only so the retransmission
	/// invariants can be observed and tested (they are not secret).
	size_t congestionWindow() const @safe pure nothrow @nogc
	{
		return cwnd;
	}

	/// The current retransmission timeout in milliseconds.
	long retransmitTimeout() const @safe pure nothrow @nogc
	{
		return rto;
	}

	/// The slow-start threshold in bytes.
	size_t slowStartThreshold() const @safe pure nothrow @nogc
	{
		return ssthresh;
	}

	// --- driving ----------------------------------------------------------------------------

	/// The initiator opens the association: send INIT, await INIT ACK. On the
	/// responder this is a no-op — it answers an inbound INIT instead.
	void connect(long now) @safe
	{
		if (role != Role.client || st != AssocState.closed)
			return;
		st = AssocState.cookieWait;
		auto init = buildInit(ChunkType.init);
		armT1(sctpPacket(0, [init]), now);
	}

	/// Feed a received SCTP datagram (already decrypted from DTLS). Malformed,
	/// hostile, or unauthenticated input is dropped, never escalated — a decode or
	/// parse failure throws internally and is caught here.
	void handleInbound(scope const(ubyte)[] datagram, long now) @safe
	{
		try
		{
			auto p = Packet.decode(datagram);
			foreach (ref c; p.chunks)
			{
				final switch (chunkKind(c.typ))
				{
				case Kind.init:
					onInit(c, now);
					break;
				case Kind.initAck:
					if (verifyTag(p)) onInitAck(c, now);
					break;
				case Kind.cookieEcho:
					onCookieEcho(c, p, now);
					break;
				case Kind.cookieAck:
					if (verifyTag(p)) onCookieAck();
					break;
				case Kind.data:
					if (verifyTag(p)) onData(c);
					break;
				case Kind.sack:
					if (verifyTag(p)) onSack(c, now);
					break;
				case Kind.shutdown:
					if (verifyTag(p)) onShutdown(c, now);
					break;
				case Kind.shutdownAck:
					if (verifyTag(p)) onShutdownAck();
					break;
				case Kind.shutdownComplete:
					if (verifyTag(p)) onShutdownComplete();
					break;
				case Kind.abort:
					if (verifyTag(p)) onAbort();
					break;
				case Kind.heartbeat:
					if (verifyTag(p)) onHeartbeat(c);
					break;
				case Kind.heartbeatAck:
					if (verifyTag(p)) onHeartbeatAck(c);
					break;
				case Kind.reConfig:
					if (verifyTag(p)) onReConfig(c, now);
					break;
				case Kind.other:
					break; // an unrecognised chunk type: ignore
				}
			}
		}
		catch (Exception)
		{
			// malformed, bad checksum, forged/stale cookie, illegal fields: drop
		}
	}

	/// The retransmission timers: T1 for the handshake, T3-rtx for DATA.
	void handleTimeout(long now) @safe
	{
		handleT1(now);
		if (active)
			handleT3(now); // retransmit and probe throughout a graceful close too
		handleT2(now);
		if (st == AssocState.established)
			handleHeartbeat(now);
		if (active)
			handleReconfig(now); // never retransmit into a closed/failed association
	}

	// T1: re-send the in-flight INIT/COOKIE-ECHO, failing after the retransmit cap.
	private void handleT1(long now) @safe
	{
		if (t1Packet is null)
			return;
		if (now - t1SentAt < rtoInitialMs)
			return;
		if (t1Tries >= maxInitRetransmits)
		{
			st = AssocState.failed;
			t1Packet = null;
			return;
		}
		t1Tries++;
		t1SentAt = now;
		outbox ~= t1Packet.dup;
	}

	// T3-rtx (RFC 4960 §6.3.3): on expiry, back off the RTO, collapse the
	// congestion window, and retransmit the earliest unacked chunk. With the
	// window shut and nothing in flight, a zero-window probe rides the same timer.
	private void handleT3(long now) @safe
	{
		if (!t3Running && sendQueue.length && peerRwnd == 0 && outstanding.length == 0)
		{
			t3Running = true; // arm the persist/probe timer
			t3StartedAt = now;
		}
		if (!t3Running || now - t3StartedAt < rto)
			return;

		if (outstanding.length)
		{
			// Association-level failure after too many consecutive retransmits
			// (RFC 4960 §8.1) — this is also the exit from a shutdown that a dead
			// peer would otherwise wedge in a draining state.
			if (++assocErrorCount > assocMaxRetrans)
			{
				st = AssocState.failed;
				t3Running = false;
				return;
			}
			ssthresh = cwnd / 2 > 4 * mtu ? cwnd / 2 : 4 * mtu;
			cwnd = mtu;
			rto = rto * 2 > rtoMaxMs ? rtoMaxMs : rto * 2; // exponential backoff
			outstanding[0].sentAt = now;
			outstanding[0].retransmitted = true;
			outstanding[0].missing = 0;
			outbox ~= sctpPacket(peerTag, [outstanding[0].chunk]);
			t3StartedAt = now;
		}
		else if (sendQueue.length && peerRwnd == 0)
		{
			rto = rto * 2 > rtoMaxMs ? rtoMaxMs : rto * 2;
			forceOneChunk(now); // probe past the closed window to elicit a SACK
			t3StartedAt = now;
		}
		else
			t3Running = false;
	}

	/// Datagrams queued to send, each already a complete SCTP packet. Flushes a
	/// pending SACK and as much window-permitted DATA as will go. `now` stamps the
	/// send time that the RTT estimator and T3-rtx timer read.
	ubyte[][] takeOutbound(long now = 0) @safe
	{
		flush(now);
		auto o = outbox;
		outbox = null;
		return o;
	}

	// --- data transfer API ------------------------------------------------------------------

	/// Queue an application message for reliable delivery on a stream. Ordered by
	/// default; `unordered` skips the per-stream sequence. The message is
	/// fragmented into DATA chunks; sending is window-limited and happens on the
	/// next takeOutbound.
	void send(ushort streamId, uint ppid, scope const(ubyte)[] data, bool unordered = false) @safe
	{
		enforce(st == AssocState.established, "sctp: send before established");
		enforce(data.length >= 1, "sctp: a DATA chunk must carry at least one byte");
		enforce(data.length <= maxMessage, "sctp: message exceeds the reassembly bound");
		enforce(sendQueuedBytes + data.length <= sendBufferCap, "sctp: send buffer full");
		sendQueuedBytes += data.length;

		ushort ssn = 0;
		if (!unordered)
		{
			ssn = nextSsn.get(streamId, cast(ushort) 0);
			nextSsn[streamId] = cast(ushort)(ssn + 1);
		}

		size_t off = 0;
		do
		{
			immutable take = data.length - off < maxPayload ? data.length - off : maxPayload;
			immutable begin = off == 0;
			immutable end = off + take >= data.length;
			ubyte flags = (unordered ? dataFlagUnordered : 0)
				| (begin ? dataFlagBegin : 0) | (end ? dataFlagEnd : 0);

			ubyte[] v = new ubyte[dataHeaderLen];
			writeBe32(v[0 .. 4], nextTsn++);
			writeBe16(v[4 .. 6], streamId);
			writeBe16(v[6 .. 8], ssn);
			writeBe32(v[8 .. 12], ppid);
			v ~= data[off .. off + take];
			sendQueue ~= Chunk(ChunkType.data, flags, v);
			off += take;
		}
		while (off < data.length);
	}

	/// Take the messages reassembled and ready for the application. Draining them
	/// frees the receive buffer, which reopens the window advertised to the peer.
	Message[] receive() @safe
	{
		auto m = inbox;
		inbox = null;
		foreach (ref msg; m)
			recvBuffered -= msg.data.length > recvBuffered ? recvBuffered : msg.data.length;
		return m;
	}

	// --- teardown ---------------------------------------------------------------------------

	/// Begin a graceful close (RFC 4960 §9.2). Outstanding and queued DATA is sent
	/// and acknowledged first; only then does SHUTDOWN go out. A no-op unless the
	/// association is established.
	void shutdown(long now) @safe
	{
		if (st != AssocState.established)
			return;
		if (dataDrained)
			sendShutdown(now);
		else
			st = AssocState.shutdownPending;
	}

	/// Abort immediately (RFC 4960 §9.1): one ABORT, then closed. No handshake,
	/// no retransmission, no waiting.
	void abort() @safe
	{
		if (st == AssocState.closed || st == AssocState.failed)
			return;
		if (peerTag != 0)
			outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.abort, 0, null)]);
		st = AssocState.closed;
		clearT1();
		clearT2();
		t3Running = false;
		// Nothing more may be sent after an ABORT: drop all pending output.
		sendQueue = null;
		sendQueuedBytes = 0;
		outstanding = null;
		outstandingBytes = 0;
		sackPending = false;
		shutdownAckPending = false;
		hbAckPending = false;
		clearReconfig();
		reconfigPending = false;
		resetQueue = null;
	}

	private bool dataDrained() const @safe pure nothrow @nogc
	{
		return outstanding.length == 0 && sendQueue.length == 0;
	}

	// --- RFC 6525 stream reset --------------------------------------------------------------

	/// Reset a stream (RFC 6525) — libp2p webrtc closes a data channel this way.
	/// One request is in flight at a time; further resets queue behind it.
	void resetStream(ushort streamId, long now) @safe
	{
		if (st != AssocState.established)
			return;
		if (reconfigPending)
		{
			import std.algorithm.searching : canFind;

			// Dedup and cap: a stream already in flight or queued is not re-queued,
			// and the queue is bounded (Law 1).
			if (!reconfigPendingStreams.canFind(streamId) && !resetQueue.canFind(streamId)
				&& resetQueue.length < maxResetStreams)
				resetQueue ~= streamId;
			return;
		}
		issueReset([streamId], now);
	}

	/// Whether a stream-reset request is still awaiting its response.
	bool streamResetPending() const @safe pure nothrow @nogc
	{
		return reconfigPending;
	}

	/// Streams the peer has reset (drained), so the caller can close the matching
	/// channels.
	ushort[] takeResetStreams() @safe
	{
		auto s = resetInbound;
		resetInbound = null;
		return s;
	}

	private void issueReset(ushort[] streams, long now) @safe
	{
		if (streams.length > maxResetStreams)
			streams = streams[0 .. maxResetStreams]; // bound the request parameter size
		reconfigPending = true;
		reconfigPendingSeq = reconfigReqSeq++;
		reconfigPendingStreams = streams.dup;
		auto param = outgoingResetRequest(reconfigPendingSeq, reconfigExpectedInSeq - 1,
			nextTsn - 1, streams);
		armReconfig(sctpPacket(peerTag, [Chunk(ChunkType.reConfig, 0, param)]), now);
	}

	private void sendShutdown(long now) @safe
	{
		// SHUTDOWN carries the cumulative TSN we have received.
		ubyte[] v = new ubyte[4];
		writeBe32(v[0 .. 4], cumAckTsn);
		st = AssocState.shutdownSent;
		armT2(sctpPacket(peerTag, [Chunk(ChunkType.shutdown, 0, v)]), now);
	}

	// --- outbound flush ---------------------------------------------------------------------

	private void flush(long now) @safe
	{
		// Once closed or failed, nothing more goes on the wire (§9.1: nothing may
		// follow an ABORT; a dead association sends no DATA/SACK).
		if (!active)
			return;
		if (shutdownAckPending)
		{
			outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.shutdownAck, 0, null)]);
			shutdownAckPending = false;
		}
		if (hbAckPending)
		{
			outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.heartbeatAck, 0, hbAckInfo)]);
			hbAckPending = false;
		}
		if (sackPending)
		{
			outbox ~= sctpPacket(peerTag, [buildSack()]);
			sackPending = false;
		}
		// Send queued DATA while the receive window and congestion window allow,
		// one DATA chunk per packet so each stays inside a DTLS record.
		while (sendQueue.length)
		{
			auto c = sendQueue[0];
			immutable payload = c.value.length - dataHeaderLen;
			if (payload > peerRwnd || outstandingBytes + payload > cwnd)
				break;
			sendQueue = sendQueue[1 .. $];
			sendQueuedBytes -= payload > sendQueuedBytes ? sendQueuedBytes : payload;
			uint tsn = readBe32(c.value[0 .. 4]);
			outstanding ~= Outstanding(tsn, c, payload, now, false, 0, false);
			outstandingBytes += payload;
			peerRwnd = payload > peerRwnd ? 0 : cast(uint)(peerRwnd - payload);
			outbox ~= sctpPacket(peerTag, [c]);
			startT3(now); // arm the retransmission timer once data is in flight
		}
	}

	// Send one queued chunk regardless of the window — a zero-window probe.
	private void forceOneChunk(long now) @safe
	{
		if (sendQueue.length == 0)
			return;
		auto c = sendQueue[0];
		sendQueue = sendQueue[1 .. $];
		immutable payload = c.value.length - dataHeaderLen;
		sendQueuedBytes -= payload > sendQueuedBytes ? sendQueuedBytes : payload;
		immutable tsn = readBe32(c.value[0 .. 4]);
		outstanding ~= Outstanding(tsn, c, payload, now, false, 0, false);
		outstandingBytes += payload;
		outbox ~= sctpPacket(peerTag, [c]);
	}

	// Fast retransmit (RFC 4960 §7.2.4): a chunk reported missing by four SACKs is
	// resent at once, and the congestion window is halved once per event.
	private void fastRetransmit(long now) @safe
	{
		bool adjusted;
		foreach (ref o; outstanding)
		{
			if (o.missing < fastRtxThreshold || o.fastRetransmitted)
				continue;
			if (!adjusted)
			{
				ssthresh = cwnd / 2 > 4 * mtu ? cwnd / 2 : 4 * mtu;
				cwnd = ssthresh;
				adjusted = true;
			}
			o.fastRetransmitted = true;
			o.missing = 0;
			o.sentAt = now;
			o.retransmitted = true;
			outbox ~= sctpPacket(peerTag, [o.chunk]);
		}
		if (adjusted)
			startT3(now); // R1: keep the timer armed after a (re)transmission
	}

	// RFC 4960 §6.3.1 RTT estimator, clamped to [RTO.Min, RTO.Max].
	private void updateRto(long r) @safe pure nothrow @nogc
	{
		if (r < 0)
			r = 0;
		if (!haveRtt)
		{
			srtt = r;
			rttvar = r / 2;
			haveRtt = true;
		}
		else
		{
			immutable delta = srtt > r ? srtt - r : r - srtt;
			rttvar = (3 * rttvar + delta) / 4;
			srtt = (7 * srtt + r) / 8;
		}
		rto = srtt + 4 * rttvar;
		if (rto < rtoMinMs)
			rto = rtoMinMs;
		if (rto > rtoMaxMs)
			rto = rtoMaxMs;
	}

	private void startT3(long now) @safe pure nothrow @nogc
	{
		if (!t3Running)
		{
			t3Running = true;
			t3StartedAt = now;
		}
	}

	private void startT3Restart(long now) @safe pure nothrow @nogc
	{
		t3Running = true;
		t3StartedAt = now;
	}

	// --- inbound DATA / SACK ----------------------------------------------------------------

	// DATA and SACK are processed while the association is up and throughout a
	// graceful close, so a shutdown can still drain and acknowledge in-flight data.
	private bool active() const @safe pure nothrow @nogc
	{
		return st == AssocState.established || st == AssocState.shutdownPending
			|| st == AssocState.shutdownSent || st == AssocState.shutdownReceived
			|| st == AssocState.shutdownAckSent;
	}

	private void onData(ref Chunk c) @safe
	{
		if (!active)
			return;
		enforce(c.value.length >= dataHeaderLen, "sctp: short DATA chunk");
		uint tsn = readBe32(c.value[0 .. 4]);

		// A TSN we have already taken (at or below the cumulative point, or still
		// buffered) is a duplicate: report it and re-send the SACK, nothing more.
		if (tsnLeq(tsn, cumAckTsn) || (tsn in received) !is null)
		{
			if (dupTsns.length < maxDupTsns)
				dupTsns ~= tsn;
			sackPending = true;
			return;
		}

		immutable payloadLen = c.value.length - dataHeaderLen;

		// Receiver flow control (RFC 4960 §6.2): once the advertised window is full
		// we drop rather than buffer without limit. A conformant peer respects the
		// shrinking a_rwnd and never reaches here; a peer that ignores it cannot
		// grow our memory past the window. The SACK still reports a_rwnd = 0.
		if (recvBuffered + payloadLen > recvWindow)
		{
			sackPending = true;
			return;
		}

		Frag f;
		f.streamId = readBe16(c.value[4 .. 6]);
		f.ssn = readBe16(c.value[6 .. 8]);
		f.ppid = readBe32(c.value[8 .. 12]);
		f.flags = c.flags;
		f.payload = c.value[dataHeaderLen .. $].dup;
		frags[tsn] = f;
		received[tsn] = true;
		recvBuffered += payloadLen;

		// Advance the cumulative ack over the now-contiguous run.
		while ((cumAckTsn + 1) in received)
		{
			cumAckTsn++;
			received.remove(cumAckTsn); // covered by the cumulative point now
		}

		reassemble();
		sackPending = true;
	}

	private void onSack(ref Chunk c, long now) @safe
	{
		if (!active)
			return;
		enforce(c.value.length >= 12, "sctp: short SACK");
		immutable cumAck = readBe32(c.value[0 .. 4]);
		immutable aRwnd = readBe32(c.value[4 .. 8]);
		immutable numGap = readBe16(c.value[8 .. 10]);
		immutable numDup = readBe16(c.value[10 .. 12]);
		enforce(12 + numGap * 4 + numDup * 4 <= c.value.length, "sctp: SACK runs past the chunk");

		// The earliest outstanding TSN, captured before the prune, for the RFC 4960
		// §6.3.2 R3 restart rule (restart only when the OLDEST chunk is acked).
		immutable hadOutstanding = outstanding.length > 0;
		immutable earliestTsn = hadOutstanding ? outstanding[0].tsn : 0;

		// The highest TSN this SACK acknowledges (cumulative or any gap block) — a
		// chunk below it that is still unacked has a "missing report".
		uint highestAcked = cumAck;
		{
			size_t pos = 12;
			foreach (_; 0 .. numGap)
			{
				immutable endg = cumAck + readBe16(c.value[pos + 2 .. pos + 4]);
				if (!tsnLeq(endg, highestAcked))
					highestAcked = endg;
				pos += 4;
			}
		}

		// Prune acked chunks, sample the RTT from one non-retransmitted ack, and
		// count missing reports for the rest.
		size_t freed;
		size_t kept;
		bool sampled;
		foreach (ref o; outstanding)
		{
			bool acked = tsnLeq(o.tsn, cumAck);
			if (!acked)
			{
				size_t pos = 12;
				foreach (_; 0 .. numGap)
				{
					immutable start = cumAck + readBe16(c.value[pos .. pos + 2]);
					immutable endg = cumAck + readBe16(c.value[pos + 2 .. pos + 4]);
					if (tsnLeq(start, o.tsn) && tsnLeq(o.tsn, endg))
					{
						acked = true;
						break;
					}
					pos += 4;
				}
			}
			if (acked)
			{
				freed += o.payloadLen;
				if (!sampled && !o.retransmitted) // Karn: never sample a retransmit
				{
					updateRto(now - o.sentAt);
					sampled = true;
				}
			}
			else
			{
				// A still-unacked chunk that sits below a TSN this SACK acked has a
				// missing report (it cannot equal an acked TSN).
				if (tsnLeq(o.tsn, highestAcked))
					o.missing++;
				outstanding[kept++] = o;
			}
		}
		outstanding = outstanding[0 .. kept];
		outstandingBytes -= freed > outstandingBytes ? outstandingBytes : freed;
		if (freed > 0)
			assocErrorCount = 0; // forward progress resets the §8.1 failure counter

		// Congestion control (RFC 4960 §7.2): slow start below ssthresh, else
		// congestion avoidance; capped.
		if (freed > 0)
		{
			if (cwnd <= ssthresh)
				cwnd += freed < mtu ? freed : mtu;
			else
				cwnd += mtu;
			if (cwnd > maxCwnd)
				cwnd = maxCwnd;
		}
		peerRwnd = aRwnd > outstandingBytes ? cast(uint)(aRwnd - outstandingBytes) : 0;

		fastRetransmit(now);

		// T3 (RFC 4960 §6.3.2): stop when nothing is outstanding (R2); restart ONLY
		// when the earliest outstanding chunk was acked (R3). A gap-ack of a higher
		// chunk while the oldest is still lost must NOT reset the timer, so a lost
		// chunk's deadline cannot be deferred forever.
		if (outstanding.length == 0)
			t3Running = false;
		else if (hadOutstanding && tsnLeq(earliestTsn, cumAck))
			startT3Restart(now);

		// A graceful close proceeds once all data has drained: the initiator sends
		// SHUTDOWN, and a peer that already saw SHUTDOWN sends its SHUTDOWN ACK.
		if (st == AssocState.shutdownPending && dataDrained)
			sendShutdown(now);
		else if (st == AssocState.shutdownReceived && dataDrained)
			sendShutdownAck(now);
	}

	// --- teardown handlers ------------------------------------------------------------------

	private void onShutdown(ref Chunk c, long now) @safe
	{
		// The SHUTDOWN's Cumulative TSN Ack acknowledges our sent data (RFC 4960
		// §9.2): prune anything it covers before deciding whether we have drained.
		if (c.value.length >= 4)
		{
			immutable cumAck = readBe32(c.value[0 .. 4]);
			size_t kept;
			foreach (ref o; outstanding)
				if (!tsnLeq(o.tsn, cumAck))
					outstanding[kept++] = o;
				else
					outstandingBytes -= o.payloadLen > outstandingBytes ? outstandingBytes : o.payloadLen;
			outstanding = outstanding[0 .. kept];
		}

		if (st == AssocState.shutdownAckSent)
		{
			shutdownAckPending = true; // coalesced re-ack, not one per duplicate chunk
			return;
		}
		if (st == AssocState.established || st == AssocState.shutdownPending
			|| st == AssocState.shutdownSent || st == AssocState.shutdownReceived)
		{
			// Ack only once our own data has drained; otherwise keep sending and
			// wait in SHUTDOWN-RECEIVED (the drain hook completes it).
			if (dataDrained)
				sendShutdownAck(now);
			else
				st = AssocState.shutdownReceived;
		}
	}

	private void sendShutdownAck(long now) @safe
	{
		st = AssocState.shutdownAckSent;
		armT2(sctpPacket(peerTag, [Chunk(ChunkType.shutdownAck, 0, null)]), now);
	}

	private void onShutdownAck() @safe
	{
		if (st != AssocState.shutdownSent && st != AssocState.shutdownAckSent)
			return;
		outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.shutdownComplete, 0, null)]);
		st = AssocState.closed;
		clearT2();
	}

	private void onShutdownComplete() @safe
	{
		if (st == AssocState.shutdownAckSent || st == AssocState.shutdownSent)
		{
			st = AssocState.closed;
			clearT2();
		}
	}

	private void onAbort() @safe
	{
		st = AssocState.closed;
		clearT1();
		clearT2();
		t3Running = false;
	}

	// --- HEARTBEAT (RFC 4960 §8.3) ----------------------------------------------------------

	// Answer a HEARTBEAT by echoing its Heartbeat Info parameter verbatim — but
	// only on an established path, only for a bounded Info, and at most once per
	// datagram (a packet stuffed with HEARTBEATs must not fan out into many ACKs).
	private void onHeartbeat(ref Chunk c) @safe
	{
		if (st != AssocState.established)
			return;
		if (c.value.length > maxHeartbeatInfo)
			return; // oversized Info: drop rather than echo it back
		if (hbAckPending)
			return; // already answering one this datagram
		hbAckPending = true;
		hbAckInfo = c.value.dup;
	}

	// A HEARTBEAT ACK carrying the info we sent confirms the path is alive.
	private void onHeartbeatAck(ref Chunk c) @safe
	{
		if (hbOutstanding && c.value == hbValue)
		{
			hbOutstanding = false;
			assocErrorCount = 0;
		}
	}

	// Probe an idle path once per HB.interval; an unanswered probe is retried per
	// RTO and, past the error cap, fails the association (path failure → §8.1).
	private void handleHeartbeat(long now) @safe
	{
		// Data in flight already proves the path (T3/SACK cover it): drop a stale
		// idle probe so its timeout cannot double-count against the §8.1 counter.
		if (hbOutstanding && outstanding.length > 0)
			hbOutstanding = false;
		if (hbOutstanding)
		{
			if (now - hbSentAt < rto)
				return;
			if (++assocErrorCount > assocMaxRetrans)
			{
				st = AssocState.failed;
				hbOutstanding = false;
				return;
			}
			hbSentAt = now;
			outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.heartbeat, 0, hbValue)]); // retry
		}
		else if (outstanding.length == 0 && now - lastHbSent >= hbIntervalMs)
		{
			hbValue = newHeartbeatInfo();
			hbOutstanding = true;
			hbSentAt = now;
			lastHbSent = now;
			outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.heartbeat, 0, hbValue)]);
		}
	}

	private ubyte[] newHeartbeatInfo() @trusted
	{
		ubyte[] v = new ubyte[12];
		writeBe16(v[0 .. 2], paramHeartbeatInfo);
		writeBe16(v[2 .. 4], 12); // parameter length: 4 header + 8 nonce
		randombytes_buf(v.ptr + 4, 8);
		return v;
	}

	// --- RFC 6525 RE-CONFIG handling --------------------------------------------------------

	private enum size_t maxReconfigParamsPerDatagram = 8; // bound the work one packet can trigger

	private void onReConfig(ref Chunk c, long now) @safe
	{
		if (st != AssocState.established)
			return;
		// The chunk value is a sequence of TLV parameters. Responses to reset
		// requests are gathered and sent in ONE packet, so a datagram packed with
		// requests cannot fan out into many outbound packets.
		ubyte[] responses;
		size_t pos;
		size_t params;
		while (pos + 4 <= c.value.length && params < maxReconfigParamsPerDatagram)
		{
			immutable ptyp = readBe16(c.value[pos .. pos + 2]);
			immutable plen = readBe16(c.value[pos + 2 .. pos + 4]);
			enforce(plen >= 4 && pos + plen <= c.value.length, "sctp: bad RE-CONFIG parameter");
			auto pval = c.value[pos + 4 .. pos + plen];
			if (ptyp == paramOutgoingReset)
				responses ~= handleIncomingReset(pval);
			else if (ptyp == paramReconfigResponse)
				handleResetResponse(pval, now);
			pos += plen;
			params++;
			while (pos % 4 != 0 && pos < c.value.length)
				pos++;
		}
		if (responses.length)
			outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.reConfig, 0, responses)]);
	}

	// Process one Outgoing SSN Reset Request; return the response parameter to
	// bundle (empty if none).
	private ubyte[] handleIncomingReset(scope const(ubyte)[] v) @safe
	{
		// reqSeq(4), respSeq(4), lastTsn(4), then stream numbers (2 each).
		enforce(v.length >= 12 && (v.length - 12) % 2 == 0, "sctp: malformed reset request");
		enforce((v.length - 12) / 2 <= maxResetStreams, "sctp: too many streams in a reset");
		immutable reqSeq = readBe32(v[0 .. 4]);

		// A duplicate of the last request: re-send the response we cached.
		if (reqSeq == reconfigExpectedInSeq - 1 && lastReconfigResponse !is null)
			return lastReconfigResponse;
		if (reqSeq != reconfigExpectedInSeq)
			return null; // out of sequence: ignore

		// Reset the inbound streams: their sequence restarts, any held-but-
		// undelivered ordered messages are dropped, and any partial fragments for
		// the stream are discarded (they belong to the pre-reset era).
		for (size_t i = 12; i < v.length; i += 2)
		{
			ushort s = readBe16(v[i .. i + 2]);
			expectedSsn[s] = 0;
			nextSsn.remove(s);
			if (s in orderedHold)
			{
				foreach (ref m; orderedHold[s])
					recvBuffered -= m.data.length > recvBuffered ? recvBuffered : m.data.length;
				orderedHold.remove(s);
			}
			dropFragsForStream(s);
			resetInbound ~= s;
		}
		reconfigExpectedInSeq++;
		lastReconfigResponse = reconfigResponse(reqSeq, reconfigSuccessPerformed);
		return lastReconfigResponse;
	}

	// Discard any received fragments belonging to a stream being reset, so a
	// late-arriving End cannot reassemble a stale pre-reset message.
	private void dropFragsForStream(ushort streamId) @safe
	{
		uint[] doomed;
		foreach (tsn, ref f; frags)
			if (f.streamId == streamId)
				doomed ~= tsn;
		foreach (tsn; doomed)
		{
			recvBuffered -= frags[tsn].payload.length > recvBuffered ? recvBuffered
				: frags[tsn].payload.length;
			frags.remove(tsn);
		}
	}

	private void handleResetResponse(scope const(ubyte)[] v, long now) @safe
	{
		enforce(v.length >= 8, "sctp: malformed reset response");
		immutable respSeq = readBe32(v[0 .. 4]);
		immutable result = readBe32(v[4 .. 8]);
		if (!reconfigPending || respSeq != reconfigPendingSeq)
			return;

		// Any matching response ends this request — stop retransmitting. On success
		// our outbound sequence for those streams restarts; a failure (Denied /
		// Bad-Sequence / In-Progress) is given up on rather than hammered until the
		// association dies.
		if (result == reconfigSuccessNothing || result == reconfigSuccessPerformed)
			foreach (s; reconfigPendingStreams)
				nextSsn[s] = 0;
		reconfigPending = false;
		clearReconfig();
		if (resetQueue.length)
		{
			auto q = resetQueue;
			resetQueue = null;
			issueReset(q, now);
		}
	}

	private ubyte[] outgoingResetRequest(uint reqSeq, uint respSeq, uint lastTsn, ushort[] streams) @safe
	{
		ubyte[] pv = new ubyte[12 + 2 * streams.length];
		writeBe32(pv[0 .. 4], reqSeq);
		writeBe32(pv[4 .. 8], respSeq);
		writeBe32(pv[8 .. 12], lastTsn);
		foreach (i, s; streams)
			writeBe16(pv[12 + 2 * i .. 14 + 2 * i], s);
		return paramTlv(paramOutgoingReset, pv);
	}

	private ubyte[] reconfigResponse(uint respSeq, uint result) @safe
	{
		ubyte[] pv = new ubyte[8];
		writeBe32(pv[0 .. 4], respSeq);
		writeBe32(pv[4 .. 8], result);
		return paramTlv(paramReconfigResponse, pv);
	}

	private void armReconfig(ubyte[] packet, long now) @safe
	{
		reconfigPacket = packet;
		reconfigStartedAt = now;
		reconfigTries = 0;
		reconfigRunning = true;
		outbox ~= packet.dup;
	}

	private void clearReconfig() @safe pure nothrow @nogc
	{
		reconfigPacket = null;
		reconfigRunning = false;
		reconfigTries = 0;
	}

	// Retransmit an unanswered RE-CONFIG, failing the association past the cap.
	private void handleReconfig(long now) @safe
	{
		if (!reconfigRunning || now - reconfigStartedAt < rto)
			return;
		if (reconfigTries >= assocMaxRetrans)
		{
			st = AssocState.failed;
			clearReconfig();
			return;
		}
		reconfigTries++;
		reconfigStartedAt = now;
		outbox ~= reconfigPacket.dup;
	}

	private void armT2(ubyte[] packet, long now) @safe
	{
		t2Packet = packet;
		t2StartedAt = now;
		t2Tries = 0;
		t2Running = true;
		outbox ~= packet.dup;
	}

	private void clearT2() @safe pure nothrow @nogc
	{
		t2Packet = null;
		t2Running = false;
		t2Tries = 0;
	}

	// T2-shutdown (RFC 4960 §9.2): retransmit SHUTDOWN / SHUTDOWN ACK, failing the
	// association after the retransmit cap.
	private void handleT2(long now) @safe
	{
		if (!t2Running || now - t2StartedAt < rto)
			return;
		if (t2Tries >= assocMaxRetrans)
		{
			st = AssocState.failed;
			clearT2();
			return;
		}
		t2Tries++;
		t2StartedAt = now;
		rto = rto * 2 > rtoMaxMs ? rtoMaxMs : rto * 2;
		outbox ~= t2Packet.dup;
	}

	// --- reassembly and delivery ------------------------------------------------------------

	private void reassemble() @safe
	{
		// Find every complete message: a run of consecutive TSNs from a Begin
		// fragment to an End fragment, all present. Deliver it, then remove it, and
		// scan again (delivering one may not free another, but a fresh scan is
		// simplest and the fragment set is small).
		bool progress = true;
		while (progress)
		{
			progress = false;
			foreach (startTsn; sortedFragTsns())
			{
				auto b = frags[startTsn];
				if (!(b.flags & dataFlagBegin))
					continue;

				// Walk consecutive TSNs to the End fragment. Every continuation
				// fragment must belong to the same message: same stream and SSN, same
				// ordered/unordered flag, and not itself a Begin. A peer that
				// interleaves or mislabels cannot fuse two messages into one.
				uint t = startTsn;
				size_t total;
				bool complete;
				bool overBound;
				bool malformed;
				while (true)
				{
					auto p = t in frags;
					if (p is null)
						break; // a gap: the message is not yet complete
					if (t != startTsn && (p.streamId != b.streamId || p.ssn != b.ssn
							|| (p.flags & dataFlagUnordered) != (b.flags & dataFlagUnordered)
							|| (p.flags & dataFlagBegin)))
					{
						malformed = true;
						break;
					}
					total += p.payload.length;
					if (total > maxMessage)
					{
						overBound = true;
						break;
					}
					if (p.flags & dataFlagEnd)
					{
						complete = true;
						break;
					}
					t++;
				}

				if (malformed)
				{
					// Drop the orphaned Begin and its continuations up to (not
					// including) the offending fragment, which belongs elsewhere.
					discardFrags(startTsn, t - 1);
					progress = true;
					break;
				}
				if (overBound)
				{
					// A message past the reassembly bound is discarded whole.
					discardFrags(startTsn, t);
					progress = true;
					break;
				}
				if (!complete)
					continue;

				ubyte[] msg;
				for (uint d = startTsn; tsnLeq(d, t); d++)
				{
					msg ~= frags[d].payload;
					frags.remove(d);
				}
				// The bytes stay counted in recvBuffered — they are still held (in the
				// ordered hold or the inbox) until the application drains them.
				deliver(b.streamId, b.ssn, b.ppid, msg, (b.flags & dataFlagUnordered) != 0);
				progress = true;
				break;
			}
		}
	}

	// Remove fragments [from .. to] (serial-inclusive) and give back their bytes.
	private void discardFrags(uint from, uint to) @safe
	{
		for (uint d = from; tsnLeq(d, to); d++)
		{
			if (auto p = d in frags)
			{
				recvBuffered -= p.payload.length > recvBuffered ? recvBuffered : p.payload.length;
				frags.remove(d);
			}
		}
	}

	private void deliver(ushort streamId, ushort ssn, uint ppid, ubyte[] data, bool unordered) @safe
	{
		if (unordered)
		{
			inbox ~= Message(streamId, ppid, data, true);
			return;
		}
		// Ordered: hold by SSN and release in sequence per stream.
		orderedHold[streamId][ssn] = Message(streamId, ppid, data, false);
		auto want = expectedSsn.get(streamId, cast(ushort) 0);
		while ((streamId in orderedHold) && (want in orderedHold[streamId]))
		{
			inbox ~= orderedHold[streamId][want];
			orderedHold[streamId].remove(want);
			want = cast(ushort)(want + 1);
			expectedSsn[streamId] = want;
		}
	}

	// --- SACK construction ------------------------------------------------------------------

	private Chunk buildSack() @safe
	{
		// Gap-ack blocks: runs of received TSNs above the cumulative point, ordered
		// by their offset from that point. Capped in number so the SACK stays inside
		// one DTLS record, and an offset that would not fit 16 bits ends the list.
		ushort[2][] gaps;
		auto tsns = sortedReceivedAboveCum();
		size_t i = 0;
		while (i < tsns.length && gaps.length < maxGapBlocks)
		{
			immutable runStart = tsns[i];
			uint runEnd = runStart;
			while (i + 1 < tsns.length && tsns[i + 1] == runEnd + 1)
			{
				runEnd = tsns[++i];
			}
			immutable startOff = runStart - cumAckTsn;
			immutable endOff = runEnd - cumAckTsn;
			if (endOff > ushort.max)
				break; // beyond a 16-bit offset: stop, do not truncate
			gaps ~= [cast(ushort) startOff, cast(ushort) endOff];
			i++;
		}

		// Advertise the window remaining after what we are currently holding.
		immutable aRwnd = recvWindow > recvBuffered ? recvWindow - recvBuffered : 0;
		auto dups = dupTsns.length > maxDupTsns ? dupTsns[0 .. maxDupTsns] : dupTsns;

		ubyte[] v = new ubyte[12];
		writeBe32(v[0 .. 4], cumAckTsn);
		writeBe32(v[4 .. 8], cast(uint) aRwnd);
		writeBe16(v[8 .. 10], cast(ushort) gaps.length);
		writeBe16(v[10 .. 12], cast(ushort) dups.length);
		foreach (g; gaps)
		{
			ubyte[4] blk;
			writeBe16(blk[0 .. 2], g[0]);
			writeBe16(blk[2 .. 4], g[1]);
			v ~= blk[];
		}
		foreach (d; dups)
		{
			ubyte[4] dt;
			writeBe32(dt[], d);
			v ~= dt[];
		}
		dupTsns = null;
		return Chunk(ChunkType.sack, 0, v);
	}

	private uint[] sortedReceivedAboveCum() @safe
	{
		import std.algorithm.sorting : sort;

		uint[] ts;
		foreach (t; received.byKey)
			if (!tsnLeq(t, cumAckTsn))
				ts ~= t;
		// Serial-number order: sort by distance above the cumulative point so a set
		// straddling the 32-bit wrap stays ascending and its runs merge correctly.
		immutable cum = cumAckTsn;
		ts.sort!((a, b) => (a - cum) < (b - cum));
		return ts;
	}

	private uint[] sortedFragTsns() @safe
	{
		import std.algorithm.sorting : sort;

		uint[] ts = frags.keys;
		ts.sort();
		return ts;
	}

	// --- inbound handlers -------------------------------------------------------------------

	private void onInit(ref Chunk c, long now) @safe
	{
		if (role != Role.server)
			return;
		auto f = parseInit(c.value); // throws on malformed / illegal fields

		// The responder is stateless here: it computes the negotiated parameters
		// LOCALLY and signs them into the cookie, and NEVER touches the TCB. So an
		// INIT arriving on an established association — or a spoofed one — is
		// answered without disturbing existing state (RFC 4960 §5.2.1/§5.2.2).
		immutable negOut = min16(localOutStreams, f.inStreams);
		immutable negIn = min16(localInStreams, f.outStreams);
		auto cookie = makeCookie(f.initiateTag, f.aRwnd, f.initialTsn, negOut, negIn, now);
		auto ack = buildInit(ChunkType.initAck, cookie);
		outbox ~= sctpPacket(f.initiateTag, [ack]);
	}

	private void onInitAck(ref Chunk c, long now) @safe
	{
		if (role != Role.client || st != AssocState.cookieWait)
			return;
		ubyte[] cookie;
		auto f = parseInitAck(c.value, cookie); // throws; guarantees a cookie
		peerTag = f.initiateTag;
		peerArwnd = f.aRwnd;
		peerInitialTsn = f.initialTsn;
		negotiatedOut = min16(localOutStreams, f.inStreams);
		negotiatedIn = min16(localInStreams, f.outStreams);

		st = AssocState.cookieEchoed;
		auto echo = Chunk(ChunkType.cookieEcho, 0, cookie.dup);
		armT1(sctpPacket(peerTag, [echo]), now);
	}

	private void onCookieEcho(ref Chunk c, ref Packet p, long now) @safe
	{
		if (role != Role.server)
			return;
		auto ck = openCookie(c.value, now); // throws on forged / stale / bad length

		// The tag the peer used must be the one we minted for them — checked
		// BEFORE any state is committed, so a cookie that fails this leaves the
		// TCB untouched.
		if (p.verificationTag != ck.localTag)
			return;

		// Idempotent on a duplicate or replayed COOKIE ECHO: if we are already up
		// with these tags, re-acknowledge without disturbing the TCB.
		if (st == AssocState.established && localTag == ck.localTag && peerTag == ck.peerTag)
		{
			outbox ~= sctpPacket(ck.peerTag, [Chunk(ChunkType.cookieAck, 0, null)]);
			return;
		}

		peerTag = ck.peerTag;
		localTag = ck.localTag;
		peerArwnd = ck.peerArwnd;
		peerInitialTsn = ck.peerInitialTsn;
		negotiatedOut = ck.negotiatedOut;
		negotiatedIn = ck.negotiatedIn;
		st = AssocState.established;
		clearT1();
		initTransfer();
		outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.cookieAck, 0, null)]);
	}

	private void onCookieAck() @safe
	{
		if (role != Role.client || st != AssocState.cookieEchoed)
			return;
		st = AssocState.established;
		clearT1();
		initTransfer();
	}

	// Seed the transfer state once the TCB is complete: our TSN starts at the
	// Initial TSN we chose, everything below the peer's Initial TSN is "already
	// received", and the send window opens to what the peer advertised.
	private void initTransfer() @safe
	{
		nextTsn = localInitialTsn;
		cumAckTsn = peerInitialTsn - 1;
		peerRwnd = peerArwnd;
		outstandingBytes = 0;
		cwnd = initialCwnd;
		// RFC 6525: request sequence numbers start at the initial TSN of each side.
		reconfigReqSeq = localInitialTsn;
		reconfigExpectedInSeq = peerInitialTsn;
	}

	// --- verification tag (RFC 4960 §8.5) ---------------------------------------------------

	private bool verifyTag(ref Packet p) @safe pure nothrow
	{
		return p.verificationTag == localTag;
	}

	// --- INIT / INIT ACK bodies -------------------------------------------------------------

	private Chunk buildInit(ChunkType typ, const(ubyte)[] cookie = null) @safe
	{
		ubyte[] v = new ubyte[16];
		writeBe32(v[0 .. 4], localTag);
		writeBe32(v[4 .. 8], localArwnd);
		writeBe16(v[8 .. 10], localOutStreams);
		writeBe16(v[10 .. 12], localInStreams);
		writeBe32(v[12 .. 16], localInitialTsn);
		if (cookie.length)
		{
			// State Cookie parameter (type 7): header + value, padded to 4.
			ubyte[] param = new ubyte[4];
			writeBe16(param[0 .. 2], paramStateCookie);
			writeBe16(param[2 .. 4], cast(ushort)(4 + cookie.length));
			param ~= cookie;
			while (param.length % 4 != 0)
				param ~= 0;
			v ~= param;
		}
		return Chunk(typ, 0, v);
	}

	private InitFields parseInit(scope const(ubyte)[] v) @safe pure
	{
		enforce(v.length >= 16, "sctp: short INIT");
		InitFields f;
		f.initiateTag = readBe32(v[0 .. 4]);
		f.aRwnd = readBe32(v[4 .. 8]);
		f.outStreams = readBe16(v[8 .. 10]);
		f.inStreams = readBe16(v[10 .. 12]);
		f.initialTsn = readBe32(v[12 .. 16]);
		// A zero Initiate Tag or a zero stream count is illegal (RFC 4960 §3.3.2).
		enforce(f.initiateTag != 0, "sctp: INIT with zero Initiate Tag");
		enforce(f.outStreams != 0 && f.inStreams != 0, "sctp: INIT with zero streams");
		return f;
	}

	private InitFields parseInitAck(scope const(ubyte)[] v, out ubyte[] cookie) @safe pure
	{
		auto f = parseInit(v);
		size_t pos = 16;
		while (pos + 4 <= v.length)
		{
			immutable ptyp = readBe16(v[pos .. pos + 2]);
			immutable plen = readBe16(v[pos + 2 .. pos + 4]);
			enforce(plen >= 4 && pos + plen <= v.length, "sctp: bad INIT ACK parameter");
			if (ptyp == paramStateCookie)
				cookie = v[pos + 4 .. pos + plen].dup;
			pos += plen;
			while (pos % 4 != 0 && pos < v.length)
				pos++;
		}
		enforce(cookie.length > 0, "sctp: INIT ACK without a state cookie");
		return f;
	}

	// --- state cookie -----------------------------------------------------------------------

	private struct Cookie
	{
		uint peerTag;
		uint localTag;
		uint peerArwnd;
		uint peerInitialTsn;
		ushort negotiatedOut;
		ushort negotiatedIn;
		long createdAt;
	}

	// The signed cookie: the negotiated state (28 bytes, ending in a 64-bit
	// creation time) followed by its HMAC-SHA256. Built from parameters, not from
	// instance fields, so minting a cookie never mutates the TCB.
	private ubyte[] makeCookie(uint thePeerTag, uint thePeerArwnd, uint thePeerInitialTsn,
		ushort negOut, ushort negIn, long now) @safe
	{
		ubyte[] body_ = new ubyte[28];
		writeBe32(body_[0 .. 4], thePeerTag);
		writeBe32(body_[4 .. 8], localTag); // our (stable) Initiate Tag
		writeBe32(body_[8 .. 12], thePeerArwnd);
		writeBe32(body_[12 .. 16], thePeerInitialTsn);
		writeBe16(body_[16 .. 18], negOut);
		writeBe16(body_[18 .. 20], negIn);
		writeBe32(body_[20 .. 24], cast(uint)(now >> 32));
		writeBe32(body_[24 .. 28], cast(uint)(now & 0xFFFF_FFFF));
		return body_ ~ cookieMac(body_);
	}

	private Cookie openCookie(scope const(ubyte)[] v, long now) @safe
	{
		enum bodyLen = 28;
		enforce(v.length == bodyLen + 32, "sctp: cookie of wrong length");
		auto body_ = v[0 .. bodyLen];
		enforce(constantTimeEqual(cookieMac(body_), v[bodyLen .. $]), "sctp: cookie MAC mismatch");
		immutable created = (cast(long) readBe32(body_[20 .. 24]) << 32) | readBe32(body_[24 .. 28]);
		enforce(now >= created && now - created <= cookieLifeMs, "sctp: stale or future cookie");
		Cookie ck;
		ck.peerTag = readBe32(body_[0 .. 4]);
		ck.localTag = readBe32(body_[4 .. 8]);
		ck.peerArwnd = readBe32(body_[8 .. 12]);
		ck.peerInitialTsn = readBe32(body_[12 .. 16]);
		ck.negotiatedOut = readBe16(body_[16 .. 18]);
		ck.negotiatedIn = readBe16(body_[18 .. 20]);
		ck.createdAt = created;
		return ck;
	}

	private ubyte[] cookieMac(scope const(ubyte)[] body_) @safe
	{
		auto h = HMAC!SHA256(cookieSecret[]);
		h.put(body_);
		return h.finish().dup;
	}

	// --- T1 timer ---------------------------------------------------------------------------

	private void armT1(ubyte[] packet, long now) @safe
	{
		t1Packet = packet;
		t1SentAt = now;
		t1Tries = 0; // the initial send below is transmission #1, not a retransmit
		outbox ~= packet.dup;
	}

	private void clearT1() @safe pure nothrow @nogc
	{
		t1Packet = null;
		t1Tries = 0;
	}

	// --- packet assembly --------------------------------------------------------------------

	private ubyte[] sctpPacket(uint verificationTag, Chunk[] chunks) @safe
	{
		Packet p;
		p.srcPort = localPort;
		p.dstPort = remotePort;
		p.verificationTag = verificationTag;
		p.chunks = chunks;
		return p.encode;
	}

	private static uint randomTag() @trusted
	{
		uint t;
		do
			randombytes_buf(&t, t.sizeof);
		while (t == 0); // the Initiate Tag must be non-zero
		return t;
	}
}

// --- chunk dispatch ----------------------------------------------------------------

private enum Kind
{
	init,
	initAck,
	cookieEcho,
	cookieAck,
	data,
	sack,
	shutdown,
	shutdownAck,
	shutdownComplete,
	abort,
	heartbeat,
	heartbeatAck,
	reConfig,
	other,
}

private Kind chunkKind(ubyte typ) @safe pure nothrow @nogc
{
	switch (typ)
	{
	case ChunkType.init:
		return Kind.init;
	case ChunkType.initAck:
		return Kind.initAck;
	case ChunkType.cookieEcho:
		return Kind.cookieEcho;
	case ChunkType.cookieAck:
		return Kind.cookieAck;
	case ChunkType.data:
		return Kind.data;
	case ChunkType.sack:
		return Kind.sack;
	case ChunkType.shutdown:
		return Kind.shutdown;
	case ChunkType.shutdownAck:
		return Kind.shutdownAck;
	case ChunkType.shutdownComplete:
		return Kind.shutdownComplete;
	case ChunkType.abort:
		return Kind.abort;
	case ChunkType.heartbeat:
		return Kind.heartbeat;
	case ChunkType.heartbeatAck:
		return Kind.heartbeatAck;
	case ChunkType.reConfig:
		return Kind.reConfig;
	default:
		return Kind.other;
	}
}

/// A reassembled application message handed up to the caller.
struct Message
{
	ushort streamId;
	uint ppid;
	ubyte[] data;
	bool unordered;
}

// A DATA chunk sent but not yet acknowledged.
private struct Outstanding
{
	uint tsn;
	Chunk chunk;
	size_t payloadLen;
	long sentAt; // when it last went out (for the RTT sample)
	bool retransmitted; // never sample RTT from a retransmitted chunk (Karn's algorithm)
	size_t missing; // gap-ack "missing report" count toward a fast retransmit
	bool fastRetransmitted; // fast-retransmitted once already
}

// A received DATA fragment awaiting reassembly.
private struct Frag
{
	ushort streamId;
	ushort ssn;
	uint ppid;
	ubyte flags;
	ubyte[] payload;
}

private enum ubyte dataFlagEnd = 0x01;
private enum ubyte dataFlagBegin = 0x02;
private enum ubyte dataFlagUnordered = 0x04;

// --- shared helpers ----------------------------------------------------------------

private bool constantTimeEqual(scope const(ubyte)[] a, scope const(ubyte)[] b) @safe pure nothrow @nogc
{
	if (a.length != b.length)
		return false;
	ubyte diff = 0;
	foreach (i; 0 .. a.length)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

private ushort min16(ushort a, ushort b) @safe pure nothrow @nogc
{
	return a < b ? a : b;
}

// A TLV parameter: type(2), length(2, header included), value, padded to 4 bytes.
private ubyte[] paramTlv(ushort typ, ubyte[] value) @safe pure
{
	ubyte[] p = new ubyte[4];
	p[0] = cast(ubyte)(typ >> 8);
	p[1] = cast(ubyte)(typ & 0xff);
	immutable len = cast(ushort)(4 + value.length);
	p[2] = cast(ubyte)(len >> 8);
	p[3] = cast(ubyte)(len & 0xff);
	p ~= value;
	while (p.length % 4 != 0)
		p ~= 0;
	return p;
}

// TSN comparison in serial-number arithmetic (RFC 1982): a <= b even across the
// 32-bit wrap, for differences below 2^31.
private bool tsnLeq(uint a, uint b) @safe pure nothrow @nogc
{
	return cast(int)(a - b) <= 0;
}

private ushort readBe16(scope const(ubyte)[] b) @safe pure nothrow @nogc
{
	return cast(ushort)((b[0] << 8) | b[1]);
}

private uint readBe32(scope const(ubyte)[] b) @safe pure nothrow @nogc
{
	return (cast(uint) b[0] << 24) | (cast(uint) b[1] << 16) | (cast(uint) b[2] << 8) | b[3];
}

private void writeBe16(ubyte[] b, ushort v) @safe pure nothrow @nogc
{
	b[0] = cast(ubyte)(v >> 8);
	b[1] = cast(ubyte)(v & 0xff);
}

private void writeBe32(ubyte[] b, uint v) @safe pure nothrow @nogc
{
	b[0] = cast(ubyte)(v >> 24);
	b[1] = cast(ubyte)(v >> 16);
	b[2] = cast(ubyte)(v >> 8);
	b[3] = cast(ubyte)(v & 0xff);
}
