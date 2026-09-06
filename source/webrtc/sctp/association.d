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
	failed,
}

// RFC 4960 §15 timers. RTO.Initial and the cap on INIT/COOKIE retransmits before
// the association is abandoned.
private enum long rtoInitialMs = 3000;
private enum size_t maxInitRetransmits = 8;
// A state cookie older than this is stale and refused (RFC 4960 §5.1.5 Valid.Cookie.Life).
private enum long cookieLifeMs = 60_000;

// DATA payload per chunk — small enough that a one-DATA SCTP packet fits inside a
// DTLS record on the 1200-byte link we set — and the per-message reassembly bound.
private enum size_t maxPayload = 1024;
private enum size_t maxMessage = 256 * 1024; // RFC 8831 / DESIGN.md reassembly bound
private enum size_t dataHeaderLen = 12; // TSN(4) + stream(2) + SSN(2) + PPID(4)
private enum size_t initialCwnd = 4 * 1500; // RFC 4960 §7.2.1
private enum size_t maxCwnd = 1024 * 1024; // cap congestion-window growth
private enum size_t recvWindow = 128 * 1024; // our advertised a_rwnd and hard receive cap
private enum size_t sendBufferCap = 1024 * 1024; // app-queued bytes we will hold before refusing
private enum size_t maxGapBlocks = 32; // keep a SACK inside one DTLS record
private enum size_t maxDupTsns = 32;

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
	private size_t recvBuffered; // bytes held in the receive path (frags + held + inbox)
	private size_t sendQueuedBytes; // app payload queued but not yet handed to the wire

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
					if (verifyTag(p)) onSack(c);
					break;
				case Kind.other:
					break; // teardown / RE-CONFIG handled by a later layer
				}
			}
		}
		catch (Exception)
		{
			// malformed, bad checksum, forged/stale cookie, illegal fields: drop
		}
	}

	/// The T1 retransmission schedule: re-send the in-flight INIT/COOKIE-ECHO, and
	/// fail the association once the retransmit cap is reached.
	void handleTimeout(long now) @safe
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

	/// Datagrams queued to send, each already a complete SCTP packet. Flushes a
	/// pending SACK and as much window-permitted DATA as will go.
	ubyte[][] takeOutbound() @safe
	{
		flush();
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

	// --- outbound flush ---------------------------------------------------------------------

	private void flush() @safe
	{
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
			outstanding ~= Outstanding(tsn, c, payload);
			outstandingBytes += payload;
			peerRwnd = payload > peerRwnd ? 0 : cast(uint)(peerRwnd - payload);
			outbox ~= sctpPacket(peerTag, [c]);
		}
	}

	// --- inbound DATA / SACK ----------------------------------------------------------------

	private void onData(ref Chunk c) @safe
	{
		if (st != AssocState.established)
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

	private void onSack(ref Chunk c) @safe
	{
		if (st != AssocState.established)
			return;
		enforce(c.value.length >= 12, "sctp: short SACK");
		immutable cumAck = readBe32(c.value[0 .. 4]);
		immutable aRwnd = readBe32(c.value[4 .. 8]);
		immutable numGap = readBe16(c.value[8 .. 10]);
		immutable numDup = readBe16(c.value[10 .. 12]);
		enforce(12 + numGap * 4 + numDup * 4 <= c.value.length, "sctp: SACK runs past the chunk");

		// Drop everything cumulatively acknowledged.
		size_t freed;
		size_t kept;
		foreach (ref o; outstanding)
		{
			bool acked = tsnLeq(o.tsn, cumAck);
			if (!acked)
			{
				// Also honour gap-ack blocks (relative to the cumulative point).
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
				freed += o.payloadLen;
			else
				outstanding[kept++] = o;
		}
		outstanding = outstanding[0 .. kept];
		outstandingBytes -= freed > outstandingBytes ? outstandingBytes : freed;

		// Congestion window growth (slow start, simplified), capped, and the peer's
		// window recomputed from what it now reports minus what is still in flight.
		if (freed > 0 && cwnd < maxCwnd)
			cwnd += freed < 1500 ? freed : 1500;
		peerRwnd = aRwnd > outstandingBytes ? cast(uint)(aRwnd - outstandingBytes) : 0;
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
