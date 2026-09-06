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
				case Kind.other:
					break; // DATA/SACK/etc handled by a later layer
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

	/// Datagrams queued to send, each already a complete SCTP packet.
	ubyte[][] takeOutbound() @safe
	{
		auto o = outbox;
		outbox = null;
		return o;
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
		outbox ~= sctpPacket(peerTag, [Chunk(ChunkType.cookieAck, 0, null)]);
	}

	private void onCookieAck() @safe
	{
		if (role != Role.client || st != AssocState.cookieEchoed)
			return;
		st = AssocState.established;
		clearT1();
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
	default:
		return Kind.other;
	}
}

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
