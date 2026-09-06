module tests.sctp.association_test;

import webrtc.sctp.association;
import webrtc.sctp.packet;
import fluent.asserts : should;

// Ferry SCTP datagrams both ways, driving each side, until both associations are
// established or the clock runs out.
private void pump(Association client, Association server)
{
	long now = 0;
	foreach (_; 0 .. 50)
	{
		client.handleTimeout(now);
		server.handleTimeout(now);
		foreach (d; client.takeOutbound())
			server.handleInbound(d, now);
		foreach (d; server.takeOutbound())
			client.handleInbound(d, now);
		if (client.isEstablished && server.isEstablished)
			return;
		now += 100;
	}
}

@("sctp: the four-way handshake brings both sides up")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	client.connect(0);
	pump(client, server);
	client.state.should.equal(AssocState.established);
	server.state.should.equal(AssocState.established);
}

// A foreign INIT from scapy: our responder must parse its fields and answer with
// an INIT ACK whose common-header verification tag echoes scapy's Initiate Tag
// (0x12345678), carrying our own non-zero tag and a state cookie.
private immutable ubyte[] scapyInit = [
	0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x16, 0xde, 0x25, 0x9a,
	0x01, 0x00, 0x00, 0x14, 0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0xa0, 0x00,
	0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x00,
];

@("sctp: a foreign INIT is answered with a valid INIT ACK")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	server.handleInbound(scapyInit, 0);
	auto outs = server.takeOutbound();
	outs.length.should.equal(1);

	auto ack = Packet.decode(outs[0]);
	ack.verificationTag.should.equal(0x1234_5678u); // scapy's Initiate Tag, echoed
	ack.chunks.length.should.equal(1);
	ack.chunks[0].typ.should.equal(cast(ubyte) ChunkType.initAck);

	// Our Initiate Tag is non-zero (RFC 4960 §3.3.2)…
	auto body_ = ack.chunks[0].value;
	body_.length.should.be.greaterThan(16);
	immutable ourTag = (cast(uint) body_[0] << 24) | (cast(uint) body_[1] << 16)
		| (cast(uint) body_[2] << 8) | body_[3];
	ourTag.should.be.greaterThan(0u);

	// …and a State Cookie parameter (type 7) is present.
	bool sawCookie;
	size_t pos = 16;
	while (pos + 4 <= body_.length)
	{
		immutable ptyp = (body_[pos] << 8) | body_[pos + 1];
		immutable plen = (body_[pos + 2] << 8) | body_[pos + 3];
		if (plen < 4)
			break;
		if (ptyp == 7)
			sawCookie = true;
		pos += plen;
		while (pos % 4 != 0 && pos < body_.length)
			pos++;
	}
	sawCookie.should.equal(true);
}

// With no INIT ACK ever returning, INIT is retransmitted on the T1 schedule and
// the association fails after the retransmit cap rather than waiting forever.
@("sctp: an unanswered INIT retransmits, then the association fails")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	client.connect(0);
	client.takeOutbound().length.should.equal(1); // the first INIT

	client.handleTimeout(3000);
	client.takeOutbound().length.should.equal(1); // one retransmit after RTO

	for (long now = 6000; now <= 40_000 && client.state != AssocState.failed; now += 3000)
		client.handleTimeout(now);
	client.state.should.equal(AssocState.failed);
}

// The client receive path against a FOREIGN INIT ACK: scapy laid out the fixed
// fields and a State Cookie parameter (type 7) holding the opaque cookie
// 0x40..0x4f. Our client must parse them and answer with a COOKIE ECHO that
// echoes that cookie verbatim, addressed with the foreign Initiate Tag
// (0x0BADF00D). Only the common-header verification tag has to be ours (the peer
// echoes it), so we wrap scapy's foreign chunk body in a correctly-tagged packet.
private immutable ubyte[] scapyInitAckBody = [
	0x0b, 0xad, 0xf0, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x20, 0x00, // init_tag, a_rwnd, out/in streams, initial TSN
	0x00, 0x07, 0x00, 0x14, // State Cookie parameter: type 7, length 20
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, // the 16-byte opaque cookie
];

@("sctp: a foreign INIT ACK is parsed and its cookie echoed verbatim")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	client.connect(0);
	client.takeOutbound(); // discard the INIT

	Packet ack;
	ack.srcPort = 5000;
	ack.dstPort = 5000;
	ack.verificationTag = client.localInitiateTag; // the peer echoes our tag
	ack.chunks ~= Chunk(ChunkType.initAck, 0, scapyInitAckBody.dup);
	client.handleInbound(ack.encode, 0);

	client.state.should.equal(AssocState.cookieEchoed);
	auto outs = client.takeOutbound();
	outs.length.should.equal(1);
	auto echo = Packet.decode(outs[0]);
	echo.verificationTag.should.equal(0x0BAD_F00Du); // the foreign Initiate Tag
	echo.chunks.length.should.equal(1);
	echo.chunks[0].typ.should.equal(cast(ubyte) ChunkType.cookieEcho);
	echo.chunks[0].value.should.equal(cast(ubyte[])[
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	]);
}

// INIT retransmits exactly Max.Init.Retransmits (8) times before failing — the
// off-by-one an "eventually fails" assertion would miss.
@("sctp: INIT retransmits exactly the RFC cap before failing")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	client.connect(0);
	client.takeOutbound().length.should.equal(1); // transmission #1 (not a retransmit)

	size_t retransmits;
	for (long now = 3000; client.state != AssocState.failed && now <= 100_000; now += 3000)
	{
		client.handleTimeout(now);
		retransmits += client.takeOutbound().length;
	}
	client.state.should.equal(AssocState.failed);
	retransmits.should.equal(8); // RFC 4960 Max.Init.Retransmits
}

// An INIT arriving on an established responder must be answered without
// disturbing the live association (RFC 4960 §5.2.2) — not clobber its TCB.
@("sctp: an INIT on an established server does not reset it")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	client.connect(0);
	pump(client, server);
	server.state.should.equal(AssocState.established);

	// A spoofed INIT with a different Initiate Tag.
	Packet spoof;
	spoof.srcPort = 5000;
	spoof.dstPort = 5000;
	spoof.verificationTag = 0;
	ubyte[] initBody = [
		0x00, 0x00, 0x00, 0x63, 0x00, 0x01, 0x00, 0x00, // tag 0x63, a_rwnd
		0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, // streams, initial TSN
	];
	spoof.chunks ~= Chunk(ChunkType.init, 0, initBody);
	server.handleInbound(spoof.encode, 100);

	// It answers (INIT ACK) but stays established with its TCB intact.
	server.state.should.equal(AssocState.established);
	auto outs = server.takeOutbound();
	outs.length.should.equal(1);
	Packet.decode(outs[0]).chunks[0].typ.should.equal(cast(ubyte) ChunkType.initAck);
}

// connect() is idempotent: a second call does not send a second INIT.
@("sctp: connect twice does not resend INIT")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	client.connect(0);
	client.connect(0);
	client.takeOutbound().length.should.equal(1);
}

// An INIT ACK with the wrong verification tag is dropped; the initiator stays in
// cookie-wait.
@("sctp: an INIT ACK with the wrong verification tag is dropped")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	client.connect(0);
	client.takeOutbound();

	Packet ack;
	ack.srcPort = 5000;
	ack.dstPort = 5000;
	ack.verificationTag = client.localInitiateTag ^ 0x1; // not our tag
	ack.chunks ~= Chunk(ChunkType.initAck, 0, scapyInitAckBody.dup);
	client.handleInbound(ack.encode, 0);
	client.state.should.equal(AssocState.cookieWait);
	client.takeOutbound().length.should.equal(0);
}

// A COOKIE ECHO whose cookie is genuine but past Valid.Cookie.Life is refused.
@("sctp: a stale state cookie is refused")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	server.handleInbound(scapyInit, 0); // mint a real INIT ACK at t=0
	auto ack = Packet.decode(server.takeOutbound()[0]);
	auto cookie = extractCookie(ack.chunks[0].value);

	Packet echo;
	echo.srcPort = 5000;
	echo.dstPort = 5000;
	echo.verificationTag = extractOurTag(ack.chunks[0].value); // the tag we minted
	echo.chunks ~= Chunk(ChunkType.cookieEcho, 0, cookie);
	server.handleInbound(echo.encode, 61_000); // > 60 s later
	server.state.should.equal(AssocState.closed);
	server.takeOutbound().length.should.equal(0);
}

private ubyte[] extractCookie(scope const(ubyte)[] initAckBody)
{
	size_t pos = 16;
	while (pos + 4 <= initAckBody.length)
	{
		immutable ptyp = (initAckBody[pos] << 8) | initAckBody[pos + 1];
		immutable plen = (initAckBody[pos + 2] << 8) | initAckBody[pos + 3];
		if (ptyp == 7)
			return initAckBody[pos + 4 .. pos + plen].dup;
		pos += plen;
		while (pos % 4 != 0 && pos < initAckBody.length)
			pos++;
	}
	return null;
}

private uint extractOurTag(scope const(ubyte)[] initAckBody)
{
	return (cast(uint) initAckBody[0] << 24) | (cast(uint) initAckBody[1] << 16)
		| (cast(uint) initAckBody[2] << 8) | initAckBody[3];
}

// A COOKIE ACK carrying the wrong verification tag is discarded: the initiator
// stays in cookie-echoed, never falsely established.
@("sctp: a COOKIE ACK with the wrong verification tag is dropped")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	client.connect(0);

	// Drive exactly two steps: INIT → INIT ACK, so the client sends COOKIE ECHO
	// and sits in cookie-echoed. The server's COOKIE ACK is deliberately not
	// delivered, so nothing legitimately establishes the client.
	foreach (d; client.takeOutbound())
		server.handleInbound(d, 0); // INIT → server emits INIT ACK
	foreach (d; server.takeOutbound())
		client.handleInbound(d, 0); // INIT ACK → client emits COOKIE ECHO
	client.state.should.equal(AssocState.cookieEchoed);

	// A forged COOKIE ACK with verification tag 0 (never our tag) must be ignored.
	Packet forged;
	forged.srcPort = 5000;
	forged.dstPort = 5000;
	forged.verificationTag = 0;
	forged.chunks ~= Chunk(ChunkType.cookieAck, 0, null);
	client.handleInbound(forged.encode, 0);
	client.state.should.equal(AssocState.cookieEchoed); // not established
}

// A COOKIE ECHO whose cookie is not one we signed is refused: no COOKIE ACK, the
// responder stays closed.
@("sctp: a forged state cookie is refused")
unittest
{
	// A cookie of the wrong length (hits the length guard) and one of the right
	// length but a bad MAC (hits the constant-time MAC check) are both refused.
	foreach (size_t cookieLen; [size_t(64), size_t(60)]) // 60 = 28-byte body + 32 MAC
	{
		auto server = new Association(Role.server, 5000, 5000);
		Packet echo;
		echo.srcPort = 5000;
		echo.dstPort = 5000;
		echo.verificationTag = 0x11223344;
		echo.chunks ~= Chunk(ChunkType.cookieEcho, 0, new ubyte[cookieLen]); // garbage
		server.handleInbound(echo.encode, 0);
		server.takeOutbound().length.should.equal(0);
		server.state.should.equal(AssocState.closed);
	}
}
