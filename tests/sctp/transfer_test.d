module tests.sctp.transfer_test;

import webrtc.sctp.association;
import webrtc.sctp.packet;
import fluent.asserts : should;

// Bring both sides up, then ferry datagrams both ways for a stretch so DATA and
// SACK flow.
private void establish(Association client, Association server)
{
	client.connect(0);
	foreach (_; 0 .. 10)
	{
		foreach (d; client.takeOutbound())
			server.handleInbound(d, 0);
		foreach (d; server.takeOutbound())
			client.handleInbound(d, 0);
		if (client.isEstablished && server.isEstablished)
			break;
	}
}

private void ferry(Association a, Association b, int rounds = 20)
{
	foreach (_; 0 .. rounds)
	{
		foreach (d; a.takeOutbound())
			b.handleInbound(d, 0);
		foreach (d; b.takeOutbound())
			a.handleInbound(d, 0);
	}
}

@("sctp: a small message is delivered reliably")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, cast(ubyte[]) "hello sctp".dup);
	ferry(client, server);

	auto msgs = server.receive();
	msgs.length.should.equal(1);
	msgs[0].streamId.should.equal(cast(ushort) 0);
	msgs[0].ppid.should.equal(53u);
	(cast(string) msgs[0].data).should.equal("hello sctp");
}

@("sctp: a large message is fragmented and reassembled byte for byte")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	// 3000 bytes forces fragmentation across three 1024-byte DATA chunks.
	ubyte[] payload = new ubyte[3000];
	foreach (i; 0 .. payload.length)
		payload[i] = cast(ubyte)(i * 7 + 1);
	client.send(1, 55, payload);
	ferry(client, server);

	auto msgs = server.receive();
	msgs.length.should.equal(1);
	msgs[0].streamId.should.equal(cast(ushort) 1);
	msgs[0].data.should.equal(payload);
}

@("sctp: ordered messages on a stream arrive in order")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 1, cast(ubyte[]) "first".dup);
	client.send(0, 1, cast(ubyte[]) "second".dup);
	client.send(0, 1, cast(ubyte[]) "third".dup);
	ferry(client, server);

	auto msgs = server.receive();
	msgs.length.should.equal(3);
	(cast(string) msgs[0].data).should.equal("first");
	(cast(string) msgs[1].data).should.equal("second");
	(cast(string) msgs[2].data).should.equal("third");
}

@("sctp: an unordered message is delivered and marked unordered")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(2, 51, cast(ubyte[]) "no order".dup, true);
	ferry(client, server);

	auto msgs = server.receive();
	msgs.length.should.equal(1);
	msgs[0].unordered.should.equal(true);
	(cast(string) msgs[0].data).should.equal("no order");
}

@("sctp: sending a message past the reassembly bound is refused")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);
	client.send(0, 0, new ubyte[256 * 1024 + 1]).should.throwException!Exception;
}

// A raw peer we drive by hand, so we own the tags and TSNs and can craft DATA the
// well-behaved send() would never emit. Returns the server's Initiate Tag.
private uint rawHandshake(Association server, uint myTag, uint myInitTsn)
{
	ubyte[] initBody = new ubyte[16];
	writeU32(initBody[0 .. 4], myTag);
	writeU32(initBody[4 .. 8], 128 * 1024); // a_rwnd
	writeU16(initBody[8 .. 10], 256);
	writeU16(initBody[10 .. 12], 256);
	writeU32(initBody[12 .. 16], myInitTsn);
	Packet init;
	init.srcPort = 5000;
	init.dstPort = 5000;
	init.verificationTag = 0;
	init.chunks ~= Chunk(ChunkType.init, 0, initBody);
	server.handleInbound(init.encode, 0);

	auto ackBody = Packet.decode(server.takeOutbound()[0]).chunks[0].value;
	immutable serverTag = readU32(ackBody[0 .. 4]);
	ubyte[] cookie;
	size_t pos = 16;
	while (pos + 4 <= ackBody.length)
	{
		immutable ptyp = readU16(ackBody[pos .. pos + 2]);
		immutable plen = readU16(ackBody[pos + 2 .. pos + 4]);
		if (ptyp == 7)
			cookie = ackBody[pos + 4 .. pos + plen].dup;
		pos += plen;
		while (pos % 4 != 0 && pos < ackBody.length)
			pos++;
	}
	Packet echo;
	echo.srcPort = 5000;
	echo.dstPort = 5000;
	echo.verificationTag = serverTag;
	echo.chunks ~= Chunk(ChunkType.cookieEcho, 0, cookie);
	server.handleInbound(echo.encode, 0);
	server.takeOutbound(); // COOKIE ACK
	return serverTag;
}

private Chunk dataChunk(uint tsn, ushort sid, ushort ssn, uint ppid, const(ubyte)[] payload, ubyte flags)
{
	ubyte[] v = new ubyte[12];
	writeU32(v[0 .. 4], tsn);
	writeU16(v[4 .. 6], sid);
	writeU16(v[6 .. 8], ssn);
	writeU32(v[8 .. 12], ppid);
	v ~= payload;
	return Chunk(ChunkType.data, flags, v);
}

// A malicious peer streaming fragments that sum past the 256 KiB bound must not be
// reassembled or delivered — and must not crash the receiver.
@("sctp: a message past the reassembly bound from a peer is discarded")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	immutable serverTag = rawHandshake(server, 0x0102_0304, 0x0000_1000);

	// 257 fragments of 1024 bytes = 263168 bytes > 262144.
	auto payload = new ubyte[1024];
	uint tsn = 0x0000_1000;
	foreach (i; 0 .. 257)
	{
		ubyte flags = 0;
		if (i == 0)
			flags |= 0x02; // Begin
		if (i == 256)
			flags |= 0x01; // End
		Packet p;
		p.srcPort = 5000;
		p.dstPort = 5000;
		p.verificationTag = serverTag;
		p.chunks ~= dataChunk(tsn++, 0, 0, 53, payload, flags);
		server.handleInbound(p.encode, 0);
		server.takeOutbound(); // drain SACKs
	}
	server.receive().length.should.equal(0); // discarded, nothing delivered
	server.state.should.equal(AssocState.established); // and still alive
}

// SACK application against an externally-shaped SACK (the wire layout confirmed
// against scapy): after our data is cumulatively acked, nothing is in flight.
@("sctp: a SACK cumulatively acking our data clears the in-flight bytes")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, cast(ubyte[]) "abcde".dup);
	auto sent = client.takeOutbound();
	sent.length.should.be.greaterThan(0);
	auto dataChunkVal = Packet.decode(sent[0]).chunks[0].value;
	immutable sentTsn = readU32(dataChunkVal[0 .. 4]);
	client.bytesInFlight.should.equal(5u);

	// A SACK (cumul_tsn_ack = sentTsn, a_rwnd, 0 gaps, 0 dups) laid out as on the
	// wire, addressed with our verification tag so the client accepts it.
	ubyte[] sackVal = new ubyte[12];
	writeU32(sackVal[0 .. 4], sentTsn);
	writeU32(sackVal[4 .. 8], 65_000);
	writeU16(sackVal[8 .. 10], 0);
	writeU16(sackVal[10 .. 12], 0);
	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, sackVal);
	client.handleInbound(sack.encode, 0);

	client.bytesInFlight.should.equal(0u);
}

private void writeU16(ubyte[] b, ushort v)
{
	b[0] = cast(ubyte)(v >> 8);
	b[1] = cast(ubyte)(v & 0xff);
}

private void writeU32(ubyte[] b, uint v)
{
	b[0] = cast(ubyte)(v >> 24);
	b[1] = cast(ubyte)(v >> 16);
	b[2] = cast(ubyte)(v >> 8);
	b[3] = cast(ubyte)(v & 0xff);
}

private ushort readU16(scope const(ubyte)[] b)
{
	return cast(ushort)((b[0] << 8) | b[1]);
}

private uint readU32(scope const(ubyte)[] b)
{
	return (cast(uint) b[0] << 24) | (cast(uint) b[1] << 16) | (cast(uint) b[2] << 8) | b[3];
}

// A peer flooding gapped TSNs (never sending cum+1) must not grow our memory
// without bound: the advertised receive window shrinks to zero and further DATA
// is dropped, and the association stays alive.
@("sctp: a gapped-TSN flood is bounded by the receive window")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	immutable serverTag = rawHandshake(server, 0x0102_0304, 0x0000_1000);

	// Send only even offsets from the cumulative point: cum is initTsn-1, so
	// initTsn is the missing hole and initTsn+1, +3, +5, … are buffered forever.
	auto payload = new ubyte[1024];
	uint tsn = 0x0000_1000 + 1;
	foreach (i; 0 .. 400) // 400 KiB of gapped data, well past the 128 KiB window
	{
		Packet p;
		p.srcPort = 5000;
		p.dstPort = 5000;
		p.verificationTag = serverTag;
		p.chunks ~= dataChunk(tsn, 0, 0, 53, payload, 0x03); // B|E single-fragment
		server.handleInbound(p.encode, 0);
		server.takeOutbound();
		tsn += 2;
	}

	server.receiveWindowBytes.should.equal(0u); // window fully closed, not negative
	server.state.should.equal(AssocState.established); // still alive, not OOM
}

// Receiving a TSN above a hole leaves the cumulative point behind and reports a
// gap-ack block; filling the hole advances the cumulative point and clears it.
@("sctp: a gap above the cumulative point is reported, then cleared")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	immutable serverTag = rawHandshake(server, 0x0102_0304, 0x0000_2000);
	auto payload = cast(ubyte[]) "x".dup;

	// Deliver initTsn+1 (a B|E message) while initTsn is still missing.
	Packet ahead;
	ahead.srcPort = 5000;
	ahead.dstPort = 5000;
	ahead.verificationTag = serverTag;
	ahead.chunks ~= dataChunk(0x0000_2001, 0, 0, 53, payload, 0x03);
	server.handleInbound(ahead.encode, 0);
	auto sack1 = Packet.decode(server.takeOutbound()[$ - 1]).chunks[0].value;
	readU32(sack1[0 .. 4]).should.equal(0x0000_1FFFu); // cumulative still initTsn-1
	readU16(sack1[8 .. 10]).should.equal(cast(ushort) 1); // one gap block
	readU16(sack1[12 .. 14]).should.equal(cast(ushort) 2); // start offset (+2)
	readU16(sack1[14 .. 16]).should.equal(cast(ushort) 2); // end offset (+2)

	// Fill the hole: the cumulative point jumps past both.
	Packet fill;
	fill.srcPort = 5000;
	fill.dstPort = 5000;
	fill.verificationTag = serverTag;
	fill.chunks ~= dataChunk(0x0000_2000, 1, 0, 55, payload, 0x03);
	server.handleInbound(fill.encode, 0);
	auto sack2 = Packet.decode(server.takeOutbound()[$ - 1]).chunks[0].value;
	readU32(sack2[0 .. 4]).should.equal(0x0000_2001u); // cumulative advanced
	readU16(sack2[8 .. 10]).should.equal(cast(ushort) 0); // no gaps left
}

// Ordered messages that arrive out of SSN order are held and released in order.
@("sctp: ordered messages arriving out of SSN order are reordered")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	immutable serverTag = rawHandshake(server, 0x0102_0304, 0x0000_3000);

	// SSN 1 arrives first (TSN initTsn), SSN 0 second (TSN initTsn+1), both ordered
	// single-fragment on stream 0.
	Packet a;
	a.srcPort = 5000;
	a.dstPort = 5000;
	a.verificationTag = serverTag;
	a.chunks ~= dataChunk(0x0000_3000, 0, 1, 53, cast(ubyte[]) "one".dup, 0x03);
	server.handleInbound(a.encode, 0);
	server.receive().length.should.equal(0); // SSN 1 held, SSN 0 not yet seen

	Packet b;
	b.srcPort = 5000;
	b.dstPort = 5000;
	b.verificationTag = serverTag;
	b.chunks ~= dataChunk(0x0000_3001, 0, 0, 53, cast(ubyte[]) "zero".dup, 0x03);
	server.handleInbound(b.encode, 0);

	auto msgs = server.receive();
	msgs.length.should.equal(2);
	(cast(string) msgs[0].data).should.equal("zero"); // SSN 0 first
	(cast(string) msgs[1].data).should.equal("one"); // then SSN 1
}

// A partial SACK (a gap-ack block, no cumulative advance) clears exactly the
// gap-acked chunk and leaves the earlier ones in flight.
@("sctp: a gap-ack block clears only the acked chunk")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, cast(ubyte[]) "aaa".dup);
	client.send(0, 53, cast(ubyte[]) "bbb".dup);
	auto sent = client.takeOutbound();
	sent.length.should.equal(2);
	immutable tsn0 = readU32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);
	client.bytesInFlight.should.equal(6u);

	// SACK: cumulative = tsn0-1 (acks nothing cumulatively), one gap block acking
	// the SECOND chunk (offset 2..2 above the cumulative point).
	ubyte[] sackVal = new ubyte[16];
	writeU32(sackVal[0 .. 4], tsn0 - 1);
	writeU32(sackVal[4 .. 8], 65_000);
	writeU16(sackVal[8 .. 10], 1); // one gap block
	writeU16(sackVal[10 .. 12], 0);
	writeU16(sackVal[12 .. 14], 2); // start offset
	writeU16(sackVal[14 .. 16], 2); // end offset
	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, sackVal);
	client.handleInbound(sack.encode, 0);

	client.bytesInFlight.should.equal(3u); // only the gap-acked chunk cleared
}

// A message whose continuation fragments claim a different stream must not be
// fused: the orphaned Begin is dropped and nothing corrupt is delivered.
@("sctp: fragments that cross streams are not fused")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	immutable serverTag = rawHandshake(server, 0x0102_0304, 0x0000_4000);

	// Begin on stream 0, then a continuation labelled stream 1 (a non-conforming
	// peer). The run must be rejected, not joined.
	Packet p;
	p.srcPort = 5000;
	p.dstPort = 5000;
	p.verificationTag = serverTag;
	p.chunks ~= dataChunk(0x0000_4000, 0, 0, 53, cast(ubyte[]) "begin".dup, 0x02); // B only
	p.chunks ~= dataChunk(0x0000_4001, 1, 0, 53, cast(ubyte[]) "end".dup, 0x01); // E, stream 1
	server.handleInbound(p.encode, 0);

	server.receive().length.should.equal(0); // nothing fused or delivered
	server.state.should.equal(AssocState.established);
}

// A received set straddling the 32-bit TSN wrap produces a single ascending,
// merged gap-ack block — not two mis-ordered ones.
@("sctp: gap-ack generation is correct across the TSN wrap")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	// Initial TSN 0xFFFFFFFE: cumulative starts at 0xFFFFFFFD.
	immutable serverTag = rawHandshake(server, 0x0102_0304, 0xFFFF_FFFE);
	auto payload = cast(ubyte[]) "y".dup;

	// Receive 0xFFFFFFFF (offset +2) and 0x00000000 (offset +3), a contiguous run
	// across the wrap, while 0xFFFFFFFE (+1) stays missing.
	foreach (t; [0xFFFF_FFFFu, 0x0000_0000u])
	{
		Packet p;
		p.srcPort = 5000;
		p.dstPort = 5000;
		p.verificationTag = serverTag;
		p.chunks ~= dataChunk(t, 0, 0, 53, payload, 0x03);
		server.handleInbound(p.encode, 0);
	}
	auto sack = Packet.decode(server.takeOutbound()[$ - 1]).chunks[0].value;
	readU16(sack[8 .. 10]).should.equal(cast(ushort) 1); // one merged block, not two
	readU16(sack[12 .. 14]).should.equal(cast(ushort) 2); // start offset +2
	readU16(sack[14 .. 16]).should.equal(cast(ushort) 3); // end offset +3
}

@("sctp: an empty message is refused")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);
	client.send(0, 0, cast(ubyte[]) "".dup).should.throwException!Exception;
}

// The app-side send buffer is bounded: queuing past the cap without the window
// draining is refused, rather than growing without limit.
@("sctp: the send buffer is bounded")
unittest
{
	import std.exception : assertThrown;

	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	// Queue 256 KiB messages without ever ferrying (so the window never reopens).
	// The 1 MiB cap admits four; the fifth is refused.
	auto big = new ubyte[256 * 1024];
	bool refused;
	foreach (i; 0 .. 8)
	{
		try
			client.send(0, 53, big);
		catch (Exception)
		{
			refused = true;
			break;
		}
	}
	refused.should.equal(true);
	client.state.should.equal(AssocState.established); // refusal, not death
}

// A DATA chunk lost in flight is recovered: with the first fragment dropped, the
// message is still delivered whole once the T3 timer retransmits it.
@("sctp: a dropped DATA chunk is recovered by retransmission")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	ubyte[] payload = new ubyte[5000]; // ~5 fragments
	foreach (i; 0 .. payload.length)
		payload[i] = cast(ubyte)(i * 3 + 2);
	client.send(0, 55, payload);

	long now = 0;
	bool dropped;
	ubyte[] got;
	foreach (_; 0 .. 100)
	{
		client.handleTimeout(now);
		server.handleTimeout(now);
		foreach (d; client.takeOutbound(now))
		{
			auto pk = Packet.decode(d);
			// Drop the very first DATA packet exactly once to simulate loss.
			if (!dropped && pk.chunks.length && pk.chunks[0].typ == ChunkType.data)
			{
				dropped = true;
				continue;
			}
			server.handleInbound(d, now);
		}
		foreach (d; server.takeOutbound(now))
			client.handleInbound(d, now);
		auto msgs = server.receive();
		if (msgs.length)
		{
			got = msgs[0].data;
			break;
		}
		now += 500;
	}
	dropped.should.equal(true); // a chunk really was lost
	got.should.equal(payload); // and the message still arrived whole
}

// Four SACKs reporting the same chunk missing trigger a fast retransmit before
// the T3 timer would fire.
@("sctp: four missing reports trigger a fast retransmit")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 55, new ubyte[5000]); // five fragments X .. X+4
	auto sent = client.takeOutbound(0);
	immutable firstTsn = readU32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);

	// A SACK that gap-acks X+1..X+4 but never X (cumulative stays X-1).
	ubyte[] sackVal = new ubyte[16];
	writeU32(sackVal[0 .. 4], firstTsn - 1);
	writeU32(sackVal[4 .. 8], 200_000);
	writeU16(sackVal[8 .. 10], 1);
	writeU16(sackVal[10 .. 12], 0);
	writeU16(sackVal[12 .. 14], 2); // start offset (X+1)
	writeU16(sackVal[14 .. 16], 5); // end offset (X+4)

	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, sackVal);

	// Four identical SACKs: the fourth reaches the missing-report threshold.
	foreach (i; 0 .. 4)
		client.handleInbound(sack.encode, 100 + i);
	auto outs = client.takeOutbound(200);

	// The missing chunk X is retransmitted. Other chunks freed by the ack may also
	// go out as the window reopens, so look for X rather than demanding it alone.
	bool sawRetransmit;
	foreach (d; outs)
	{
		auto pk = Packet.decode(d);
		if (pk.chunks[0].typ == ChunkType.data && readU32(pk.chunks[0].value[0 .. 4]) == firstTsn)
			sawRetransmit = true;
	}
	sawRetransmit.should.equal(true);
}

// With the peer's window shut and data queued, a zero-window probe is sent when
// the timer fires, so the connection cannot deadlock waiting for a SACK.
@("sctp: a zero-window probe is sent when the window is shut")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, cast(ubyte[]) "first".dup);
	auto sent = client.takeOutbound(0);
	immutable tsn0 = readU32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);

	// Acknowledge it but advertise a zero window.
	ubyte[] sackVal = new ubyte[12];
	writeU32(sackVal[0 .. 4], tsn0);
	writeU32(sackVal[4 .. 8], 0); // a_rwnd = 0
	writeU16(sackVal[8 .. 10], 0);
	writeU16(sackVal[10 .. 12], 0);
	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, sackVal);
	client.handleInbound(sack.encode, 100);
	client.bytesInFlight.should.equal(0u);

	// Queue more; the shut window holds it back.
	client.send(0, 53, cast(ubyte[]) "second".dup);
	client.takeOutbound(200).length.should.equal(0);

	// Arm the probe timer, then fire it a full RTO later.
	client.handleTimeout(200);
	client.handleTimeout(200 + 60_000);
	auto probe = client.takeOutbound(60_200);
	probe.length.should.equal(1);
	Packet.decode(probe[0]).chunks[0].typ.should.equal(cast(ubyte) ChunkType.data);
}

// On a T3 expiry the congestion window collapses to one MTU, ssthresh becomes
// max(cwnd/2, 4·MTU), and the RTO doubles — the RFC 4960 §6.3.3 / §7.2.3 math,
// now observable.
@("sctp: a T3 expiry collapses cwnd and backs off the RTO")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, new ubyte[500]); // one fragment
	client.takeOutbound(0); // sent, T3 armed at now=0
	immutable cwnd0 = client.congestionWindow; // 4 * 1200
	immutable rto0 = client.retransmitTimeout; // RTO.Initial, no sample yet
	rto0.should.equal(3000L);

	client.handleTimeout(rto0); // now == deadline: T3 fires
	client.congestionWindow.should.equal(1200u); // one MTU
	client.slowStartThreshold.should.equal(4800u); // max(cwnd0/2=2400, 4*MTU=4800)
	client.retransmitTimeout.should.equal(6000L); // doubled
}

// Karn's algorithm: the RTT is never sampled from a retransmitted chunk, so
// acking one leaves the backed-off RTO unchanged.
@("sctp: an ack of a retransmitted chunk does not resample the RTO")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, new ubyte[500]);
	auto sent = client.takeOutbound(0);
	immutable tsn = readU32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);
	client.handleTimeout(3000); // T3 expiry: chunk retransmitted, RTO now 6000
	client.retransmitTimeout.should.equal(6000L);

	// Ack the (retransmitted) chunk: Karn forbids a sample, so RTO stays put.
	ubyte[] sackVal = new ubyte[12];
	writeU32(sackVal[0 .. 4], tsn);
	writeU32(sackVal[4 .. 8], 200_000);
	writeU16(sackVal[8 .. 10], 0);
	writeU16(sackVal[10 .. 12], 0);
	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, sackVal);
	client.handleInbound(sack.encode, 3100);
	client.retransmitTimeout.should.equal(6000L); // unchanged — no sample taken
}

// RFC 4960 §6.3.2 R3: a gap-ack of a HIGHER chunk while the earliest is still
// lost must not defer the T3 deadline, so the lost chunk is still retransmitted
// on the original schedule.
@("sctp: a gap-ack of a higher chunk does not defer T3 for a lost earlier one")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, new ubyte[2000]); // two fragments X, X+1
	auto sent = client.takeOutbound(0); // T3 armed at now=0
	immutable firstTsn = readU32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);

	// Gap-ack only X+1 (offset 2 above cumulative X-1); X stays lost.
	ubyte[] sackVal = new ubyte[16];
	writeU32(sackVal[0 .. 4], firstTsn - 1);
	writeU32(sackVal[4 .. 8], 200_000);
	writeU16(sackVal[8 .. 10], 1);
	writeU16(sackVal[10 .. 12], 0);
	writeU16(sackVal[12 .. 14], 2);
	writeU16(sackVal[14 .. 16], 2);
	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, sackVal);
	client.handleInbound(sack.encode, 100); // T3 must NOT be restarted here

	// The original T3 deadline (0 + 3000) still holds: firing at 3000 retransmits X.
	client.handleTimeout(3000);
	auto outs = client.takeOutbound(3000);
	bool sawX;
	foreach (d; outs)
	{
		auto pk = Packet.decode(d);
		if (pk.chunks[0].typ == ChunkType.data && readU32(pk.chunks[0].value[0 .. 4]) == firstTsn)
			sawX = true;
	}
	sawX.should.equal(true);
}
