module tests.sctp.reconfig_test;

import webrtc.sctp.association;
import webrtc.sctp.packet;
import fluent.asserts : should;

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

// A stream reset completes both ways: the requester's pending clears and the
// peer records the stream as reset.
@("sctp: a stream reset completes end to end")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.resetStream(0, 0);
	client.streamResetPending.should.equal(true);
	ferry(client, server);

	client.streamResetPending.should.equal(false); // response received
	server.takeResetStreams().should.equal([cast(ushort) 0]);
}

// A duplicate reset request resets the stream once and re-sends the cached
// response, rather than resetting again.
@("sctp: a duplicate reset request is idempotent")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.resetStream(3, 0);
	auto req = client.takeOutbound(0);
	req.length.should.equal(1);

	server.handleInbound(req[0], 0);
	server.takeResetStreams().should.equal([cast(ushort) 3]); // reset once
	auto resp1 = server.takeOutbound(0);
	resp1.length.should.equal(1); // a response went out

	server.handleInbound(req[0], 0); // the same request again
	server.takeResetStreams().length.should.equal(0); // NOT reset a second time
	server.takeOutbound(0).length.should.equal(1); // but the cached response is re-sent
}

// An unanswered reset request retransmits and, past the cap, fails the
// association.
@("sctp: an unanswered reset request retransmits then fails")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.resetStream(0, 0);
	client.takeOutbound(0).length.should.equal(1); // the initial request

	long now;
	foreach (_; 0 .. 15)
	{
		client.handleTimeout(now);
		client.takeOutbound(now);
		if (client.state == AssocState.failed)
			break;
		now += 61_000;
	}
	client.state.should.equal(AssocState.failed);
}

// Two resets requested at once are serialised: the second issues only after the
// first completes, and both reach the peer.
@("sctp: a second reset queues behind the first")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.resetStream(0, 0);
	client.resetStream(1, 0); // queued while the first is in flight
	ferry(client, server, 40);

	client.streamResetPending.should.equal(false);
	server.takeResetStreams().should.equal([cast(ushort) 0, cast(ushort) 1]);
}

private void writeU16(ubyte[] b, ushort v) { b[0] = cast(ubyte)(v >> 8); b[1] = cast(ubyte)(v & 0xff); }
private void writeU32(ubyte[] b, uint v)
{
	b[0] = cast(ubyte)(v >> 24); b[1] = cast(ubyte)(v >> 16);
	b[2] = cast(ubyte)(v >> 8); b[3] = cast(ubyte) v;
}
private uint readU32(scope const(ubyte)[] b)
{
	return (cast(uint) b[0] << 24) | (cast(uint) b[1] << 16) | (cast(uint) b[2] << 8) | b[3];
}

private uint rawHandshake(Association server, uint myTag, uint myInitTsn)
{
	ubyte[] initBody = new ubyte[16];
	writeU32(initBody[0 .. 4], myTag);
	writeU32(initBody[4 .. 8], 128 * 1024);
	writeU16(initBody[8 .. 10], 256);
	writeU16(initBody[10 .. 12], 256);
	writeU32(initBody[12 .. 16], myInitTsn);
	Packet init;
	init.srcPort = 5000; init.dstPort = 5000; init.verificationTag = 0;
	init.chunks ~= Chunk(ChunkType.init, 0, initBody);
	server.handleInbound(init.encode, 0);
	auto ackBody = Packet.decode(server.takeOutbound()[0]).chunks[0].value;
	immutable serverTag = readU32(ackBody[0 .. 4]);
	ubyte[] cookie;
	size_t pos = 16;
	while (pos + 4 <= ackBody.length)
	{
		immutable ptyp = (ackBody[pos] << 8) | ackBody[pos + 1];
		immutable plen = (ackBody[pos + 2] << 8) | ackBody[pos + 3];
		if (ptyp == 7) cookie = ackBody[pos + 4 .. pos + plen].dup;
		pos += plen;
		while (pos % 4 != 0 && pos < ackBody.length) pos++;
	}
	Packet echo;
	echo.srcPort = 5000; echo.dstPort = 5000; echo.verificationTag = serverTag;
	echo.chunks ~= Chunk(ChunkType.cookieEcho, 0, cookie);
	server.handleInbound(echo.encode, 0);
	server.takeOutbound();
	return serverTag;
}

// A foreign RE-CONFIG from scapy (Outgoing SSN Reset Request, stream 0, req seq
// 0x2000) is parsed and answered — the parser is pinned to another stack's bytes,
// not just our own encoder.
@("sctp: a foreign RE-CONFIG reset request is parsed and answered")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	immutable serverTag = rawHandshake(server, 0x0102_0304, 0x0000_2000);

	// The 20-byte RE-CONFIG chunk value scapy produced (param type 13).
	ubyte[] reconfigValue = [
		0x00, 0x0d, 0x00, 0x12, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x1f, 0xff,
		0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
	];
	Packet rc;
	rc.srcPort = 5000; rc.dstPort = 5000; rc.verificationTag = serverTag;
	rc.chunks ~= Chunk(ChunkType.reConfig, 0, reconfigValue);
	server.handleInbound(rc.encode, 0);

	server.takeResetStreams().should.equal([cast(ushort) 0]);
	bool answered;
	foreach (d; server.takeOutbound(0))
		if (Packet.decode(d).chunks[0].typ == ChunkType.reConfig)
			answered = true;
	answered.should.equal(true);
}

// A failure Result (Denied) ends the request without killing the association.
@("sctp: a Denied reset response gives up without failing the association")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.resetStream(0, 0);
	auto reqValue = Packet.decode(client.takeOutbound(0)[0]).chunks[0].value;
	immutable reqSeq = readU32(reqValue[4 .. 8]); // param: type/len then reqSeq

	// A RE-CONFIG response with result = 2 (Denied).
	ubyte[] resp = new ubyte[12];
	writeU16(resp[0 .. 2], 16); // response param type
	writeU16(resp[2 .. 4], 12);
	writeU32(resp[4 .. 8], reqSeq);
	writeU32(resp[8 .. 12], 2); // Denied
	Packet rc;
	rc.srcPort = 5000; rc.dstPort = 5000; rc.verificationTag = client.localInitiateTag;
	rc.chunks ~= Chunk(ChunkType.reConfig, 0, resp);
	client.handleInbound(rc.encode, 0);

	// The request is ended and its timer stopped, so it will not retransmit itself
	// to death; the association stays up.
	client.streamResetPending.should.equal(false);
	client.handleTimeout(4000); // past the reconfig RTO
	client.takeOutbound(4000).length.should.equal(0); // no retransmit
	client.state.should.equal(AssocState.established);
}

// Aborting while a reset is pending clears the reconfig timer: nothing is sent
// afterward and the association stays closed (not resurrected to failed).
@("sctp: abort clears a pending reset's timer")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.resetStream(0, 0);
	client.abort();
	client.takeOutbound(0); // drain the ABORT

	for (long now = 61_000; now <= 800_000; now += 61_000)
	{
		client.handleTimeout(now);
		client.takeOutbound(now).length.should.equal(0); // nothing after abort
	}
	client.state.should.equal(AssocState.closed); // never flipped to failed
}

// One datagram carrying many duplicate reset requests yields at most one
// outbound RE-CONFIG packet, not one per request.
@("sctp: many reset requests in a datagram produce at most one response packet")
unittest
{
	auto server = new Association(Role.server, 5000, 5000);
	immutable serverTag = rawHandshake(server, 0x0102_0304, 0x0000_2000);

	// First a real request so a cached response exists for req seq 0x2000.
	ubyte[] one = [
		0x00, 0x0d, 0x00, 0x12, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x1f, 0xff,
		0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
	];
	Packet first;
	first.srcPort = 5000; first.dstPort = 5000; first.verificationTag = serverTag;
	first.chunks ~= Chunk(ChunkType.reConfig, 0, one);
	server.handleInbound(first.encode, 0);
	server.takeOutbound(0);
	server.takeResetStreams();

	// Now 30 duplicates of that request in one chunk value.
	ubyte[] many;
	foreach (_; 0 .. 30)
		many ~= one;
	Packet flood;
	flood.srcPort = 5000; flood.dstPort = 5000; flood.verificationTag = serverTag;
	flood.chunks ~= Chunk(ChunkType.reConfig, 0, many);
	server.handleInbound(flood.encode, 0);

	server.takeOutbound(0).length.should.equal(1); // coalesced to one packet
	server.state.should.equal(AssocState.established);
}
