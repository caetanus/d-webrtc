module tests.sctp.heartbeat_test;

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

// On an idle association a HEARTBEAT is sent each interval and the peer echoes a
// HEARTBEAT ACK, so both stay established indefinitely.
@("sctp: heartbeats keep an idle association alive")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	long now;
	foreach (_; 0 .. 8)
	{
		client.handleTimeout(now);
		server.handleTimeout(now);
		foreach (d; client.takeOutbound(now))
			server.handleInbound(d, now);
		foreach (d; server.takeOutbound(now))
			client.handleInbound(d, now);
		now += 31_000; // past HB.interval each round
	}
	client.state.should.equal(AssocState.established);
	server.state.should.equal(AssocState.established);
}

// A path that stops answering heartbeats fails the association rather than
// probing forever.
@("sctp: unanswered heartbeats fail the association")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	long now = 30_000; // first HB is due
	foreach (_; 0 .. 20)
	{
		client.handleTimeout(now);
		client.takeOutbound(now); // heartbeats vanish, never answered
		if (client.state == AssocState.failed)
			break;
		now += 3000; // retries accrue per RTO
	}
	client.state.should.equal(AssocState.failed);
}

// An inbound HEARTBEAT is answered with a HEARTBEAT ACK echoing its info verbatim.
@("sctp: an inbound HEARTBEAT is echoed as a HEARTBEAT ACK")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	ubyte[] info = [0, 1, 0, 12, 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
	Packet hb;
	hb.srcPort = 5000;
	hb.dstPort = 5000;
	hb.verificationTag = server.localInitiateTag;
	hb.chunks ~= Chunk(ChunkType.heartbeat, 0, info);
	server.handleInbound(hb.encode, 0);

	bool echoed;
	foreach (d; server.takeOutbound(0))
	{
		auto pk = Packet.decode(d);
		if (pk.chunks[0].typ == ChunkType.heartbeatAck)
		{
			pk.chunks[0].value.should.equal(info);
			echoed = true;
		}
	}
	echoed.should.equal(true);
}

// A datagram packed with many HEARTBEAT chunks yields at most ONE HEARTBEAT ACK,
// not one per chunk — no amplification.
@("sctp: many HEARTBEATs in a datagram produce at most one ACK")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	Packet hb;
	hb.srcPort = 5000;
	hb.dstPort = 5000;
	hb.verificationTag = server.localInitiateTag;
	foreach (i; 0 .. 50)
		hb.chunks ~= Chunk(ChunkType.heartbeat, 0,
			[cast(ubyte) 0, 1, 0, 12, cast(ubyte) i, 0, 0, 0, 0, 0, 0, 0]);
	server.handleInbound(hb.encode, 0);

	size_t acks;
	foreach (d; server.takeOutbound(0))
		foreach (ch; Packet.decode(d).chunks)
			if (ch.typ == ChunkType.heartbeatAck)
				acks++;
	acks.should.equal(1);
}

// An oversized Heartbeat Info is dropped, not echoed.
@("sctp: an oversized HEARTBEAT is not echoed")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	ubyte[] huge = new ubyte[4096];
	huge[1] = 1; // param type
	Packet hb;
	hb.srcPort = 5000;
	hb.dstPort = 5000;
	hb.verificationTag = server.localInitiateTag;
	hb.chunks ~= Chunk(ChunkType.heartbeat, 0, huge);
	server.handleInbound(hb.encode, 0);

	bool echoed;
	foreach (d; server.takeOutbound(0))
		foreach (ch; Packet.decode(d).chunks)
			if (ch.typ == ChunkType.heartbeatAck)
				echoed = true;
	echoed.should.equal(false);
}

// A HEARTBEAT arriving after the association has failed is not echoed.
@("sctp: a HEARTBEAT after failure is not echoed")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	server.abort(); // now closed
	server.takeOutbound(0); // drain the ABORT

	Packet hb;
	hb.srcPort = 5000;
	hb.dstPort = 5000;
	hb.verificationTag = server.localInitiateTag;
	hb.chunks ~= Chunk(ChunkType.heartbeat, 0, [cast(ubyte) 0, 1, 0, 12, 9, 9, 9, 9, 9, 9, 9, 9]);
	server.handleInbound(hb.encode, 0);
	server.takeOutbound(0).length.should.equal(0); // nothing after the end
}

// A stale HEARTBEAT ACK from a previous probe (wrong nonce) does not confirm the
// current one; the path still fails if the real ACK never comes.
@("sctp: a replayed HEARTBEAT ACK with a stale nonce is ignored")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	// Drive the first probe out and capture the nonce it used.
	client.handleTimeout(30_000);
	auto sent = client.takeOutbound(30_000);
	ubyte[] currentInfo;
	foreach (d; sent)
		foreach (ch; Packet.decode(d).chunks)
			if (ch.typ == ChunkType.heartbeat)
				currentInfo = ch.value.dup;
	currentInfo.length.should.be.greaterThan(0);

	// A HEARTBEAT ACK with a DIFFERENT (stale) nonce must not clear the probe.
	auto stale = currentInfo.dup;
	stale[$ - 1] ^= 0xff;
	Packet ack;
	ack.srcPort = 5000;
	ack.dstPort = 5000;
	ack.verificationTag = client.localInitiateTag;
	ack.chunks ~= Chunk(ChunkType.heartbeatAck, 0, stale);
	client.handleInbound(ack.encode, 30_100);

	// The probe is still outstanding, so an unanswered path still fails.
	long now = 33_000;
	foreach (_; 0 .. 20)
	{
		client.handleTimeout(now);
		client.takeOutbound(now);
		if (client.state == AssocState.failed)
			break;
		now += 3000;
	}
	client.state.should.equal(AssocState.failed);
}
