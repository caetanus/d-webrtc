module tests.sctp.teardown_test;

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

// A graceful shutdown brings both endpoints to closed via
// SHUTDOWN → SHUTDOWN ACK → SHUTDOWN COMPLETE.
@("sctp: a graceful shutdown closes both sides")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.shutdown(0);
	ferry(client, server);

	client.state.should.equal(AssocState.closed);
	server.state.should.equal(AssocState.closed);
}

// Shutdown flushes data first: a message sent just before shutdown is still
// delivered, and only then does the association close.
@("sctp: shutdown drains queued data before closing")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, cast(ubyte[]) "goodbye".dup);
	client.shutdown(0); // data is still outstanding: enter pending, not sent
	client.state.should.equal(AssocState.shutdownPending);

	ferry(client, server);

	auto msgs = server.receive();
	msgs.length.should.equal(1);
	(cast(string) msgs[0].data).should.equal("goodbye");
	client.state.should.equal(AssocState.closed);
	server.state.should.equal(AssocState.closed);
}

// An unanswered SHUTDOWN retransmits on T2 and, past the cap, fails the
// association rather than hanging.
@("sctp: an unanswered SHUTDOWN retransmits then fails")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.shutdown(0);
	auto first = client.takeOutbound(0);
	first.length.should.equal(1);
	Packet.decode(first[0]).chunks[0].typ.should.equal(cast(ubyte) ChunkType.shutdown);

	// One retransmit after the RTO.
	client.handleTimeout(3000);
	auto again = client.takeOutbound(3000);
	again.length.should.equal(1);
	Packet.decode(again[0]).chunks[0].typ.should.equal(cast(ubyte) ChunkType.shutdown);

	// Driven past the cap — each retransmit backs the RTO off toward 60 s — it
	// fails rather than retrying forever.
	long now = 6000;
	foreach (_; 0 .. 12)
	{
		client.handleTimeout(now);
		if (client.state == AssocState.failed)
			break;
		now += 61_000;
	}
	client.state.should.equal(AssocState.failed);
}

// ABORT closes immediately, and a received ABORT closes the peer.
@("sctp: abort closes both sides immediately")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.abort();
	client.state.should.equal(AssocState.closed);

	auto outs = client.takeOutbound(0);
	outs.length.should.equal(1);
	Packet.decode(outs[0]).chunks[0].typ.should.equal(cast(ubyte) ChunkType.abort);

	server.handleInbound(outs[0], 0);
	server.state.should.equal(AssocState.closed);
}

// An ABORT carrying the wrong verification tag is ignored (no forced close).
@("sctp: an ABORT with the wrong verification tag is ignored")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	Packet forged;
	forged.srcPort = 5000;
	forged.dstPort = 5000;
	forged.verificationTag = server.localInitiateTag ^ 0x1; // not the server's tag
	forged.chunks ~= Chunk(ChunkType.abort, 0, null);
	server.handleInbound(forged.encode, 0);
	server.state.should.equal(AssocState.established); // still up
}

private ubyte[] u32(uint v)
{
	return [cast(ubyte)(v >> 24), cast(ubyte)(v >> 16), cast(ubyte)(v >> 8), cast(ubyte) v];
}

private uint readu32(scope const(ubyte)[] b)
{
	return (cast(uint) b[0] << 24) | (cast(uint) b[1] << 16) | (cast(uint) b[2] << 8) | b[3];
}

// A graceful shutdown still completes when data is lost mid-close: the dropped
// chunk is retransmitted during the draining phase, delivered, and both close.
@("sctp: shutdown recovers a chunk lost during the close")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	ubyte[] payload = new ubyte[3000];
	foreach (i; 0 .. payload.length)
		payload[i] = cast(ubyte)(i + 1);
	client.send(0, 55, payload);
	client.shutdown(0);

	long now;
	ubyte[] got;
	bool dropped;
	foreach (_; 0 .. 100)
	{
		client.handleTimeout(now);
		server.handleTimeout(now);
		foreach (d; client.takeOutbound(now))
		{
			auto pk = Packet.decode(d);
			if (!dropped && pk.chunks[0].typ == ChunkType.data)
			{
				dropped = true;
				continue; // lose the first DATA once
			}
			server.handleInbound(d, now);
		}
		foreach (d; server.takeOutbound(now))
			client.handleInbound(d, now);
		auto m = server.receive();
		if (m.length)
			got = m[0].data;
		if (client.state == AssocState.closed && server.state == AssocState.closed)
			break;
		now += 500;
	}
	dropped.should.equal(true);
	got.should.equal(payload);
	client.state.should.equal(AssocState.closed);
	server.state.should.equal(AssocState.closed);
}

// If the peer vanishes mid-close, the draining shutdown does not hang forever:
// the association-level retransmit counter eventually fails it.
@("sctp: a shutdown against a vanished peer fails rather than hanging")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 55, new ubyte[500]);
	client.shutdown(0);

	long now;
	foreach (_; 0 .. 20)
	{
		client.handleTimeout(now);
		client.takeOutbound(now); // flush/retransmit into the void
		if (client.state == AssocState.failed)
			break;
		now += 61_000;
	}
	client.state.should.equal(AssocState.failed);
}

// A peer's SHUTDOWN arriving while we still have unacked data does not tear us
// down early: we enter SHUTDOWN-RECEIVED and ACK only once our data drains.
@("sctp: an inbound SHUTDOWN waits for our data to drain before acking")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, cast(ubyte[]) "hold".dup);
	auto sent = client.takeOutbound(0);
	immutable tsn = readu32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);
	client.bytesInFlight.should.equal(4u);

	// SHUTDOWN whose cumulative ack does NOT cover our sent chunk.
	Packet sd;
	sd.srcPort = 5000;
	sd.dstPort = 5000;
	sd.verificationTag = client.localInitiateTag;
	sd.chunks ~= Chunk(ChunkType.shutdown, 0, u32(tsn - 1));
	client.handleInbound(sd.encode, 0);
	client.state.should.equal(AssocState.shutdownReceived); // not acked yet

	bool sawAck;
	foreach (d; client.takeOutbound(0))
		if (Packet.decode(d).chunks[0].typ == ChunkType.shutdownAck)
			sawAck = true;
	sawAck.should.equal(false); // no SHUTDOWN ACK while our data is unacked

	// Now ack our data: draining completes and the SHUTDOWN ACK goes out.
	ubyte[] sackVal = u32(tsn) ~ u32(200_000) ~ cast(ubyte[])[0, 0, 0, 0];
	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, sackVal);
	client.handleInbound(sack.encode, 0);
	client.state.should.equal(AssocState.shutdownAckSent);
}

// Both sides calling shutdown at once still converges to closed.
@("sctp: simultaneous shutdown closes both sides")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.shutdown(0);
	server.shutdown(0);
	ferry(client, server);

	client.state.should.equal(AssocState.closed);
	server.state.should.equal(AssocState.closed);
}

// After abort, no DATA queued before it leaks onto the wire — only the ABORT.
@("sctp: abort with queued data emits nothing after the ABORT")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, cast(ubyte[]) "unsent".dup); // queued
	client.abort();
	auto outs = client.takeOutbound(0);
	outs.length.should.equal(1);
	Packet.decode(outs[0]).chunks[0].typ.should.equal(cast(ubyte) ChunkType.abort);
}
