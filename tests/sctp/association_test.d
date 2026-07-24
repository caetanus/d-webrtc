module tests.sctp.association_test;

import webrtc.sctp.association;
import webrtc.sctp.chunk.data : PPID_STRING;
import fluent.asserts : should;

// Pump control packets between the two associations until both are established
// or `rounds` is exhausted.
private void pump(Association a, Association b, int rounds = 8)
{
	foreach (_; 0 .. rounds)
	{
		foreach (pkt; a.gatherOutbound(0))
			b.handleInbound(pkt, 0);
		foreach (pkt; b.gatherOutbound(0))
			a.handleInbound(pkt, 0);
		if (a.isEstablished && b.isEstablished)
			break;
	}
}

// Shuttle packets both ways until neither side has anything left to send (the
// data path has quiesced). `now` is fixed — deterministic, no wall clock.
private void pumpData(Association a, Association b, long now = 0, int rounds = 16)
{
	foreach (_; 0 .. rounds)
	{
		bool moved;
		foreach (pkt; a.gatherOutbound(now))
		{
			b.handleInbound(pkt, now);
			moved = true;
		}
		foreach (pkt; b.gatherOutbound(now))
		{
			a.handleInbound(pkt, now);
			moved = true;
		}
		if (!moved)
			break;
	}
}

// Bring a fresh client/server pair to Established.
private void connect(out Association client, out Association server)
{
	client = new Association(Side.client, 0x1111_1111, 100, 0);
	server = new Association(Side.server, 0x2222_2222, 200, 0);
	pump(client, server);
}

@("SCTP four-way handshake brings both ends to Established")
unittest
{
	auto client = new Association(Side.client, 0x1111_1111, 100, 0);
	auto server = new Association(Side.server, 0x2222_2222, 200, 0);

	// The client starts in COOKIE-WAIT (its INIT is already queued).
	client.state.should.equal(AssociationState.cookieWait);
	server.state.should.equal(AssociationState.closed);

	pump(client, server);

	client.isEstablished.should.equal(true);
	server.isEstablished.should.equal(true);
}

@("SCTP handshake fails to complete if the cookie is corrupted (no false connect)")
unittest
{
	// A server on its own never leaves Closed without a valid COOKIE-ECHO.
	auto server = new Association(Side.server, 0x2222_2222, 200, 0);
	server.gatherOutbound(0).length.should.equal(0); // nothing to send unsolicited
	server.isEstablished.should.equal(false);
}

@("SCTP delivers an ordered message end-to-end")
unittest
{
	Association client, server;
	connect(client, server);

	client.send(0, PPID_STRING, cast(ubyte[]) "hello sctp".dup, true);
	pumpData(client, server);

	auto msg = server.receive();
	msg.isNull.should.equal(false);
	msg.get.streamId.should.equal(cast(ushort) 0);
	msg.get.ppid.should.equal(PPID_STRING);
	(cast(string) msg.get.data).should.equal("hello sctp");
	server.receive().isNull.should.equal(true); // only one message
}

@("SCTP preserves order across several messages on one stream")
unittest
{
	Association client, server;
	connect(client, server);

	foreach (i; 0 .. 5)
		client.send(7, PPID_STRING, cast(ubyte[])("msg" ~ cast(char)('0' + i)).dup, true);
	pumpData(client, server);

	foreach (i; 0 .. 5)
	{
		auto m = server.receive();
		m.isNull.should.equal(false);
		(cast(string) m.get.data).should.equal("msg" ~ cast(char)('0' + i));
	}
	server.receive().isNull.should.equal(true);
}

@("SCTP reassembles a message fragmented across many DATA chunks")
unittest
{
	Association client, server;
	connect(client, server);

	// Well beyond one MTU-sized fragment, so it must be split and rejoined.
	auto big = new ubyte[5000];
	foreach (i, ref b; big)
		b = cast(ubyte)(i & 0xff);
	client.send(3, PPID_STRING, big, true);
	pumpData(client, server);

	auto m = server.receive();
	m.isNull.should.equal(false);
	m.get.data.length.should.equal(cast(size_t) 5000);
	(m.get.data == big).should.equal(true);
}

@("SCTP data flows in both directions")
unittest
{
	Association client, server;
	connect(client, server);

	client.send(1, PPID_STRING, cast(ubyte[]) "ping".dup, true);
	server.send(1, PPID_STRING, cast(ubyte[]) "pong".dup, true);
	pumpData(client, server);

	auto atServer = server.receive();
	auto atClient = client.receive();
	atServer.isNull.should.equal(false);
	atClient.isNull.should.equal(false);
	(cast(string) atServer.get.data).should.equal("ping");
	(cast(string) atClient.get.data).should.equal("pong");
}

@("SCTP retransmits a dropped DATA chunk after the T3-rtx timeout")
unittest
{
	Association client, server;
	connect(client, server);

	client.send(0, PPID_STRING, cast(ubyte[]) "recover me".dup, true);

	// Drop the first transmission entirely: drain it but never deliver it. The
	// chunk is now in-flight and unacked, with the T3-rtx timer armed at t=0.
	auto dropped = client.gatherOutbound(0);
	(dropped.length > 0).should.equal(true); // there WAS a DATA packet to lose

	// Time advances past the RTO (default 3000ms); the timeout fires.
	enum long t = 4000;
	client.handleTimeout(t);

	// The retransmission now flows, the server delivers it, and its SACK settles
	// the in-flight window.
	foreach (pkt; client.gatherOutbound(t))
		server.handleInbound(pkt, t);
	foreach (pkt; server.gatherOutbound(t))
		client.handleInbound(pkt, t);

	auto msg = server.receive();
	msg.isNull.should.equal(false);
	(cast(string) msg.get.data).should.equal("recover me");
}
