/// SCTP under loss: the recovery paths a clean in-memory ferry never exercises.
module tests.sctp.lossy_test;

import webrtc.sctp.association;
import webrtc.sctp.packet;
import fluent.asserts : should;

private struct InFlight
{
	long at;
	ubyte[] data;
}

// A one-way link: fixed delay, a serialisation rate, random loss.
private struct Link
{
	long delayMs;
	long perPacketUs; // serialisation time per packet
	uint lossPermille;
	InFlight[] q;
	long busyUntilUs;
	size_t sent, dropped;
	uint rng = 12345;

	uint next()
	{
		rng = rng * 1103515245 + 12345;
		return (rng >> 16) % 1000;
	}

	void put(long nowMs, ubyte[] d)
	{
		sent++;
		if (next() < lossPermille)
		{
			dropped++;
			return;
		}
		immutable nowUs = nowMs * 1000;
		busyUntilUs = (busyUntilUs > nowUs ? busyUntilUs : nowUs) + perPacketUs;
		q ~= InFlight(busyUntilUs / 1000 + delayMs, d);
	}

	ubyte[][] due(long nowMs)
	{
		ubyte[][] o;
		size_t k;
		foreach (f; q)
			if (f.at <= nowMs)
				o ~= f.data;
			else
				q[k++] = f;
		q = q[0 .. k];
		return o;
	}
}

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

// A bulk transfer over a lossy, delayed link keeps moving: 1 % loss each way,
// 40 ms each way, ~2.4 MB/s of serialisation. Losses are recovered by fast
// retransmit within the flight and by T3 for whole-flight losses — no loss may
// leave the association waiting out backed-off timers (it did: a lost chunk
// behind another waited 16, 32 s).
@("sctp: a bulk transfer over a lossy link keeps its throughput")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);
	auto up = Link(40, 500, 10);
	auto down = Link(40, 500, 10, null, 0, 0, 0, 999);
	size_t delivered;
	long longestGap, lastDelivery;
	auto msg = new ubyte[16 * 1024];
	foreach (ms; 0 .. 20_000)
	{
		immutable now = ms + 1;
		while (client.canSend(msg.length))
			client.send(0, 53, msg);
		client.handleTimeout(now);
		server.handleTimeout(now);
		foreach (d; up.due(now))
			server.handleInbound(d, now);
		foreach (d; down.due(now))
			client.handleInbound(d, now);
		if (auto got = server.receive())
		{
			foreach (m; got)
				delivered += m.data.length;
			if (lastDelivery && now - lastDelivery > longestGap)
				longestGap = now - lastDelivery;
			lastDelivery = now;
		}
		foreach (d; client.takeOutbound(now))
			up.put(now, d);
		foreach (d; server.takeOutbound(now))
			down.put(now, d);
	}
	(up.dropped > 50).should.equal(true); // the link really lost packets
	(delivered / 20 > 400_000).should.equal(true); // > 400 KB/s (the window allows ~1.6 MB/s)
	(longestGap < 2000).should.equal(true); // never stuck for seconds
}

// On a T3 expiry every chunk of the flight is resent — the earliest at once,
// the rest as acks reopen the window — not one per (doubling) timer.
@("sctp: a T3 expiry resends the whole flight, not one chunk per timer")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, new ubyte[4000]); // four chunks
	client.takeOutbound(0).length.should.equal(4); // all lost
	client.handleTimeout(3000); // T3: RTO.Initial
	auto first = client.takeOutbound(3000);
	first.length.should.equal(1); // cwnd is one MTU now
	foreach (d; first)
		server.handleInbound(d, 3010);
	long now = 3020;
	size_t resent = first.length;
	foreach (_; 0 .. 10)
	{
		foreach (d; server.takeOutbound(now))
			client.handleInbound(d, now);
		auto more = client.takeOutbound(now);
		resent += more.length;
		foreach (d; more)
			server.handleInbound(d, now + 5);
		now += 10;
	}
	resent.should.equal(4); // the rest followed the acks, well inside one RTO
	auto msgs = server.receive();
	msgs.length.should.equal(1);
	msgs[0].data.length.should.equal(4000);
}

// A window smaller than one chunk stops the sender as surely as a zero one; with
// nothing in flight, the probe timer must go off, or the association deadlocks.
@("sctp: a window smaller than a chunk, nothing in flight, is probed")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 53, cast(ubyte[]) "first".dup);
	auto sent = client.takeOutbound(0);
	immutable tsn0 = readU32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);
	ubyte[] sackVal = new ubyte[12];
	writeU32(sackVal[0 .. 4], tsn0);
	writeU32(sackVal[4 .. 8], 500); // room, but less than the next chunk
	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, sackVal);
	client.handleInbound(sack.encode, 100);

	client.send(0, 53, new ubyte[1000]);
	client.takeOutbound(200).length.should.equal(0); // held back by the window
	client.handleTimeout(200); // arms the probe
	client.handleTimeout(200 + 60_000);
	auto probe = client.takeOutbound(60_200);
	probe.length.should.equal(1);
	Packet.decode(probe[0]).chunks[0].typ.should.equal(cast(ubyte) ChunkType.data);
}

// A receiver that advertised a small window tells the sender as soon as the
// application drains it — a window update — rather than leaving it to a probe.
@("sctp: draining a nearly full receive buffer sends a window update")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	// Fill the server's receive buffer without the application reading it.
	auto msg = new ubyte[16 * 1024];
	foreach (_; 0 .. 7)
		client.send(0, 53, msg);
	foreach (_; 0 .. 200)
	{
		foreach (d; client.takeOutbound(0))
			server.handleInbound(d, 0);
		foreach (d; server.takeOutbound(0))
			client.handleInbound(d, 0);
	}
	(server.receiveWindowBytes < 32 * 1024).should.equal(true);
	server.takeOutbound(0).length.should.equal(0); // nothing new to say

	server.receive(); // the application reads it all
	auto update = server.takeOutbound(0);
	update.length.should.equal(1);
	auto chunk = Packet.decode(update[0]).chunks[0];
	chunk.typ.should.equal(cast(ubyte) ChunkType.sack);
	(readU32(chunk.value[4 .. 8]) > 100 * 1024).should.equal(true); // the reopened window
}

private uint readU32(const(ubyte)[] b)
{
	return (uint(b[0]) << 24) | (uint(b[1]) << 16) | (uint(b[2]) << 8) | b[3];
}

private void writeU32(ubyte[] b, uint v)
{
	b[0] = cast(ubyte)(v >> 24);
	b[1] = cast(ubyte)(v >> 16);
	b[2] = cast(ubyte)(v >> 8);
	b[3] = cast(ubyte) v;
}

// A fast retransmit of the earliest chunk restarts T3 (RFC 4960 §7.2.4 step 4):
// the timer must not fire on it again before its recovery can be acknowledged.
@("sctp: a fast retransmit of the earliest chunk restarts the T3 timer")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);

	client.send(0, 55, new ubyte[5000]); // X .. X+4, T3 armed at 0 (RTO.Initial 3 s)
	auto sent = client.takeOutbound(0);
	immutable firstTsn = readU32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);
	foreach (i; 0 .. 3) // X+1, X+1..2, X+1..3 acked: X reported missing three times
		client.handleInbound(sackWithGap(client, firstTsn - 1, 2, cast(ushort)(2 + i)), 2900 + i);
	client.takeOutbound(2905);
	immutable cwndFr = client.congestionWindow; // cut once, by fast recovery
	(cwndFr > 1200).should.equal(true);

	// T3 ran from 0; restarted at the fast retransmit (2902) it runs to 2902 + RTO.
	// Just past the original deadline, the restarted one has not come.
	immutable rto = client.retransmitTimeout;
	client.handleTimeout(rto + 100);
	client.congestionWindow.should.equal(cwndFr); // no T3 collapse to one MTU
}

private ubyte[] sackWithGap(Association client, uint cum, ushort start, ushort end)
{
	ubyte[] v = new ubyte[16];
	writeU32(v[0 .. 4], cum);
	writeU32(v[4 .. 8], 200_000);
	v[8] = 0;
	v[9] = 1;
	v[12] = cast(ubyte)(start >> 8);
	v[13] = cast(ubyte) start;
	v[14] = cast(ubyte)(end >> 8);
	v[15] = cast(ubyte) end;
	Packet sack;
	sack.srcPort = 5000;
	sack.dstPort = 5000;
	sack.verificationTag = client.localInitiateTag;
	sack.chunks ~= Chunk(ChunkType.sack, 0, v);
	return sack.encode;
}

// A hole found later in the same Fast Recovery is resent under the window by
// flush(); when it is by then the earliest outstanding chunk, that resend
// restarts T3 as well.
@("sctp: a deferred fast retransmit of the earliest chunk restarts T3")
unittest
{
	auto client = new Association(Role.client, 5000, 5000);
	auto server = new Association(Role.server, 5000, 5000);
	establish(client, server);
	// Warm up: a clean transfer opens the congestion window past eight chunks.
	client.send(0, 55, new ubyte[60_000]);
	foreach (_; 0 .. 100)
	{
		foreach (d; client.takeOutbound(0))
			server.handleInbound(d, 0);
		foreach (d; server.takeOutbound(0))
			client.handleInbound(d, 0);
	}
	server.receive();
	(client.congestionWindow >= 8 * 1200).should.equal(true);
	client.bytesInFlight.should.equal(0u);

	client.send(0, 55, new ubyte[8000]); // X .. X+7, all sent at once
	auto sent = client.takeOutbound(0);
	sent.length.should.equal(8);
	immutable x = readU32(Packet.decode(sent[0]).chunks[0].value[0 .. 4]);
	// X is lost: reported missing by three SACKs -> Fast Recovery (exit X+7).
	foreach (i; 0 .. 3)
		client.handleInbound(sackWithGap(client, x - 1, 2, cast(ushort)(2 + i)), 100 + i);
	client.takeOutbound(105);
	// X's resend arrives (cumulative X+3: T3 restarts, R3) and X+4 is lost:
	// three reports while still in recovery -> deferred to flush().
	immutable tc = 200;
	client.handleInbound(sackWithGap(client, x + 3, 2, 2), tc);
	client.handleInbound(sackWithGap(client, x + 3, 2, 3), tc + 1);
	client.handleInbound(sackWithGap(client, x + 3, 2, 4), tc + 2);
	immutable cwndFr = client.congestionWindow;
	bool resent;
	foreach (d; client.takeOutbound(tc + 3))
	{
		auto pk = Packet.decode(d);
		if (pk.chunks[0].typ == ChunkType.data && readU32(pk.chunks[0].value[0 .. 4]) == x + 4)
			resent = true;
	}
	resent.should.equal(true);

	// Past the deadline T3 had before the resend (tc + RTO), short of the restarted one.
	client.handleTimeout(tc + client.retransmitTimeout + 1);
	client.congestionWindow.should.equal(cwndFr); // no T3 collapse
}
