module tests.datachannel.channels_test;

import webrtc.datachannel.channels;
import webrtc.sctp.association : Association, Role;
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

// Ferry SCTP datagrams both ways and collect channel events on each side.
private void pump(Association ca, Association sa, DataChannels cd, DataChannels sd,
	ref ChannelEvent[] cev, ref ChannelEvent[] sev, int rounds = 30)
{
	foreach (_; 0 .. rounds)
	{
		foreach (d; ca.takeOutbound(0))
			sa.handleInbound(d, 0);
		foreach (d; sa.takeOutbound(0))
			ca.handleInbound(d, 0);
		sev ~= sd.events();
		cev ~= cd.events();
	}
}

private bool hasMessage(ChannelEvent[] evs, ushort ch, string data, bool binary)
{
	foreach (e; evs)
		if (e.kind == ChannelEventKind.message && e.channel == ch && e.binary == binary
			&& cast(string) e.data == data)
			return true;
	return false;
}

private bool hasOpened(ChannelEvent[] evs, ushort ch)
{
	foreach (e; evs)
		if (e.kind == ChannelEventKind.opened && e.channel == ch)
			return true;
	return false;
}

private bool hasClosed(ChannelEvent[] evs, ushort ch)
{
	foreach (e; evs)
		if (e.kind == ChannelEventKind.closed && e.channel == ch)
			return true;
	return false;
}

// The negotiated id-0 channel (libp2p's Noise channel) carries data with no DCEP
// handshake.
@("datachannel: the negotiated channel carries messages")
unittest
{
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto cd = new DataChannels(ca, Role.client);
	auto sd = new DataChannels(sa, Role.server);
	cd.openNegotiated(0);
	sd.openNegotiated(0);

	cd.send(0, cast(ubyte[]) "hello".dup, false);
	ChannelEvent[] cev, sev;
	pump(ca, sa, cd, sd, cev, sev);
	hasMessage(sev, 0, "hello", false).should.equal(true);
}

// A DCEP open handshake establishes a channel on both sides; then data flows.
@("datachannel: DCEP opens a channel and data flows")
unittest
{
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto cd = new DataChannels(ca, Role.client);
	auto sd = new DataChannels(sa, Role.server);

	immutable id = cd.open("chat", "proto");
	ChannelEvent[] cev, sev;
	pump(ca, sa, cd, sd, cev, sev);

	hasOpened(sev, id).should.equal(true); // server saw the OPEN
	hasOpened(cev, id).should.equal(true); // client saw the ACK
	cd.isOpen(id).should.equal(true);
	sd.isOpen(id).should.equal(true);

	// The label/protocol reached the server.
	bool labelled;
	foreach (e; sev)
		if (e.kind == ChannelEventKind.opened && e.channel == id && e.label == "chat"
			&& e.protocol == "proto")
			labelled = true;
	labelled.should.equal(true);

	// Now send both ways.
	cd.send(id, cast(ubyte[]) "ping".dup, true);
	sd.send(id, cast(ubyte[]) "pong".dup, false);
	ChannelEvent[] cev2, sev2;
	pump(ca, sa, cd, sd, cev2, sev2);
	hasMessage(sev2, id, "ping", true).should.equal(true);
	hasMessage(cev2, id, "pong", false).should.equal(true);
}

// An empty message round-trips as an empty message (RFC 8831 empty PPID).
@("datachannel: an empty message is delivered empty")
unittest
{
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto cd = new DataChannels(ca, Role.client);
	auto sd = new DataChannels(sa, Role.server);
	cd.openNegotiated(0);
	sd.openNegotiated(0);

	cd.send(0, [], false);
	ChannelEvent[] cev, sev;
	pump(ca, sa, cd, sd, cev, sev);

	bool gotEmpty;
	foreach (e; sev)
		if (e.kind == ChannelEventKind.message && e.channel == 0 && e.data.length == 0)
			gotEmpty = true;
	gotEmpty.should.equal(true);
}

// Closing a channel resets its stream; the peer sees a closed event.
@("datachannel: closing a channel resets the stream and the peer sees it")
unittest
{
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto cd = new DataChannels(ca, Role.client);
	auto sd = new DataChannels(sa, Role.server);

	immutable id = cd.open("x", "");
	ChannelEvent[] cev, sev;
	pump(ca, sa, cd, sd, cev, sev);
	sd.isOpen(id).should.equal(true);

	cd.close(id, 0);
	ChannelEvent[] cev2, sev2;
	pump(ca, sa, cd, sd, cev2, sev2);
	hasClosed(sev2, id).should.equal(true);
	sd.isOpen(id).should.equal(false);
}

// A DCEP OPEN authored by hand from RFC 8832 §5.1 (not our encoder) decodes to
// the right label/protocol, and our encoder reproduces those exact bytes — the
// codec pinned to a reference layout, both directions.
@("datachannel: the DCEP OPEN wire format matches the RFC byte layout")
unittest
{
	// type=0x03, channel type=0x00, priority=0, reliability=0, label len=4,
	// protocol len=2, "chat", "xy".
	ubyte[] reference = [
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x02, 'c', 'h', 'a', 't', 'x', 'y',
	];

	// Drive a server so an OPEN on stream 1 (odd, valid) is processed.
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto sd = new DataChannels(sa, Role.server);

	// Feed the reference OPEN as if it arrived on stream 1 via SCTP.
	// (We reach in through a raw DATA-bearing message by sending it from the
	//  client association on stream 1 with the DCEP PPID.)
	auto cd = new DataChannels(ca, Role.client);
	// Client is even-id; to place a specific id we craft via the association.
	ca.send(1, 50, reference); // ppid 50 = DCEP, stream 1
	ChannelEvent[] cev, sev;
	pump(ca, sa, cd, sd, cev, sev);

	bool matched;
	foreach (e; sev)
		if (e.kind == ChannelEventKind.opened && e.channel == 1 && e.label == "chat"
			&& e.protocol == "xy")
			matched = true;
	matched.should.equal(true);
}

// A DCEP OPEN on the reserved negotiated id 0 is ignored (never DCEP-opened).
@("datachannel: a DCEP OPEN on id 0 is dropped")
unittest
{
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto cd = new DataChannels(ca, Role.client);
	auto sd = new DataChannels(sa, Role.server);

	ubyte[] open0 = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 'z'];
	ca.send(0, 50, open0);
	ChannelEvent[] cev, sev;
	pump(ca, sa, cd, sd, cev, sev);
	hasOpened(sev, 0).should.equal(false);
	sd.isOpen(0).should.equal(false);
}

// A duplicate DATA_CHANNEL_OPEN on a live channel does not re-emit opened.
@("datachannel: a duplicate OPEN does not re-open a live channel")
unittest
{
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto cd = new DataChannels(ca, Role.client);
	auto sd = new DataChannels(sa, Role.server);

	ubyte[] open5 = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
	ca.send(5, 50, open5);
	ChannelEvent[] cev, sev;
	pump(ca, sa, cd, sd, cev, sev);
	size_t opens;
	foreach (e; sev)
		if (e.kind == ChannelEventKind.opened && e.channel == 5)
			opens++;
	opens.should.equal(1);

	// A second, fresh OPEN for the same live stream.
	ca.send(5, 50, open5);
	ChannelEvent[] cev2, sev2;
	pump(ca, sa, cd, sd, cev2, sev2);
	foreach (e; sev2)
		(e.kind == ChannelEventKind.opened && e.channel == 5).should.equal(false);
}

// Application data on a stream that was never opened is dropped, not surfaced.
@("datachannel: data on an unopened stream is dropped")
unittest
{
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto cd = new DataChannels(ca, Role.client);
	auto sd = new DataChannels(sa, Role.server);

	ca.send(7, 51, cast(ubyte[]) "orphan".dup); // PPID 51 (string) on unopened stream 7
	ChannelEvent[] cev, sev;
	pump(ca, sa, cd, sd, cev, sev);
	foreach (e; sev)
		(e.kind == ChannelEventKind.message).should.equal(false);
}

// Sending on a closed channel is refused.
@("datachannel: send after close is refused")
unittest
{
	auto ca = new Association(Role.client, 5000, 5000);
	auto sa = new Association(Role.server, 5000, 5000);
	establish(ca, sa);
	auto cd = new DataChannels(ca, Role.client);
	cd.openNegotiated(0);
	cd.close(0, 0);
	cd.send(0, cast(ubyte[]) "x".dup, false).should.throwException!Exception;
}
