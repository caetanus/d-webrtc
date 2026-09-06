module tests.ice.agent_test;

import webrtc.ice.agent;
import webrtc.ice.candidate : Candidate;
import webrtc.stun.message;
import fluent.asserts : should;

// ICE has no RFC sample exchange to replay the way STUN does, so the vector here
// is the protocol's own behaviour driven end to end: two independent agents,
// each only touched through its sans-io surface, ferried by an in-memory pump
// that does nothing but move bytes and tag them with (from, to). Nothing reads a
// clock — `now` is advanced by hand — and nothing spawns.

private enum aAddr = TransportAddr("127.0.0.1", 4001);
private enum bAddr = TransportAddr("127.0.0.1", 4002);
private enum aCreds = Credentials("AAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaa");
private enum bCreds = Credentials("BBBBBBBB", "bbbbbbbbbbbbbbbbbbbbbb");

// Ferry one agent's output into the other, gathering afresh each tick, until both
// connect or the clock runs out. Returns whether they connected.
private bool pump(Agent a, Agent b) @safe
{
	long now = 0;
	foreach (_; 0 .. 500)
	{
		if (a.isConnected && b.isConnected)
			return true;
		a.handleTimeout(now);
		b.handleTimeout(now);
		auto fromA = a.gatherOutbound(now);
		auto fromB = b.gatherOutbound(now);
		foreach (o; fromA)
			b.handleInbound(o.data, o.src, o.dst, now);
		foreach (o; fromB)
			a.handleInbound(o.data, o.src, o.dst, now);
		now += 20;
	}
	return a.isConnected && b.isConnected;
}

// Ferry both directions for a stretch of simulated time, so consent checks and
// their responses flow. Returns the clock it stopped at.
private long ferry(Agent a, Agent b, long start, long stepMs, int ticks) @safe
{
	long now = start;
	foreach (_; 0 .. ticks)
	{
		a.handleTimeout(now);
		b.handleTimeout(now);
		auto fromA = a.gatherOutbound(now);
		auto fromB = b.gatherOutbound(now);
		foreach (o; fromA)
			b.handleInbound(o.data, o.src, o.dst, now);
		foreach (o; fromB)
			a.handleInbound(o.data, o.src, o.dst, now);
		now += stepMs;
	}
	return now;
}

private Agent controllingAgent() @safe
{
	auto a = new Agent(Role.controlling, aCreds, 0x2222_2222_2222_2222);
	a.setRemoteCredentials(bCreds);
	a.addLocalCandidate(Candidate.host(aAddr.ip, aAddr.port));
	a.addRemoteCandidate(Candidate.host(bAddr.ip, bAddr.port));
	return a;
}

private Agent controlledAgent() @safe
{
	auto b = new Agent(Role.controlled, bCreds, 0x1111_1111_1111_1111);
	b.setRemoteCredentials(aCreds);
	b.addLocalCandidate(Candidate.host(bAddr.ip, bAddr.port));
	b.addRemoteCandidate(Candidate.host(aAddr.ip, aAddr.port));
	return b;
}

@("ice: a controlling and a controlled agent nominate the same pair")
unittest
{
	auto a = new Agent(Role.controlling, aCreds, 0x2222_2222_2222_2222);
	auto b = new Agent(Role.controlled, bCreds, 0x1111_1111_1111_1111);
	a.setRemoteCredentials(bCreds);
	b.setRemoteCredentials(aCreds);
	a.addLocalCandidate(Candidate.host(aAddr.ip, aAddr.port));
	a.addRemoteCandidate(Candidate.host(bAddr.ip, bAddr.port));
	b.addLocalCandidate(Candidate.host(bAddr.ip, bAddr.port));
	b.addRemoteCandidate(Candidate.host(aAddr.ip, aAddr.port));

	pump(a, b).should.equal(true);

	a.connectionState.should.equal(ConnectionState.connected);
	b.connectionState.should.equal(ConnectionState.connected);

	TransportAddr al, ar, bl, br;
	a.selectedPair(al, ar).should.equal(true);
	b.selectedPair(bl, br).should.equal(true);
	// The one pair, seen from each side: local/remote swapped.
	al.port.should.equal(aAddr.port);
	ar.port.should.equal(bAddr.port);
	bl.port.should.equal(bAddr.port);
	br.port.should.equal(aAddr.port);
}

// A check that fails MESSAGE-INTEGRITY must be dropped: no response, no connect.
// A valid check to the same agent proves the drop was about the HMAC, not a dead
// agent — and that the valid one is learned peer-reflexive and answered.
@("ice: a bad MESSAGE-INTEGRITY check is refused; a valid one is learned and answered")
unittest
{
	auto b = new Agent(Role.controlled, bCreds, 0x1111_1111_1111_1111);
	b.setRemoteCredentials(aCreds);
	b.addLocalCandidate(Candidate.host(bAddr.ip, bAddr.port));
	// No remote candidate: the valid check must be learned peer-reflexive.

	auto forged = binding("BBBBBBBB:AAAAAAAA", "not-the-password");
	b.handleInbound(forged, aAddr, bAddr, 0);
	b.gatherOutbound(0).length.should.equal(0);
	b.isConnected.should.equal(false);

	auto good = binding("BBBBBBBB:AAAAAAAA", bCreds.pwd);
	b.handleInbound(good, aAddr, bAddr, 0);
	auto outs = b.gatherOutbound(0);

	// Exactly one success response, back to the sender and signed with our pwd —
	// alongside it, having learned the pair peer-reflexive, B also starts its own
	// check, so there is a request too.
	size_t responses, requests;
	foreach (o; outs)
	{
		auto msg = Message.decode(o.data);
		if (msg.typ == bindingSuccess)
		{
			responses++;
			msg.checkMessageIntegrity(cast(ubyte[]) bCreds.pwd).should.equal(true);
			o.dst.port.should.equal(aAddr.port);
		}
		else if (msg.typ == bindingRequest)
			requests++;
	}
	responses.should.equal(1);
	requests.should.equal(1);
}

// A check signed with `pwd`, USERNAME as given, priority and controlling role.
private ubyte[] binding(string username, string pwd)
{
	Message m;
	m.typ = bindingRequest;
	m.transactionId = Message.randomTransactionId();
	m.attributes ~= Attribute(attrUsername, cast(ubyte[]) username.dup);
	m.attributes ~= Attribute(attrPriority, cast(ubyte[])[0x7e, 0, 0, 0xff]);
	m.attributes ~= Attribute(attrIceControlling, cast(ubyte[])[0, 0, 0, 0, 0, 0, 0, 1]);
	m.addMessageIntegrity(cast(ubyte[]) pwd);
	m.addFingerprint();
	return m.encode;
}

// With no peer ever answering, the checks retransmit on the §14 schedule and the
// pair — and the agent — end in Failed rather than hanging.
@("ice: unanswered checks retransmit, then the agent fails")
unittest
{
	auto a = new Agent(Role.controlling, aCreds, 0x2222_2222_2222_2222);
	a.setRemoteCredentials(bCreds);
	a.addLocalCandidate(Candidate.host(aAddr.ip, aAddr.port));
	a.addRemoteCandidate(Candidate.host(bAddr.ip, bAddr.port));

	// The first check goes out at once.
	auto first = a.gatherOutbound(0);
	first.length.should.equal(1);
	Message.decode(first[0].data).typ.should.equal(bindingRequest);

	// One retransmit after the RTO — a second check to the same peer.
	auto again = a.gatherOutbound(500);
	again.length.should.equal(1);
	Message.decode(again[0].data).typ.should.equal(bindingRequest);
	again[0].dst.port.should.equal(bAddr.port);

	// Driven past the try cap, the agent reaches Failed.
	for (long now = 1000; now <= 8000 && !a.isConnected; now += 500)
		a.handleTimeout(now);
	a.connectionState.should.equal(ConnectionState.failed);
}

// Once connected, consent checks flow and are answered, so the connection holds
// well past the consent timeout.
@("ice: consent freshness keeps a connected pair alive")
unittest
{
	auto a = controllingAgent();
	auto b = controlledAgent();
	pump(a, b).should.equal(true);

	// 60 s of ferried traffic — twelve consent intervals, twice the timeout.
	ferry(a, b, 200, 1000, 60);

	a.isConnected.should.equal(true);
	b.isConnected.should.equal(true);
}

// If the path goes dead after connecting, consent is not refreshed and the
// controlling agent fails rather than believing forever it is still connected.
@("ice: lost consent fails the connection")
unittest
{
	auto a = controllingAgent();
	auto b = controlledAgent();
	pump(a, b).should.equal(true);
	a.isConnected.should.equal(true);

	// The peer is gone: advance A's clock past the consent timeout with nothing
	// coming back.
	for (long now = 1000; now <= 40_000 && a.isConnected; now += 1000)
		a.handleTimeout(now);
	a.connectionState.should.equal(ConnectionState.failed);
}

// A restart with fresh credentials drops the selection and re-runs checking; the
// same pair is nominated again under the new credentials.
@("ice: an ICE restart reconnects under new credentials")
unittest
{
	auto a = controllingAgent();
	auto b = controlledAgent();
	pump(a, b).should.equal(true);

	auto a2 = Credentials("A2AAAAAA", "a2aaaaaaaaaaaaaaaaaaaa");
	auto b2 = Credentials("B2BBBBBB", "b2bbbbbbbbbbbbbbbbbbbb");
	a.restart(a2, b2);
	b.restart(b2, a2);
	a.isConnected.should.equal(false);
	a.connectionState.should.equal(ConnectionState.checking);

	pump(a, b).should.equal(true);
	TransportAddr al, ar;
	a.selectedPair(al, ar).should.equal(true);
	al.port.should.equal(aAddr.port);
	ar.port.should.equal(bAddr.port);
}
