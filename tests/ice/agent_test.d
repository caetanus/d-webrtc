module tests.ice.agent_test;

import webrtc.ice.agent;
import webrtc.ice.attributes : Role;
import webrtc.ice.candidate : Candidate, CandidateType;
import fluent.asserts : should;

private Candidate host(string ip, ushort port)
{
	Candidate c;
	c.typ = CandidateType.host;
	c.address = ip;
	c.port = port;
	return c;
}

// Shuttle STUN packets between two agents until both connect (or rounds run out).
// An OutboundStun leaves `src` (the sender's local candidate) for `dst` (the
// peer's local candidate), so the peer sees from=src, to=dst.
private void pump(Agent a, Agent b, int rounds = 16)
{
	foreach (_; 0 .. rounds)
	{
		bool moved;
		foreach (o; a.gatherOutbound(0))
		{
			b.handleInbound(o.data, o.src, o.dst, 0);
			moved = true;
		}
		foreach (o; b.gatherOutbound(0))
		{
			a.handleInbound(o.data, o.src, o.dst, 0);
			moved = true;
		}
		if (a.isConnected && b.isConnected)
			break;
		if (!moved)
			break;
	}
}

@("ICE agents complete a full connectivity check and nominate a pair")
unittest
{
	auto dialer = new Agent(Role.controlling, Credentials("uAAA", "pAAAAAAAAAAAAAAAAAAA"), 1);
	auto listener = new Agent(Role.controlled, Credentials("uBBB", "pBBBBBBBBBBBBBBBBBBB"), 2);

	auto da = host("1.1.1.1", 1000);
	auto la = host("2.2.2.2", 2000);
	dialer.addLocalCandidate(da);
	listener.addLocalCandidate(la);

	dialer.setRemoteCredentials(Credentials("uBBB", "pBBBBBBBBBBBBBBBBBBB"));
	listener.setRemoteCredentials(Credentials("uAAA", "pAAAAAAAAAAAAAAAAAAA"));
	dialer.addRemoteCandidate(la);
	listener.addRemoteCandidate(da);

	pump(dialer, listener);

	dialer.isConnected.should.equal(true);
	listener.isConnected.should.equal(true);

	auto dp = dialer.selectedPair();
	auto lp = listener.selectedPair();
	dp.isNull.should.equal(false);
	lp.isNull.should.equal(false);
	// Dialer's selected pair is (its local, the listener's addr) and vice-versa.
	dp.get[0].should.equal(TransportAddr("1.1.1.1", 1000));
	dp.get[1].should.equal(TransportAddr("2.2.2.2", 2000));
	lp.get[0].should.equal(TransportAddr("2.2.2.2", 2000));
	lp.get[1].should.equal(TransportAddr("1.1.1.1", 1000));
}

@("controlled agent learns a peer-reflexive remote from an inbound check")
unittest
{
	auto dialer = new Agent(Role.controlling, Credentials("uAAA", "pAAAAAAAAAAAAAAAAAAA"), 1);
	auto listener = new Agent(Role.controlled, Credentials("uBBB", "pBBBBBBBBBBBBBBBBBBB"), 2);

	auto da = host("1.1.1.1", 1000);
	auto la = host("2.2.2.2", 2000);
	dialer.addLocalCandidate(da);
	listener.addLocalCandidate(la);

	// The listener is given ONLY the credentials — no remote candidate. It must
	// discover the dialer as a peer-reflexive candidate from the first check.
	dialer.setRemoteCredentials(Credentials("uBBB", "pBBBBBBBBBBBBBBBBBBB"));
	listener.setRemoteCredentials(Credentials("uAAA", "pAAAAAAAAAAAAAAAAAAA"));
	dialer.addRemoteCandidate(la);

	pump(dialer, listener);

	dialer.isConnected.should.equal(true);
	listener.isConnected.should.equal(true);
	listener.selectedPair().get[1].should.equal(TransportAddr("1.1.1.1", 1000));
}

@("a check with a bad MESSAGE-INTEGRITY is rejected (no false connect)")
unittest
{
	auto dialer = new Agent(Role.controlling, Credentials("uAAA", "pAAAAAAAAAAAAAAAAAAA"), 1);
	auto listener = new Agent(Role.controlled, Credentials("uBBB", "pBBBBBBBBBBBBBBBBBBB"), 2);

	dialer.addLocalCandidate(host("1.1.1.1", 1000));
	listener.addLocalCandidate(host("2.2.2.2", 2000));

	// The dialer (controlling) expects the WRONG listener password: it can never
	// validate the listener's Binding successes, so no pair succeeds, nothing is
	// nominated, and neither side is ever selected.
	dialer.setRemoteCredentials(Credentials("uBBB", "WRONG-PASSWORD-XXXXX"));
	listener.setRemoteCredentials(Credentials("uAAA", "pAAAAAAAAAAAAAAAAAAA"));
	dialer.addRemoteCandidate(host("2.2.2.2", 2000));
	listener.addRemoteCandidate(host("1.1.1.1", 1000));

	pump(dialer, listener);

	dialer.isConnected.should.equal(false);
	listener.isConnected.should.equal(false);
}
