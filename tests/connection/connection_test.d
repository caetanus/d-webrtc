module tests.connection.connection_test;

import webrtc.connection.connection;
import webrtc.dtls.certificate : Certificate;
import webrtc.ice.agent : Credentials, TransportAddr;
import webrtc.ice.candidate : Candidate;
import webrtc.datachannel.channels : ChannelEvent, ChannelEventKind;
import fluent.asserts : should;

private enum aAddr = TransportAddr("127.0.0.1", 4001);
private enum bAddr = TransportAddr("127.0.0.1", 4002);
private enum aCreds = Credentials("AAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaa");
private enum bCreds = Credentials("BBBBBBBB", "bbbbbbbbbbbbbbbbbbbbbb");

// Ferry datagrams both ways (tagging each with its sender's address), driving
// both connections, until a stop condition holds or the clock runs out.
private void pump(Connection dialer, Connection listener, long stop, ref ChannelEvent[] dEv,
	ref ChannelEvent[] lEv, bool delegate() done)
{
	long now = 0;
	foreach (_; 0 .. 600)
	{
		dialer.handleTimeout(now);
		listener.handleTimeout(now);
		foreach (o; dialer.gatherOutbound(now))
			listener.handleInbound(o.data, aAddr, now);
		foreach (o; listener.gatherOutbound(now))
			dialer.handleInbound(o.data, bAddr, now);
		dEv ~= dialer.poll();
		lEv ~= listener.poll();
		if (done())
			return;
		now += 20;
	}
}

private Connection[2] connectedPair()
{
	auto dialer = new Connection(Perspective.dialer, new Certificate, aAddr, aCreds, 0x2222_2222);
	auto listener = new Connection(Perspective.listener, new Certificate, bAddr, bCreds, 0x1111_1111);

	dialer.addLocalCandidate(Candidate.host(aAddr.ip, aAddr.port));
	dialer.addRemoteCandidate(Candidate.host(bAddr.ip, bAddr.port));
	dialer.setRemoteCredentials(bCreds);
	dialer.setExpectedFingerprint(listener.localFingerprint());

	listener.addLocalCandidate(Candidate.host(bAddr.ip, bAddr.port));
	listener.addRemoteCandidate(Candidate.host(aAddr.ip, aAddr.port));
	listener.setRemoteCredentials(aCreds);
	listener.setExpectedFingerprint(dialer.localFingerprint());

	ChannelEvent[] dEv, lEv;
	pump(dialer, listener, 0, dEv, lEv,
		() => dialer.state == ConnState.connected && listener.state == ConnState.connected);
	return [dialer, listener];
}

// The full stack comes up: ICE nominates, DTLS 1.2 completes with the peer
// fingerprint pinned, SCTP establishes, and both reach connected.
@("connection: the full webrtc-direct stack reaches connected")
unittest
{
	auto pair = connectedPair();
	pair[0].state.should.equal(ConnState.connected);
	pair[1].state.should.equal(ConnState.connected);
}

// A wrong expected fingerprint fails the connection at the DTLS pin, not later.
@("connection: a mismatched certificate fingerprint fails the connection")
unittest
{
	auto dialer = new Connection(Perspective.dialer, new Certificate, aAddr, aCreds, 0x2222_2222);
	auto listener = new Connection(Perspective.listener, new Certificate, bAddr, bCreds, 0x1111_1111);

	dialer.addLocalCandidate(Candidate.host(aAddr.ip, aAddr.port));
	dialer.addRemoteCandidate(Candidate.host(bAddr.ip, bAddr.port));
	dialer.setRemoteCredentials(bCreds);
	ubyte[32] wrong;
	wrong[0] = 0xDE; // not the listener's fingerprint
	dialer.setExpectedFingerprint(wrong);

	listener.addLocalCandidate(Candidate.host(bAddr.ip, bAddr.port));
	listener.addRemoteCandidate(Candidate.host(aAddr.ip, aAddr.port));
	listener.setRemoteCredentials(aCreds);
	listener.setExpectedFingerprint(dialer.localFingerprint());

	ChannelEvent[] dEv, lEv;
	pump(dialer, listener, 0, dEv, lEv, () => dialer.state == ConnState.failed);
	dialer.state.should.equal(ConnState.failed);
}

// Application data flows over the negotiated channel once connected.
@("connection: data flows over the negotiated channel")
unittest
{
	auto pair = connectedPair();
	auto dialer = pair[0], listener = pair[1];
	dialer.state.should.equal(ConnState.connected);

	dialer.channels().send(0, cast(ubyte[]) "over webrtc".dup, false);
	ChannelEvent[] dEv, lEv;
	pump(dialer, listener, 0, dEv, lEv, () {
		foreach (e; lEv)
			if (e.kind == ChannelEventKind.message && e.channel == 0)
				return true;
		return false;
	});

	bool got;
	foreach (e; lEv)
		if (e.kind == ChannelEventKind.message && e.channel == 0
			&& cast(string) e.data == "over webrtc")
			got = true;
	got.should.equal(true);
}

// A graceful close brings the dialer to closed via the sequenced SCTP shutdown
// then DTLS close_notify.
@("connection: close shuts the connection down in order")
unittest
{
	auto pair = connectedPair();
	auto dialer = pair[0], listener = pair[1];
	dialer.state.should.equal(ConnState.connected);

	dialer.close(0);
	ChannelEvent[] dEv, lEv;
	pump(dialer, listener, 0, dEv, lEv, () => dialer.state == ConnState.closed);
	dialer.state.should.equal(ConnState.closed);
}

private Connection[2] makePair(bool dialerPins = true)
{
	auto dialer = new Connection(Perspective.dialer, new Certificate, aAddr, aCreds, 0x2222_2222);
	auto listener = new Connection(Perspective.listener, new Certificate, bAddr, bCreds, 0x1111_1111);
	dialer.addLocalCandidate(Candidate.host(aAddr.ip, aAddr.port));
	dialer.addRemoteCandidate(Candidate.host(bAddr.ip, bAddr.port));
	dialer.setRemoteCredentials(bCreds);
	if (dialerPins)
		dialer.setExpectedFingerprint(listener.localFingerprint());
	listener.addLocalCandidate(Candidate.host(bAddr.ip, bAddr.port));
	listener.addRemoteCandidate(Candidate.host(aAddr.ip, aAddr.port));
	listener.setRemoteCredentials(aCreds);
	listener.setExpectedFingerprint(dialer.localFingerprint());
	return [dialer, listener];
}

// Closing before the connection is up must reach closed, not hang in closing —
// the exact off-happy-path ending v3 exists to get right.
@("connection: close before connected reaches closed")
unittest
{
	auto dialer = new Connection(Perspective.dialer, new Certificate, aAddr, aCreds, 0x2222_2222);
	dialer.addLocalCandidate(Candidate.host(aAddr.ip, aAddr.port));
	dialer.addRemoteCandidate(Candidate.host(bAddr.ip, bAddr.port));
	dialer.setRemoteCredentials(bCreds);
	dialer.setExpectedFingerprint(dialer.localFingerprint()); // any value; never reached

	dialer.close(0); // during ICE, no peer answering
	dialer.state.should.equal(ConnState.closed);
}

// A dialer that pins no fingerprint is refused at the DTLS pin (fail closed):
// webrtc-direct's certhash is mandatory.
@("connection: a connection with no expected fingerprint fails closed")
unittest
{
	auto pair = makePair(false); // dialer does NOT set an expected fingerprint
	auto dialer = pair[0], listener = pair[1];
	ChannelEvent[] dEv, lEv;
	pump(dialer, listener, 0, dEv, lEv, () => dialer.state == ConnState.failed);
	dialer.state.should.equal(ConnState.failed);
}

// The negotiated channel surfaces an opened event, so a poller sees id 0 come up.
@("connection: the negotiated channel emits an opened event")
unittest
{
	auto pair = makePair();
	auto dialer = pair[0], listener = pair[1];
	ChannelEvent[] dEv, lEv;
	pump(dialer, listener, 0, dEv, lEv,
		() => dialer.state == ConnState.connected && listener.state == ConnState.connected);

	bool opened0;
	foreach (e; dEv)
		if (e.kind == ChannelEventKind.opened && e.channel == 0)
			opened0 = true;
	opened0.should.equal(true);
}
