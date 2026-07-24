module tests.connection_test;

import webrtc.connection;
import webrtc.ice.agent : Credentials, TransportAddr;
import webrtc.ice.candidate : Candidate, CandidateType;
import webrtc.dtls.certificate : Certificate;
import webrtc.datachannel.channel : DataChannelConfig, ChannelState;
import fluent.asserts : should;

private Candidate host(string ip, ushort port)
{
	Candidate c;
	c.typ = CandidateType.host;
	c.address = ip;
	c.port = port;
	return c;
}

// Shuttle UDP datagrams between the two peers. A datagram leaves `src` for `dst`,
// so the peer sees from=src, to=dst. Runs until `done` or the round budget.
private void pump(PeerConnection a, PeerConnection b, bool delegate() done, int rounds = 80)
{
	foreach (_; 0 .. rounds)
	{
		bool moved;
		foreach (d; a.gatherOutbound(0))
		{
			b.handleDatagram(d.data, d.src, d.dst, 0);
			moved = true;
		}
		foreach (d; b.gatherOutbound(0))
		{
			a.handleDatagram(d.data, d.src, d.dst, 0);
			moved = true;
		}
		if (done())
			break;
		if (!moved)
			break;
	}
}

private void connect(out PeerConnection dialer, out PeerConnection listener)
{
	auto dCreds = Credentials("uDialer0", "pDialerXXXXXXXXXXXXX");
	auto lCreds = Credentials("uListen0", "pListenXXXXXXXXXXXXX");

	dialer = new PeerConnection(Perspective.dialer, dCreds, 1, Certificate.generate());
	listener = new PeerConnection(Perspective.listener, lCreds, 2, Certificate.generate());

	auto da = host("1.1.1.1", 1000);
	auto la = host("2.2.2.2", 2000);
	dialer.addLocalCandidate(da);
	listener.addLocalCandidate(la);

	dialer.setRemoteIce(lCreds, la);
	listener.setRemoteIce(dCreds, da);

	pump(dialer, listener, () => dialer.isReady && listener.isReady);
}

@("full stack: ICE + DTLS + SCTP all come up end to end")
unittest
{
	PeerConnection dialer, listener;
	connect(dialer, listener);

	dialer.iceConnected.should.equal(true);
	listener.iceConnected.should.equal(true);
	dialer.dtlsConnected.should.equal(true);
	listener.dtlsConnected.should.equal(true);
	dialer.isReady.should.equal(true); // SCTP association established
	listener.isReady.should.equal(true);
}

@("full stack: DTLS certificate fingerprints are pinnable end to end")
unittest
{
	PeerConnection dialer, listener;
	connect(dialer, listener);

	// Each side observes a 32-byte peer fingerprint (the certhash to verify
	// against the multiaddr). They are non-zero and mutually distinct.
	auto df = dialer.peerFingerprint();
	auto lf = listener.peerFingerprint();
	df.length.should.equal(cast(size_t) 32);
	(df == lf).should.equal(false);
}

@("full stack: a data channel carries messages both ways over the whole stack")
unittest
{
	PeerConnection dialer, listener;
	connect(dialer, listener);
	dialer.isReady.should.equal(true);

	// Dialer opens a channel; drive DCEP to completion.
	immutable sid = dialer.channels.open(DataChannelConfig("chat", "proto"));
	pump(dialer, listener, () => dialer.channels.channelState(sid) == ChannelState.open);

	// Exchange application messages across the full ICE+DTLS+SCTP+DCEP stack.
	dialer.channels.send(sid, cast(ubyte[]) "hello over webrtc".dup, true);
	listener.channels.send(sid, cast(ubyte[]) "hi back".dup, true);
	pump(dialer, listener, () => false, 20);

	auto atListener = listener.channels.receive();
	auto atDialer = dialer.channels.receive();
	atListener.isNull.should.equal(false);
	atDialer.isNull.should.equal(false);
	(cast(string) atListener.get.data).should.equal("hello over webrtc");
	(cast(string) atDialer.get.data).should.equal("hi back");
}
