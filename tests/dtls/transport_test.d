module tests.dtls.transport_test;

import webrtc.dtls.certificate : Certificate;
import webrtc.dtls.transport;
import fluent.asserts : should;

// Shuttle DTLS datagrams between the two endpoints until both complete the
// handshake (or the round budget is spent).
private void pump(DtlsTransport a, DtlsTransport b, int rounds = 40)
{
	foreach (_; 0 .. rounds)
	{
		a.handshake();
		b.handshake();
		bool moved;
		foreach (d; a.gatherOutbound())
		{
			b.feed(d);
			moved = true;
		}
		foreach (d; b.gatherOutbound())
		{
			a.feed(d);
			moved = true;
		}
		if (a.isConnected && b.isConnected)
			break;
		if (!moved)
			break;
	}
}

@("two DTLS endpoints complete a handshake over memory BIOs")
unittest
{
	auto client = new DtlsTransport(DtlsRole.client, Certificate.generate());
	auto server = new DtlsTransport(DtlsRole.server, Certificate.generate());

	pump(client, server);

	client.isConnected.should.equal(true);
	server.isConnected.should.equal(true);
}

@("each side sees the other's certificate fingerprint")
unittest
{
	auto clientCert = Certificate.generate();
	auto serverCert = Certificate.generate();
	auto client = new DtlsTransport(DtlsRole.client, clientCert);
	auto server = new DtlsTransport(DtlsRole.server, serverCert);

	pump(client, server);
	client.isConnected.should.equal(true);

	// The peer fingerprint each side observes matches the other's own cert —
	// this is exactly the certhash pinning check WebRTC/libp2p performs.
	client.peerFingerprint().should.equal(serverCert.fingerprint());
	server.peerFingerprint().should.equal(clientCert.fingerprint());
}

@("application data flows both ways once connected")
unittest
{
	auto client = new DtlsTransport(DtlsRole.client, Certificate.generate());
	auto server = new DtlsTransport(DtlsRole.server, Certificate.generate());
	pump(client, server);
	client.isConnected.should.equal(true);
	server.isConnected.should.equal(true);

	client.send(cast(ubyte[]) "ping over dtls".dup);
	server.send(cast(ubyte[]) "pong over dtls".dup);
	// Deliver the ciphertext both ways.
	foreach (d; client.gatherOutbound())
		server.feed(d);
	foreach (d; server.gatherOutbound())
		client.feed(d);

	(cast(string) server.receive()).should.equal("ping over dtls");
	(cast(string) client.receive()).should.equal("pong over dtls");
}
