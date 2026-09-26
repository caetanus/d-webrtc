module tests.dtls.transport_test;

import webrtc.dtls.certificate : Certificate;
import webrtc.dtls.transport;
import fluent.asserts : should;

// The vector here is a real DTLS 1.2 handshake between two independent
// endpoints — OpenSSL on each side, nothing mocked — driven only through the
// sans-io surface, with an in-memory pump moving datagrams. That the two agree
// on keys and on each other's fingerprint is the check.

// Ferry datagrams both ways, driving each side, until both handshakes complete
// or the rounds run out.
private void driveHandshake(DtlsTransport client, DtlsTransport server)
{
	foreach (_; 0 .. 200)
	{
		immutable cd = client.handshake();
		immutable sd = server.handshake();
		foreach (dg; client.takeOutbound())
			server.feedInbound(dg);
		foreach (dg; server.takeOutbound())
			client.feedInbound(dg);
		if (cd && sd)
			return;
	}
}

@("dtls: two endpoints complete a handshake and pin each other's fingerprint")
unittest
{
	auto cCert = new Certificate;
	auto sCert = new Certificate;
	auto client = new DtlsTransport(DtlsRole.client, cCert);
	auto server = new DtlsTransport(DtlsRole.server, sCert);

	driveHandshake(client, server);
	client.isHandshakeComplete().should.equal(true);
	server.isHandshakeComplete().should.equal(true);

	// Each side sees exactly the other's certificate fingerprint.
	auto seenByClient = client.peerFingerprint();
	auto serverFp = sCert.sha256Fingerprint();
	seenByClient[].should.equal(serverFp[]);

	auto seenByServer = server.peerFingerprint();
	auto clientFp = cCert.sha256Fingerprint();
	seenByServer[].should.equal(clientFp[]);

	// Pinning: the real fingerprint verifies, a wrong one does not.
	client.verifyPeerFingerprint(serverFp).should.equal(true);
	auto wrong = serverFp;
	wrong[0] ^= 0xff;
	client.verifyPeerFingerprint(wrong).should.equal(false);
}

@("dtls: application data flows both ways once connected")
unittest
{
	auto client = new DtlsTransport(DtlsRole.client, new Certificate);
	auto server = new DtlsTransport(DtlsRole.server, new Certificate);
	driveHandshake(client, server);

	client.write(cast(ubyte[]) "ping".dup);
	foreach (dg; client.takeOutbound())
		server.feedInbound(dg);
	(cast(string) server.read()).should.equal("ping");

	server.write(cast(ubyte[]) "pong".dup);
	foreach (dg; server.takeOutbound())
		client.feedInbound(dg);
	(cast(string) client.read()).should.equal("pong");
}

@("dtls: a peer close_notify is observed")
unittest
{
	auto client = new DtlsTransport(DtlsRole.client, new Certificate);
	auto server = new DtlsTransport(DtlsRole.server, new Certificate);
	driveHandshake(client, server);

	client.close();
	foreach (dg; client.takeOutbound())
		server.feedInbound(dg);

	server.read(); // consumes the close_notify
	server.peerClosed().should.equal(true);
}

// Every record goes out as a datagram of its own, whole. A stream memory BIO ran
// records together and takeOutbound's fixed-size reads cut one across two
// datagrams: the peer dropped both halves, a loss every few packets of a burst.
@("dtls: a burst of records leaves as one whole datagram each")
unittest
{
	auto client = new DtlsTransport(DtlsRole.client, new Certificate);
	auto server = new DtlsTransport(DtlsRole.server, new Certificate);
	driveHandshake(client, server);
	client.isHandshakeComplete().should.equal(true);

	enum n = 10;
	foreach (i; 0 .. n)
	{
		auto rec = new ubyte[1100];
		rec[] = cast(ubyte) i;
		client.write(rec);
	}
	auto dgs = client.takeOutbound();
	dgs.length.should.equal(n); // one datagram per record, none split or merged

	// Fed one datagram at a time — as a socket delivers them — each reads back whole.
	foreach (i, dg; dgs)
	{
		server.feedInbound(dg);
		auto got = server.read();
		got.length.should.equal(1100);
		got[0].should.equal(cast(ubyte) i);
	}
}
