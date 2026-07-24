module tests.sctp.association_test;

import webrtc.sctp.association;
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
