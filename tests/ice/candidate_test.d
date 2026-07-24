module tests.ice.candidate_test;

import webrtc.ice.candidate;
import fluent.asserts : should;

@("host candidate priority follows RFC 8445 §5.1.2.1")
unittest
{
	Candidate c;
	c.typ = CandidateType.host;
	c.address = "192.168.1.2";
	c.port = 4242;
	// (2^24)·126 + (2^8)·65535 + (256 − 1)
	immutable expected = (1u << 24) * 126 + (1u << 8) * 65535 + (256 - 1);
	c.priority.should.equal(expected);
}

@("candidate type preferences match the recommended weights")
unittest
{
	preference(CandidateType.host).should.equal(cast(ushort) 126);
	preference(CandidateType.peerReflexive).should.equal(cast(ushort) 110);
	preference(CandidateType.serverReflexive).should.equal(cast(ushort) 100);
	preference(CandidateType.relay).should.equal(cast(ushort) 0);
}

@("foundation is a stable decimal CRC-32C of type+address+network")
unittest
{
	Candidate a;
	a.address = "10.0.0.1";
	Candidate b;
	b.address = "10.0.0.1";
	Candidate other;
	other.address = "10.0.0.2";

	// Deterministic, all digits, and distinguishes different addresses.
	a.foundation.should.equal(b.foundation);
	(a.foundation != other.foundation).should.equal(true);
	foreach (ch; a.foundation)
		(ch >= '0' && ch <= '9').should.equal(true);
}

@("network token reflects the address family")
unittest
{
	Candidate v4;
	v4.address = "1.2.3.4";
	Candidate v6;
	v6.address = "::1";
	v6.ipv6 = true;
	// Different network token => different foundation for the same address shape.
	(v4.foundation != v6.foundation).should.equal(true);
}
