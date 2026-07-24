module tests.dtls.certificate_test;

import webrtc.dtls.certificate;
import fluent.asserts : should;

@("generates a self-signed cert with a 32-byte SHA-256 fingerprint")
unittest
{
	auto c = Certificate.generate();
	c.cert().should.not.beNull;
	c.key().should.not.beNull;

	auto fp = c.fingerprint();
	fp.length.should.equal(cast(size_t) 32);

	// The fingerprint is stable across calls on the same cert.
	c.fingerprint().should.equal(fp);
}

@("distinct certificates have distinct fingerprints")
unittest
{
	auto a = Certificate.generate();
	auto b = Certificate.generate();
	(a.fingerprint() == b.fingerprint()).should.equal(false);
}
