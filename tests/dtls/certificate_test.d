module tests.dtls.certificate_test;

import std.digest.sha : sha256Of;

import webrtc.dtls.certificate;
import fluent.asserts : should;

// The fingerprint must be the SHA-256 of the certificate's DER — that is what a
// libp2p peer computes and pins. We check OpenSSL's own X509_digest against an
// independent SHA-256 over the DER bytes, so the two agreeing is a real cross
// check, not a self-round-trip.
@("dtls: the fingerprint is SHA-256 over the certificate DER")
unittest
{
	auto c = new Certificate;
	auto fp = c.sha256Fingerprint();
	fp.length.should.equal(32);
	fp[].should.equal(sha256Of(c.der)[]);
}

// Two certificates are independently generated, so their keys — and therefore
// their DER and fingerprints — differ.
@("dtls: independent certificates have different fingerprints")
unittest
{
	auto a = new Certificate;
	auto b = new Certificate;
	(a.sha256Fingerprint() == b.sha256Fingerprint()).should.equal(false);
}

// The fingerprint is stable across reads of the same certificate.
@("dtls: a certificate's fingerprint is stable")
unittest
{
	auto c = new Certificate;
	c.sha256Fingerprint().should.equal(c.sha256Fingerprint());
	// And still equals the DER digest on a second encode.
	auto fp2 = c.sha256Fingerprint();
	fp2[].should.equal(sha256Of(c.der)[]);
}
