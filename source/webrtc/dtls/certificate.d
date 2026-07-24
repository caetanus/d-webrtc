/**
 * DTLS certificates for WebRTC. Each endpoint presents a self-signed X.509
 * certificate; the SHA-256 of its DER is the "certhash" carried in the SDP
 * fingerprint line (a=fingerprint) and, for libp2p webrtc-direct, in the
 * `/certhash` multiaddr component. WebRTC uses ECDSA P-256 certificates.
 *
 * This is NOT laundered from webrtc-rs's rtc-dtls (which reimplements the DTLS
 * stack): per the project rule "if it's in Deimos, don't bother", we let OpenSSL
 * (via deimos.openssl) generate the key, build the cert, and do the DTLS
 * handshake. deimos-openssl 3.4.0 binds everything we need here.
 */
module webrtc.dtls.certificate;

import std.exception : enforce;

import deimos.openssl.ssl;
import deimos.openssl.x509;
import deimos.openssl.evp;
import deimos.openssl.ec;
import deimos.openssl.asn1;
import deimos.openssl.obj_mac : NID_X9_62_prime256v1;

/// A self-signed DTLS identity: an ECDSA P-256 key and its X.509 certificate.
/// Owns the OpenSSL objects and frees them when destroyed.
final class Certificate
{
	private EVP_PKEY* key_;
	private X509* cert_;

	private this(EVP_PKEY* key, X509* cert) @safe @nogc nothrow
	{
		key_ = key;
		cert_ = cert;
	}

	~this() @trusted
	{
		if (cert_ !is null)
			X509_free(cert_);
		if (key_ !is null)
			EVP_PKEY_free(key_);
	}

	/// The raw OpenSSL handles, for installing on an SSL_CTX.
	EVP_PKEY* key() @safe @nogc nothrow
	{
		return key_;
	}

	X509* cert() @safe @nogc nothrow
	{
		return cert_;
	}

	/// The certificate fingerprint: the SHA-256 of its DER encoding. This is the
	/// value the peer pins via the SDP a=fingerprint line / the libp2p certhash.
	ubyte[32] fingerprint() @trusted
	{
		ubyte[32] md;
		uint n;
		enforce(X509_digest(cert_, EVP_sha256(), md.ptr, &n) == 1 && n == 32,
			"dtls: X509_digest failed");
		return md;
	}

	/// Generate a fresh self-signed ECDSA P-256 certificate.
	static Certificate generate() @trusted
	{
		auto key = generateP256Key();
		X509* cert;
		try
			cert = buildSelfSigned(key);
		catch (Exception e)
		{
			EVP_PKEY_free(key);
			throw e;
		}
		return new Certificate(key, cert);
	}
}

private EVP_PKEY* generateP256Key() @trusted
{
	// The classic EC_KEY path: deimos-openssl 3.4.0's
	// EVP_PKEY_CTX_set_ec_paramgen_curve_nid macro hardcodes the PARAMGEN op and
	// so fails after keygen_init, so we generate the EC key directly and wrap it.
	auto ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	enforce(ec !is null, "dtls: EC_KEY_new_by_curve_name failed");
	if (EC_KEY_generate_key(ec) != 1)
	{
		EC_KEY_free(ec);
		throw new Exception("dtls: EC_KEY_generate_key failed");
	}

	auto key = EVP_PKEY_new();
	if (key is null)
	{
		EC_KEY_free(ec);
		throw new Exception("dtls: EVP_PKEY_new failed");
	}
	// On success EVP_PKEY takes ownership of `ec`; on failure we free it.
	if (EVP_PKEY_assign_EC_KEY(key, ec) != 1)
	{
		EC_KEY_free(ec);
		EVP_PKEY_free(key);
		throw new Exception("dtls: EVP_PKEY_assign_EC_KEY failed");
	}
	return key;
}

private X509* buildSelfSigned(EVP_PKEY* key) @trusted
{
	auto cert = X509_new();
	enforce(cert !is null, "dtls: X509_new failed");
	scope (failure)
		X509_free(cert);

	X509_set_version(cert, 2); // v3
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_getm_notBefore(cert), 0);
	X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24 * 365); // 1 year
	X509_set_pubkey(cert, key);

	auto name = X509_get_subject_name(cert);
	X509_NAME_add_entry_by_txt(name, "CN", 0x1000 | 1 /* MBSTRING_ASC */,
		cast(const(ubyte)*) "webrtc".ptr, 6, -1, 0);
	X509_set_issuer_name(cert, name); // self-signed

	// ECDSA certificates are sealed with an ECDSA-with-SHA256 signature.
	enforce(X509_sign(cert, key, EVP_sha256()) != 0, "dtls: X509_sign failed");
	return cert;
}
