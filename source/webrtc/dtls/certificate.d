/**
 * The DTLS identity: a self-signed ECDSA P-256 certificate generated at
 * startup, and its SHA-256 fingerprint. In libp2p webrtc-direct the fingerprint
 * is the certhash carried in the multiaddr and pinned inside the Noise prologue,
 * so getting it exactly right — the SHA-256 over the certificate's DER encoding
 * — is the whole point.
 *
 * The key and certificate are OpenSSL's; we own their lifetime and the
 * fingerprint. Law 5 of DESIGN.md: crypto is not ours, so nothing here
 * reimplements a digest or a curve — it drives libcrypto and copies the result
 * out. A failure from any libcrypto call throws.
 */
module webrtc.dtls.certificate;

import core.stdc.config : c_long;
import std.digest.sha : sha256Of;
import std.exception : enforce;

import deimos.openssl.asn1;
import deimos.openssl.ec : EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID;
import deimos.openssl.evp;
import deimos.openssl.obj_mac : NID_X9_62_prime256v1;
import deimos.openssl.x509;

import libsodium.randombytes : randombytes_buf;

// Not in the deimos binding we use; declared here against the linked libcrypto.
private extern (C) nothrow @nogc
{
	int X509_set_version(X509* x, c_long v);
	ASN1_INTEGER* X509_get_serialNumber(X509* x);
	X509_NAME* X509_get_subject_name(const(X509)* x);
}

private enum int MBSTRING_ASC = 0x1000 | 1;

final class Certificate
{
	private X509* cert;
	private EVP_PKEY* key;
	private ubyte[32] fp;

	this() @trusted
	{
		generate();
	}

	~this() @trusted nothrow
	{
		if (cert !is null)
			X509_free(cert);
		if (key !is null)
			EVP_PKEY_free(key);
	}

	/// The SHA-256 fingerprint of the certificate's DER encoding.
	ubyte[32] sha256Fingerprint() const @safe pure nothrow @nogc
	{
		return fp;
	}

	/// The certificate, for handing to a DTLS context.
	inout(X509)* x509() inout @safe pure nothrow @nogc
	{
		return cert;
	}

	/// The private key, for handing to a DTLS context.
	inout(EVP_PKEY)* privateKey() inout @safe pure nothrow @nogc
	{
		return key;
	}

	/// The DER encoding of the certificate (what the fingerprint is taken over).
	ubyte[] der() const @trusted
	{
		auto x = cast(X509*) cert;
		immutable len = i2d_X509(x, null);
		enforce(len > 0, "dtls: could not encode certificate");
		auto buf = new ubyte[len];
		auto p = buf.ptr;
		i2d_X509(x, &p);
		return buf;
	}

	private void generate() @trusted
	{
		auto pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null);
		enforce(pctx !is null, "dtls: EVP_PKEY_CTX_new_id failed");
		scope (exit)
			EVP_PKEY_CTX_free(pctx);

		enforce(EVP_PKEY_keygen_init(pctx) == 1, "dtls: keygen_init failed");
		// The binding's set_ec_paramgen_curve_nid hardcodes OP_PARAMGEN, which does not
		// match a keygen context; drive the ctrl with both ops set.
		enforce(EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_EC,
				EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
				EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, NID_X9_62_prime256v1, null) > 0,
			"dtls: could not select P-256");
		enforce(EVP_PKEY_keygen(pctx, &key) == 1, "dtls: key generation failed");

		cert = X509_new();
		enforce(cert !is null, "dtls: X509_new failed");
		enforce(X509_set_version(cert, 2) == 1, "dtls: set_version failed"); // v3

		// A random 63-bit serial, so two certificates never collide.
		ubyte[8] r;
		randombytes_buf(r.ptr, r.length);
		c_long serial = 0;
		foreach (b; r)
			serial = (serial << 8) | b;
		if (serial < 0)
			serial = -serial;
		ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

		// Valid from now, for a year — this is an ephemeral transport identity.
		X509_gmtime_adj(X509_getm_notBefore(cert), 0);
		X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24 * 365);

		enforce(X509_set_pubkey(cert, key) == 1, "dtls: set_pubkey failed");

		// Self-signed: subject equals issuer.
		auto name = X509_get_subject_name(cert);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
			cast(const(ubyte)*) "libp2p-webrtc".ptr, -1, -1, 0);
		enforce(X509_set_issuer_name(cert, name) == 1, "dtls: set_issuer failed");

		enforce(X509_sign(cert, key, EVP_sha256()) > 0, "dtls: self-signing failed");

		uint len;
		enforce(X509_digest(cert, EVP_sha256(), fp.ptr, &len) == 1, "dtls: digest failed");
		enforce(len == 32, "dtls: fingerprint was not SHA-256 sized");
	}
}

