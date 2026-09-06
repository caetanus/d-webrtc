/**
 * A DTLS 1.2 endpoint, sans-io. OpenSSL does the protocol; we own only the pump
 * between it and the socket the consumer holds. Received datagrams go in with
 * feedInbound, records to send come out with takeOutbound, and handshake() /
 * read() / write() / close() drive the state — none of them touch a socket or a
 * clock. Two OpenSSL memory BIOs stand in for the network: SSL reads what we
 * fed, and writes what we will send.
 *
 * The peer's certificate is self-signed, so certificate-chain verification is
 * deliberately accepted (the callback returns 1); trust comes instead from
 * pinning the peer's fingerprint — verifyPeerFingerprint — against the certhash
 * the multiaddr and Noise prologue carry. That comparison is the whole security
 * of webrtc-direct's DTLS, and law 5's "we own the comparison" in practice.
 */
module webrtc.dtls.transport;

import std.exception : enforce;

import deimos.openssl.bio;
import deimos.openssl.err : ERR_get_error, ERR_error_string_n;
import deimos.openssl.evp : EVP_sha256;
import deimos.openssl.ssl;
import deimos.openssl.x509;
import deimos.openssl.x509_vfy : X509_STORE_CTX;

import webrtc.dtls.certificate : Certificate;

// Missing from the deimos binding we use; DTLS_method negotiates DTLS ≥ 1.0 and
// we floor it at 1.2 below. (DTLSv1_handle_timeout is already provided by the
// binding as an SSL_ctrl helper.)
private extern (C) const(SSL_METHOD)* DTLS_method() @nogc nothrow;

private enum int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 0x02;
private enum long dtls12Version = 0xFEFD; // DTLS1_2_VERSION
private enum int dtlsCtrlSetLinkMtu = 120; // DTLS_CTRL_SET_LINK_MTU, absent from the binding

/// The DTLS role. In libp2p webrtc-direct the dialer is the client and the
/// listener the server; the caller decides from its perspective.
enum DtlsRole
{
	client,
	server,
}

final class DtlsTransport
{
	private SSL_CTX* ctx;
	private SSL* ssl;
	private BIO* rbio; /// we write received datagrams here; SSL reads from it
	private BIO* wbio; /// SSL writes here; we read datagrams to send from it
	private Certificate cert; /// kept alive for the life of the context
	private bool handshakeDone;
	private bool peerClosedFlag;

	this(DtlsRole role, Certificate cert) @trusted
	{
		this.cert = cert;
		enforce(cert !is null, "dtls: a certificate is required");

		ctx = SSL_CTX_new(DTLS_method());
		enforce(ctx !is null, "dtls: SSL_CTX_new failed");
		SSL_CTX_set_min_proto_version(ctx, cast(int) dtls12Version);
		enforce(SSL_CTX_use_certificate(ctx, cast(X509*) cert.x509) == 1,
			"dtls: use_certificate failed");
		enforce(SSL_CTX_use_PrivateKey(ctx, cast(EVP_PKEY*) cert.privateKey) == 1,
			"dtls: use_PrivateKey failed");

		// Self-signed on both ends: accept the chain, then pin the fingerprint.
		// The server must ask for the client's certificate to see it at all.
		int mode = SSL_VERIFY_PEER;
		if (role == DtlsRole.server)
			mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		SSL_CTX_set_verify(ctx, mode, &acceptAnyChain);

		ssl = SSL_new(ctx);
		enforce(ssl !is null, "dtls: SSL_new failed");
		rbio = BIO_new(BIO_s_mem());
		wbio = BIO_new(BIO_s_mem());
		enforce(rbio !is null && wbio !is null, "dtls: BIO_new failed");
		// An empty memory BIO returns EOF by default, which DTLS reads as a dead
		// connection; make an empty read signal "retry" (WANT_READ) instead.
		BIO_set_mem_eof_return(rbio, -1);
		SSL_set_bio(ssl, rbio, wbio); // SSL now owns both BIOs

		// A memory BIO has no MTU to query; tell DTLS not to try, and give it a
		// fixed link MTU so it fragments the handshake instead of failing.
		SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
		SSL_ctrl(ssl, dtlsCtrlSetLinkMtu, 1200, null);

		if (role == DtlsRole.client)
			SSL_set_connect_state(ssl);
		else
			SSL_set_accept_state(ssl);
	}

	~this() @trusted nothrow
	{
		if (ssl !is null)
			SSL_free(ssl); // frees rbio and wbio too
		if (ctx !is null)
			SSL_CTX_free(ctx);
	}

	// --- the pump ---------------------------------------------------------------------------

	/// Feed a received datagram into the DTLS engine.
	void feedInbound(scope const(ubyte)[] data) @trusted
	{
		if (data.length == 0)
			return;
		BIO_write(rbio, data.ptr, cast(int) data.length);
	}

	/// Take everything DTLS has queued to send. Each element is one datagram.
	ubyte[][] takeOutbound() @trusted
	{
		ubyte[][] out_;
		ubyte[4096] buf;
		while (true)
		{
			immutable n = BIO_read(wbio, buf.ptr, cast(int) buf.length);
			if (n <= 0)
				break;
			out_ ~= buf[0 .. n].dup;
		}
		return out_;
	}

	// --- driving ----------------------------------------------------------------------------

	/// Advance the handshake. Returns true once it has completed. Throws on a
	/// genuine handshake failure (as opposed to simply needing more input).
	bool handshake() @trusted
	{
		if (handshakeDone)
			return true;
		immutable r = SSL_do_handshake(ssl);
		if (r == 1)
		{
			handshakeDone = true;
			return true;
		}
		immutable e = SSL_get_error(ssl, r);
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
			return false;
		throw new Exception("dtls: handshake failed (SSL_get_error " ~ errName(e) ~ "): " ~ errQueue());
	}

	bool isHandshakeComplete() const @safe pure nothrow @nogc
	{
		return handshakeDone;
	}

	/// Retransmit the last handshake flight if it has gone unanswered. This is the
	/// one place the engine leans on OpenSSL's own clock rather than the caller's
	/// `now` — DTLS's retransmit timer lives inside OpenSSL — so the caller drives
	/// it from its periodic timeout and the records surface through takeOutbound.
	void handleTimeout() @trusted
	{
		if (!handshakeDone)
			DTLSv1_handle_timeout(ssl);
	}

	/// Whether the peer's close_notify has been observed.
	bool peerClosed() const @safe pure nothrow @nogc
	{
		return peerClosedFlag;
	}

	/// Write application data. Must be called after the handshake completes.
	void write(scope const(ubyte)[] data) @trusted
	{
		enforce(handshakeDone, "dtls: write before handshake completed");
		if (data.length == 0)
			return;
		immutable n = SSL_write(ssl, data.ptr, cast(int) data.length);
		if (n <= 0)
		{
			immutable e = SSL_get_error(ssl, n);
			if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
				return; // a mem BIO does not block; treat as nothing written
			throw new Exception("dtls: write failed (SSL_get_error " ~ errName(e) ~ ")");
		}
	}

	/// Read the next application record, or null if none is ready. A peer
	/// close_notify is recorded and reported through peerClosed().
	ubyte[] read() @trusted
	{
		ubyte[16384] buf;
		immutable n = SSL_read(ssl, buf.ptr, cast(int) buf.length);
		if (n > 0)
			return buf[0 .. n].dup;
		immutable e = SSL_get_error(ssl, n);
		if (e == SSL_ERROR_ZERO_RETURN)
			peerClosedFlag = true;
		return null;
	}

	/// Begin an orderly close: emit a close_notify. The caller drains it with
	/// takeOutbound and sends it.
	void close() @trusted
	{
		if (ssl !is null)
			SSL_shutdown(ssl);
	}

	// --- fingerprint pinning ----------------------------------------------------------------

	/// The SHA-256 fingerprint of the peer's certificate. Valid once the
	/// handshake has completed.
	ubyte[32] peerFingerprint() @trusted
	{
		enforce(handshakeDone, "dtls: peer fingerprint before handshake completed");
		auto peer = SSL_get1_peer_certificate(ssl);
		enforce(peer !is null, "dtls: peer presented no certificate");
		scope (exit)
			X509_free(peer);
		ubyte[32] fp;
		uint len;
		enforce(X509_digest(peer, EVP_sha256(), fp.ptr, &len) == 1, "dtls: peer digest failed");
		enforce(len == 32, "dtls: peer fingerprint was not SHA-256 sized");
		return fp;
	}

	/// Pin the peer to an expected fingerprint (the certhash from the multiaddr).
	bool verifyPeerFingerprint(ubyte[32] expected) @trusted
	{
		return peerFingerprint() == expected;
	}
}

// Self-signed certificates: skip chain verification here and pin the fingerprint
// instead.
private extern (C) int acceptAnyChain(int preverifyOk, X509_STORE_CTX* storeCtx) @nogc nothrow
{
	return 1;
}

private string errQueue() @trusted nothrow
{
	string s;
	try
		while (true)
		{
			immutable code = ERR_get_error();
			if (code == 0)
				break;
			char[256] buf;
			ERR_error_string_n(code, buf.ptr, buf.length);
			import core.stdc.string : strlen;

			s ~= (s.length ? "; " : "") ~ buf[0 .. strlen(buf.ptr)].idup;
		}
	catch (Exception)
	{
	}
	return s.length ? s : "no error queued";
}

private string errName(int e) @safe pure nothrow
{
	switch (e)
	{
	case SSL_ERROR_NONE:
		return "NONE";
	case SSL_ERROR_ZERO_RETURN:
		return "ZERO_RETURN";
	case SSL_ERROR_WANT_READ:
		return "WANT_READ";
	case SSL_ERROR_WANT_WRITE:
		return "WANT_WRITE";
	case SSL_ERROR_SSL:
		return "SSL";
	case SSL_ERROR_SYSCALL:
		return "SYSCALL";
	default:
		return "other";
	}
}
