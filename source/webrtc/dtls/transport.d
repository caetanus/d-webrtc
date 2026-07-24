/**
 * DTLS transport — a sans-io wrapper around OpenSSL's DTLS 1.2 over a pair of
 * memory BIOs. This is the encryption layer that sits on the ICE-selected UDP
 * path and carries the SCTP association (WebRTC = SCTP-over-DTLS-over-ICE).
 *
 * Per the "Deimos is ours" rule we do NOT reimplement DTLS (webrtc-rs's rtc-dtls
 * is ~16k LoC); OpenSSL does the handshake and record layer. We only adapt it to
 * a sans-io surface fit for a vibe driver: `feed` inbound datagrams into the
 * read BIO, `handshake`/`send`/`receive` drive the SSL object, and
 * `gatherOutbound` drains the write BIO into datagrams to put on the wire. No
 * sockets here — the driver owns those.
 *
 * WebRTC authenticates by pinning the peer certificate's SHA-256 (the SDP
 * a=fingerprint / libp2p certhash), so ordinary chain verification is bypassed
 * (accept-any callback) and the caller compares `peerFingerprint` itself.
 */
module webrtc.dtls.transport;

import std.exception : enforce;

import deimos.openssl.ssl;
import deimos.openssl.bio;
import deimos.openssl.x509;
import deimos.openssl.evp;
import deimos.openssl.x509_vfy : X509_STORE_CTX;

import webrtc.dtls.certificate : Certificate;

// deimos-openssl 3.4.0 only binds DTLSv1_method (DTLS 1.0); WebRTC needs the
// version-flexible DTLS_method (negotiates DTLS 1.2). Declare it directly, the
// same way the SCTP layer declares the HMAC symbols the binding is missing.
private extern (C) const(SSL_METHOD)* DTLS_method();

// The link MTU pinned on the DTLS session (a conservative value that fits a
// 1500-byte Ethernet path with room for IP/UDP headers). OpenSSL fragments
// handshake records to this, and gatherOutbound packs records into datagrams
// no larger than it.
private enum int DTLS_MTU = 1200;

/// Which side of the DTLS handshake this endpoint plays.
enum DtlsRole
{
	client,
	server,
}

// Split a write-BIO blob (a run of DTLS records) into datagrams of at most
// DTLS_MTU bytes, appending each to `outs`. A DTLS record header is 13 bytes
// with the fragment length as a big-endian u16 at offset 11. Unparseable tail
// bytes are emitted as-is (best effort — should not happen with a mem BIO).
private void packRecords(scope const(ubyte)[] blob, ref ubyte[][] outs) @safe pure nothrow
{
	size_t i;
	ubyte[] cur;
	while (i + 13 <= blob.length)
	{
		immutable recLen = 13 + ((blob[i + 11] << 8) | blob[i + 12]);
		if (i + recLen > blob.length)
			break; // truncated record — bail to the tail handler below
		if (cur.length && cur.length + recLen > DTLS_MTU)
		{
			outs ~= cur;
			cur = [];
		}
		cur ~= blob[i .. i + recLen];
		i += recLen;
	}
	if (cur.length)
		outs ~= cur;
	if (i < blob.length)
		outs ~= blob[i .. $].dup; // leftover we could not frame
}

/// A single DTLS connection, driven sans-io over memory BIOs.
final class DtlsTransport
{
	private SSL_CTX* ctx;
	private SSL* ssl;
	private BIO* rbio; // inbound ciphertext we feed in
	private BIO* wbio; // outbound ciphertext we drain out
	private Certificate cert; // kept alive for the CTX's lifetime
	private bool established_;

	this(DtlsRole role, Certificate certificate) @trusted
	{
		cert = certificate;
		ctx = SSL_CTX_new(DTLS_method());
		enforce(ctx !is null, "dtls: SSL_CTX_new failed");
		scope (failure)
			cleanup();

		enforce(SSL_CTX_use_certificate(ctx, cert.cert()) == 1, "dtls: use_certificate failed");
		enforce(SSL_CTX_use_PrivateKey(ctx, cert.key()) == 1, "dtls: use_PrivateKey failed");

		// Both peers present a certificate; we authenticate by fingerprint, so
		// accept any chain and let the caller compare peerFingerprint().
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, &acceptAnyCert);

		// A memory BIO cannot report a path MTU, so pin one: OpenSSL then fragments
		// the DTLS handshake into records that fit a real UDP datagram instead of
		// emitting oversized flights that a real network would drop.
		SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);

		ssl = SSL_new(ctx);
		enforce(ssl !is null, "dtls: SSL_new failed");

		rbio = BIO_new(BIO_s_mem());
		wbio = BIO_new(BIO_s_mem());
		enforce(rbio !is null && wbio !is null, "dtls: BIO_new failed");
		SSL_set_bio(ssl, rbio, wbio); // SSL takes ownership of both BIOs

		if (role == DtlsRole.client)
			SSL_set_connect_state(ssl);
		else
			SSL_set_accept_state(ssl);

		// SSL_set_mtu(ssl, DTLS_MTU) equivalent — the deimos SSL_set_mtu template
		// references an undefined SSL_CTRL_MTU, so call SSL_ctrl directly.
		SSL_ctrl(ssl, SSL_CTRL_SET_MTU, DTLS_MTU, null);
	}

	~this() @trusted
	{
		cleanup();
	}

	/// Whether the handshake has completed.
	bool isConnected() const @safe @nogc nothrow
	{
		return established_;
	}

	/// Feed an inbound DTLS datagram (ciphertext received from the peer).
	void feed(scope const(ubyte)[] datagram) @trusted
	{
		if (datagram.length == 0)
			return;
		BIO_write(rbio, datagram.ptr, cast(int) datagram.length);
	}

	/// Retransmit the last handshake flight if OpenSSL's DTLS timer has expired.
	/// A no-op once connected or when no timeout is pending; the freshly queued
	/// ciphertext is drained by the next `gatherOutbound`. (OpenSSL uses its own
	/// wall clock here, not the caller's `now`.)
	void handleTimeout() @trusted
	{
		if (!established_)
			DTLSv1_handle_timeout(ssl);
	}

	/// Advance the handshake. Safe to call repeatedly; it becomes a no-op once
	/// connected. Throws on a real (non-want-read/write) error.
	void handshake() @trusted
	{
		if (established_)
			return;
		immutable r = SSL_do_handshake(ssl);
		if (r == 1)
		{
			established_ = true;
			return;
		}
		immutable err = SSL_get_error(ssl, r);
		enforce(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE,
			"dtls: handshake failed (SSL error)");
	}

	/// Send application data (an SCTP packet) over the established connection.
	void send(scope const(ubyte)[] data) @trusted
	{
		enforce(established_, "dtls: send before handshake completed");
		if (data.length == 0)
			return;
		SSL_write(ssl, data.ptr, cast(int) data.length);
	}

	/// Read the next decrypted application message, or an empty slice if none is
	/// available. (One SSL_read per call — DTLS preserves datagram boundaries.)
	ubyte[] receive() @trusted
	{
		if (!established_)
			return null;
		ubyte[4096] buf;
		immutable n = SSL_read(ssl, buf.ptr, cast(int) buf.length);
		if (n <= 0)
			return null;
		return buf[0 .. n].dup;
	}

	/// Drain the ciphertext the connection wants to send, as UDP-datagram-sized
	/// chunks. OpenSSL accumulates one or more DTLS records in the write BIO; we
	/// split them at record boundaries and pack them into datagrams no larger
	/// than the link MTU, so a handshake flight never becomes one oversized
	/// datagram (which a real network would drop or fragment).
	ubyte[][] gatherOutbound() @trusted
	{
		ubyte[][] outs;
		while (true)
		{
			immutable pending = BIO_ctrl_pending(wbio);
			if (pending == 0)
				break;
			auto buf = new ubyte[pending];
			immutable n = BIO_read(wbio, buf.ptr, cast(int) buf.length);
			if (n <= 0)
				break;
			packRecords(buf[0 .. n], outs);
		}
		return outs;
	}

	/// The peer certificate's SHA-256 fingerprint (to compare against the pinned
	/// certhash). Null if the peer presented no certificate yet.
	ubyte[32] peerFingerprint() @trusted
	{
		auto pc = SSL_get1_peer_certificate(ssl);
		enforce(pc !is null, "dtls: peer presented no certificate");
		scope (exit)
			X509_free(pc);
		ubyte[32] md;
		uint len;
		enforce(X509_digest(pc, EVP_sha256(), md.ptr, &len) == 1 && len == 32,
			"dtls: peer X509_digest failed");
		return md;
	}

	private void cleanup() @trusted nothrow
	{
		if (ssl !is null)
		{
			SSL_free(ssl); // also frees rbio/wbio it owns
			ssl = null;
		}
		if (ctx !is null)
		{
			SSL_CTX_free(ctx);
			ctx = null;
		}
	}
}

/// OpenSSL verify callback that accepts any certificate — WebRTC authenticates
/// out of band by pinning the certificate fingerprint, not via a CA chain.
private extern (C) int acceptAnyCert(int preverifyOk, X509_STORE_CTX* storeCtx) @nogc nothrow
{
	cast(void) preverifyOk;
	cast(void) storeCtx;
	return 1;
}
