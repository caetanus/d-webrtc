/**
 * HMAC-SHA1 — via OpenSSL's libcrypto, since libsodium provides no SHA-1.
 *
 * Preference order for crypto primitives is libsodium → OpenSSL → hand-roll;
 * STUN MESSAGE-INTEGRITY (RFC 5389 §15.4) needs HMAC-SHA1, which libsodium
 * lacks. We declare the two libcrypto symbols directly as `extern(C)` rather
 * than importing `deimos.openssl.hmac`, because deimos-openssl 3.4.0's `ssl.di`
 * fails to compile (undefined `HMAC_CTX`) and we only need this one function.
 * Linked via `libs: [ssl, crypto]` in dub.json.
 */
module webrtc.util.hmac;

private extern (C) @nogc nothrow
{
	struct evp_md_st;
	const(evp_md_st)* EVP_sha1();
	ubyte* HMAC(const(evp_md_st)* evp_md, const(void)* key, int key_len,
		const(ubyte)* d, size_t n, ubyte* md, uint* md_len);
}

/// HMAC-SHA1 of `data` under `key` (20-byte output).
///
/// @trusted: passes bounded D slices to libcrypto's HMAC as (ptr, len) pairs;
/// it reads exactly the given lengths and writes exactly 20 bytes into the
/// stack array. No pointer escapes.
ubyte[20] hmacSha1(scope const(ubyte)[] key, scope const(ubyte)[] data) @trusted
{
	ubyte[20] out_;
	uint outlen;
	HMAC(EVP_sha1(), key.ptr, cast(int) key.length,
		data.ptr, data.length, out_.ptr, &outlen);
	return out_;
}
