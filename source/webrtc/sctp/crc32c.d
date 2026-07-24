/**
 * CRC-32C (Castagnoli) — the checksum SCTP puts in its common header
 * (RFC 4960 §6.8, RFC 3309). Not a cryptographic hash and absent from libsodium
 * and OpenSSL's easy surface, so we hand-roll the standard table-driven variant
 * (reflected polynomial 0x82F63B78, init/xorout 0xFFFFFFFF).
 *
 * Laundered from webrtc-rs's rtc-sctp (it uses the `crc32c` crate / hardware
 * CRC32C instruction; the checksum is bit-identical).
 */
module webrtc.sctp.crc32c;

// Lookup table built at compile time (CTFE).
private immutable uint[256] TABLE = () {
	uint[256] t;
	foreach (i; 0 .. 256)
	{
		uint crc = cast(uint) i;
		foreach (_; 0 .. 8)
			crc = (crc & 1) ? (crc >> 1) ^ 0x82F6_3B78 : crc >> 1;
		t[i] = crc;
	}
	return t;
}();

/// Fold `data` into a running CRC-32C register (no init/final XOR).
uint crc32cUpdate(uint crc, scope const(ubyte)[] data) @safe pure nothrow @nogc
{
	foreach (b; data)
		crc = TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8);
	return crc;
}

/// CRC-32C of `data`.
uint crc32c(scope const(ubyte)[] data) @safe pure nothrow @nogc
{
	return crc32cUpdate(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF;
}

/// The SCTP packet checksum: CRC-32C over the packet with the 4-byte checksum
/// field (offset 8..12) treated as zero (RFC 4960 §6.8). Returned as the u32
/// value; it is written into the header little-endian.
uint packetChecksum(scope const(ubyte)[] raw) @safe pure nothrow @nogc
{
	static immutable ubyte[4] zeroes = [0, 0, 0, 0];
	uint crc = 0xFFFF_FFFF;
	crc = crc32cUpdate(crc, raw[0 .. 8]);
	crc = crc32cUpdate(crc, zeroes[]);
	crc = crc32cUpdate(crc, raw[12 .. $]);
	return crc ^ 0xFFFF_FFFF;
}
