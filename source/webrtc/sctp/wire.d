/**
 * Big-endian read/write helpers shared by the SCTP chunk and parameter codecs.
 * SCTP is a network-byte-order protocol (RFC 4960); these keep the per-chunk
 * modules free of repetitive shift/mask arithmetic.
 */
module webrtc.sctp.wire;

import std.exception : enforce;

ubyte[] be16(ushort v) @safe pure nothrow
{
	return [cast(ubyte)(v >> 8), cast(ubyte)(v & 0xff)];
}

ubyte[] be32(uint v) @safe pure nothrow
{
	return [cast(ubyte)(v >> 24), cast(ubyte)(v >> 16), cast(ubyte)(v >> 8), cast(ubyte) v];
}

ushort read16(scope const(ubyte)[] b, size_t off) @safe pure
{
	enforce(off + 2 <= b.length, "sctp: read16 out of bounds");
	return cast(ushort)((b[off] << 8) | b[off + 1]);
}

uint read32(scope const(ubyte)[] b, size_t off) @safe pure
{
	enforce(off + 4 <= b.length, "sctp: read32 out of bounds");
	return (cast(uint) b[off] << 24) | (cast(uint) b[off + 1] << 16)
		| (cast(uint) b[off + 2] << 8) | b[off + 3];
}
