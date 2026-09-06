/**
 * SCTP packets on the wire (RFC 4960 §3): the 12-byte common header, the chunk
 * framing every chunk shares, and the CRC32c (RFC 3309) that guards the whole
 * datagram. Typed knowledge of each chunk's body lives with the association
 * that acts on it; this layer is the envelope — parse a datagram into chunks,
 * serialise chunks into a datagram, and get the checksum exactly right.
 *
 * The checksum is the one SCTP quirk worth naming: CRC32c is computed over the
 * packet with the checksum field zeroed, and the result is stored little-endian
 * even though everything else on the wire is big-endian. A packet whose checksum
 * does not verify is thrown out before any chunk is looked at.
 *
 * Bounded before allocated (law 3): every chunk length is checked against the
 * bytes present before a copy, and a length that runs past the datagram throws.
 */
module webrtc.sctp.packet;

import std.exception : enforce;

enum size_t commonHeaderLen = 12;
enum size_t chunkHeaderLen = 4;
/// A datagram larger than this we will not hold (a generous DTLS-record bound).
enum size_t maxPacketLen = 65_536;

/// The chunk types this engine names (RFC 4960 §3.2, plus RFC 6525 and 3758).
enum ChunkType : ubyte
{
	data = 0,
	init = 1,
	initAck = 2,
	sack = 3,
	heartbeat = 4,
	heartbeatAck = 5,
	abort = 6,
	shutdown = 7,
	shutdownAck = 8,
	error = 9,
	cookieEcho = 10,
	cookieAck = 11,
	shutdownComplete = 14,
	reConfig = 130, // RFC 6525
	forwardTsn = 192, // RFC 3758
}

/// One chunk: its type byte, its flags byte, and its body (the value after the
/// 4-byte chunk header, without the padding that aligns the next chunk).
struct Chunk
{
	ubyte typ;
	ubyte flags;
	ubyte[] value;
}

/// An SCTP packet: the ports and verification tag from the common header, and
/// the chunks it carries. The checksum is not stored — it is computed on encode
/// and verified on decode.
struct Packet
{
	ushort srcPort;
	ushort dstPort;
	uint verificationTag;
	Chunk[] chunks;

	static Packet decode(scope const(ubyte)[] data) @safe pure
	{
		enforce(data.length >= commonHeaderLen, "sctp: short common header");
		enforce(data.length <= maxPacketLen, "sctp: packet too large");

		immutable stored = readLe32(data[8 .. 12]); // SCTP stores CRC32c little-endian
		enforce(verifyChecksum(data, stored), "sctp: bad CRC32c");

		Packet p;
		p.srcPort = readBe16(data[0 .. 2]);
		p.dstPort = readBe16(data[2 .. 4]);
		p.verificationTag = readBe32(data[4 .. 8]);

		size_t pos = commonHeaderLen;
		while (pos < data.length)
		{
			enforce(pos + chunkHeaderLen <= data.length, "sctp: truncated chunk header");
			immutable typ = data[pos];
			immutable flags = data[pos + 1];
			immutable len = readBe16(data[pos + 2 .. pos + 4]);
			enforce(len >= chunkHeaderLen, "sctp: chunk length below its header");
			enforce(pos + len <= data.length, "sctp: chunk runs past the packet");
			p.chunks ~= Chunk(typ, flags, data[pos + chunkHeaderLen .. pos + len].dup);
			pos += len;
			// Chunks are padded to a 4-byte boundary; the padding is not counted
			// in the chunk length and may be absent on the last chunk.
			while (pos % 4 != 0 && pos < data.length)
				pos++;
		}
		return p;
	}

	ubyte[] encode() const @safe pure
	{
		ubyte[] out_ = new ubyte[commonHeaderLen];
		writeBe16(out_[0 .. 2], srcPort);
		writeBe16(out_[2 .. 4], dstPort);
		writeBe32(out_[4 .. 8], verificationTag);
		// out_[8 .. 12] is the checksum, left zero until the end.

		foreach (ref c; chunks)
		{
			immutable len = chunkHeaderLen + c.value.length;
			enforce(len <= ushort.max, "sctp: chunk too large to encode");
			ubyte[4] hdr;
			hdr[0] = c.typ;
			hdr[1] = c.flags;
			writeBe16(hdr[2 .. 4], cast(ushort) len);
			out_ ~= hdr[];
			out_ ~= c.value;
			// Pad every chunk to a 4-byte boundary. The padding is not counted in
			// the chunk length; a receiver skips it. RFC 4960 §3.2 permits padding
			// the last chunk too, which is what peers on the wire (scapy, usrsctp)
			// do, so we match them rather than special-casing the tail.
			while (out_.length % 4 != 0)
				out_ ~= 0;
		}

		immutable crc = crc32c(out_);
		writeLe32(out_[8 .. 12], crc);
		return out_;
	}
}

// A checksum verifies if CRC32c over the packet with the field zeroed equals the
// stored value. Folded over the three segments — before the field, four zero
// bytes, after the field — so no copy of the datagram is made.
private bool verifyChecksum(scope const(ubyte)[] data, uint stored) @safe pure nothrow
{
	static immutable ubyte[4] zeros = [0, 0, 0, 0];
	uint crc = crcInit;
	crc = crcUpdate(crc, data[0 .. 8]);
	crc = crcUpdate(crc, zeros[]);
	crc = crcUpdate(crc, data[12 .. $]);
	return (crc ^ crcInit) == stored;
}

// --- CRC32c (RFC 3309): reflected Castagnoli, init/xorout 0xFFFFFFFF ---------------

private immutable uint[256] crcTable = makeCrcTable();

private uint[256] makeCrcTable() @safe pure nothrow
{
	uint[256] t;
	foreach (n; 0 .. 256)
	{
		uint c = n;
		foreach (_; 0 .. 8)
			c = (c & 1) ? (0x82F63B78 ^ (c >> 1)) : (c >> 1);
		t[n] = c;
	}
	return t;
}

private enum uint crcInit = 0xFFFF_FFFF;

// Fold `data` into a running CRC32c register (reflected Castagnoli). Not
// finalised — the caller xors with crcInit when done.
private uint crcUpdate(uint crc, scope const(ubyte)[] data) @safe pure nothrow @nogc
{
	foreach (b; data)
		crc = crcTable[(crc ^ b) & 0xFF] ^ (crc >> 8);
	return crc;
}

/// CRC32c over `data`, reflected in and out with the standard 0xFFFFFFFF init
/// and final xor. CRC32c("123456789") == 0xE3069283.
uint crc32c(scope const(ubyte)[] data) @safe pure nothrow
{
	return crcUpdate(crcInit, data) ^ crcInit;
}

// --- big/little-endian helpers -----------------------------------------------------

private ushort readBe16(scope const(ubyte)[] b) @safe pure nothrow @nogc
{
	return cast(ushort)((b[0] << 8) | b[1]);
}

private uint readBe32(scope const(ubyte)[] b) @safe pure nothrow @nogc
{
	return (cast(uint) b[0] << 24) | (cast(uint) b[1] << 16) | (cast(uint) b[2] << 8) | b[3];
}

private void writeBe16(ubyte[] b, ushort v) @safe pure nothrow @nogc
{
	b[0] = cast(ubyte)(v >> 8);
	b[1] = cast(ubyte)(v & 0xff);
}

private void writeBe32(ubyte[] b, uint v) @safe pure nothrow @nogc
{
	b[0] = cast(ubyte)(v >> 24);
	b[1] = cast(ubyte)(v >> 16);
	b[2] = cast(ubyte)(v >> 8);
	b[3] = cast(ubyte)(v & 0xff);
}

private uint readLe32(scope const(ubyte)[] b) @safe pure nothrow @nogc
{
	return cast(uint) b[0] | (cast(uint) b[1] << 8) | (cast(uint) b[2] << 16) | (cast(uint) b[3] << 24);
}

private void writeLe32(ubyte[] b, uint v) @safe pure nothrow @nogc
{
	b[0] = cast(ubyte)(v & 0xff);
	b[1] = cast(ubyte)(v >> 8);
	b[2] = cast(ubyte)(v >> 16);
	b[3] = cast(ubyte)(v >> 24);
}
