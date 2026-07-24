/**
 * SCTP packet framing (RFC 4960 §3): a 12-byte common header plus a sequence of
 * self-describing chunks, protected by a CRC-32C over the whole packet.
 *
 * Laundered from webrtc-rs's rtc-sctp `packet.rs`. This layer handles only the
 * generic container — the common header, the CRC-32C checksum, and splitting/
 * joining chunks by their 4-byte chunk header (type, flags, length) with 4-byte
 * padding. Each chunk's typed payload (INIT params, DATA/TSN, SACK gaps, …) is
 * parsed by the per-chunk modules from `Chunk.value`.
 */
module webrtc.sctp.packet;

import std.exception : enforce;

import webrtc.sctp.crc32c : packetChecksum;

/// Size of the SCTP common header, in bytes.
enum size_t PACKET_HEADER_SIZE = 12;
/// Size of a chunk's header (type, flags, length), in bytes.
enum size_t CHUNK_HEADER_SIZE = 4;

// Chunk types (RFC 4960 §3.2 + the extensions the data channel path uses).
enum ubyte CT_PAYLOAD_DATA = 0;
enum ubyte CT_INIT = 1;
enum ubyte CT_INIT_ACK = 2;
enum ubyte CT_SACK = 3;
enum ubyte CT_HEARTBEAT = 4;
enum ubyte CT_HEARTBEAT_ACK = 5;
enum ubyte CT_ABORT = 6;
enum ubyte CT_SHUTDOWN = 7;
enum ubyte CT_SHUTDOWN_ACK = 8;
enum ubyte CT_ERROR = 9;
enum ubyte CT_COOKIE_ECHO = 10;
enum ubyte CT_COOKIE_ACK = 11;
enum ubyte CT_SHUTDOWN_COMPLETE = 14;
enum ubyte CT_RECONFIG = 130;
enum ubyte CT_FORWARD_TSN = 192;

/// Padding needed to round `len` up to a 4-byte boundary.
size_t paddingSize(size_t len) @safe pure nothrow @nogc
{
	return (4 - (len % 4)) % 4;
}

/// One SCTP chunk: a type, flag byte, and raw value (unpadded).
struct Chunk
{
	ubyte typ;
	ubyte flags;
	ubyte[] value;
}

/// A parsed SCTP packet: the common header fields plus its chunks.
struct Packet
{
	ushort sourcePort;
	ushort destinationPort;
	uint verificationTag;
	Chunk[] chunks;

	/// Serialize with a correct CRC-32C checksum.
	ubyte[] marshal() const @safe pure nothrow
	{
		ubyte[] buf;
		buf ~= [cast(ubyte)(sourcePort >> 8), cast(ubyte)(sourcePort & 0xff)];
		buf ~= [cast(ubyte)(destinationPort >> 8), cast(ubyte)(destinationPort & 0xff)];
		buf ~= be32(verificationTag);
		buf ~= [0, 0, 0, 0]; // checksum placeholder

		foreach (ref c; chunks)
		{
			immutable len = CHUNK_HEADER_SIZE + c.value.length;
			buf ~= [c.typ, c.flags, cast(ubyte)(len >> 8), cast(ubyte)(len & 0xff)];
			buf ~= c.value;
			foreach (_; 0 .. paddingSize(len))
				buf ~= 0;
		}

		immutable csum = packetChecksum(buf);
		buf[8 .. 12] = [cast(ubyte)(csum & 0xff), cast(ubyte)(csum >> 8),
			cast(ubyte)(csum >> 16), cast(ubyte)(csum >> 24)]; // little-endian
		return buf;
	}

	/// Parse a packet, verifying the checksum. Throws on a short/corrupt packet.
	static Packet unmarshal(scope const(ubyte)[] raw) @safe pure
	{
		enforce(raw.length >= PACKET_HEADER_SIZE, "sctp: packet too small");
		immutable theirs = (cast(uint) raw[8]) | (cast(uint) raw[9] << 8)
			| (cast(uint) raw[10] << 16) | (cast(uint) raw[11] << 24);
		enforce(theirs == packetChecksum(raw), "sctp: checksum mismatch");

		Packet p;
		p.sourcePort = cast(ushort)((raw[0] << 8) | raw[1]);
		p.destinationPort = cast(ushort)((raw[2] << 8) | raw[3]);
		p.verificationTag = (cast(uint) raw[4] << 24) | (cast(uint) raw[5] << 16)
			| (cast(uint) raw[6] << 8) | raw[7];

		size_t off = PACKET_HEADER_SIZE;
		while (off != raw.length)
		{
			enforce(off + CHUNK_HEADER_SIZE <= raw.length, "sctp: chunk header truncated");
			immutable typ = raw[off];
			immutable flags = raw[off + 1];
			immutable len = (raw[off + 2] << 8) | raw[off + 3];
			enforce(len >= CHUNK_HEADER_SIZE, "sctp: bad chunk length");
			enforce(off + len <= raw.length, "sctp: chunk truncated");
			auto value = raw[off + CHUNK_HEADER_SIZE .. off + len].dup;
			p.chunks ~= Chunk(typ, flags, value);
			off += len + paddingSize(len);
		}
		return p;
	}
}

private ubyte[] be32(uint v) @safe pure nothrow
{
	return [cast(ubyte)(v >> 24), cast(ubyte)(v >> 16), cast(ubyte)(v >> 8), cast(ubyte) v];
}
