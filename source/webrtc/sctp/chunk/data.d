/**
 * SCTP DATA chunk (RFC 4960 §3.3.1) — the chunk that carries user data, i.e.
 * every WebRTC data-channel message.
 *
 * Laundered from webrtc-rs's rtc-sctp `chunk_payload_data.rs`, keeping ONLY the
 * wire fields. The sender-side bookkeeping there (acked, nsent, since, retransmit,
 * inflight flags, …) is association state, not part of the chunk on the wire, so
 * it lives in the association layer, not here.
 *
 *  Type=0 | Reserved|I|U|B|E | Length
 *  TSN (32)
 *  Stream Identifier (16) | Stream Sequence Number (16)
 *  Payload Protocol Identifier (32)
 *  User Data ...
 */
module webrtc.sctp.chunk.data;

import std.exception : enforce;

import webrtc.sctp.packet : Chunk, CT_PAYLOAD_DATA;
import webrtc.sctp.wire : be16, be32, read16, read32;

// DATA chunk flag bits (in the chunk header's flags byte).
enum ubyte FLAG_ENDING = 1; // E
enum ubyte FLAG_BEGINNING = 2; // B
enum ubyte FLAG_UNORDERED = 4; // U
enum ubyte FLAG_IMMEDIATE_SACK = 8; // I

// Payload Protocol Identifiers used by WebRTC data channels (IANA).
enum uint PPID_DCEP = 50;
enum uint PPID_STRING = 51;
enum uint PPID_BINARY = 53;
enum uint PPID_STRING_EMPTY = 56;
enum uint PPID_BINARY_EMPTY = 57;

private enum size_t DATA_HEADER_SIZE = 12;

/// A DATA chunk's wire content.
struct DataChunk
{
	bool unordered;
	bool beginningFragment;
	bool endingFragment;
	bool immediateSack;

	uint tsn;
	ushort streamIdentifier;
	ushort streamSequenceNumber;
	uint payloadType; // Payload Protocol Identifier
	ubyte[] userData;

	/// The chunk-header flags byte encoding the U/B/E/I bits.
	ubyte flags() const @safe pure nothrow @nogc
	{
		ubyte f;
		if (endingFragment)
			f |= FLAG_ENDING;
		if (beginningFragment)
			f |= FLAG_BEGINNING;
		if (unordered)
			f |= FLAG_UNORDERED;
		if (immediateSack)
			f |= FLAG_IMMEDIATE_SACK;
		return f;
	}

	/// Build a generic chunk (type, flags, value) for the packet layer.
	Chunk toChunk() const @safe pure nothrow
	{
		ubyte[] v;
		v ~= be32(tsn);
		v ~= be16(streamIdentifier);
		v ~= be16(streamSequenceNumber);
		v ~= be32(payloadType);
		v ~= userData;
		return Chunk(CT_PAYLOAD_DATA, flags(), v);
	}

	/// Parse a DATA chunk from a generic chunk. Throws on a short value.
	static DataChunk fromChunk(const Chunk c) @safe pure
	{
		enforce(c.typ == CT_PAYLOAD_DATA, "sctp: not a DATA chunk");
		enforce(c.value.length >= DATA_HEADER_SIZE, "sctp: DATA chunk too short");
		DataChunk d;
		d.unordered = (c.flags & FLAG_UNORDERED) != 0;
		d.beginningFragment = (c.flags & FLAG_BEGINNING) != 0;
		d.endingFragment = (c.flags & FLAG_ENDING) != 0;
		d.immediateSack = (c.flags & FLAG_IMMEDIATE_SACK) != 0;
		d.tsn = read32(c.value, 0);
		d.streamIdentifier = read16(c.value, 4);
		d.streamSequenceNumber = read16(c.value, 6);
		d.payloadType = read32(c.value, 8);
		d.userData = c.value[DATA_HEADER_SIZE .. $].dup;
		return d;
	}
}
