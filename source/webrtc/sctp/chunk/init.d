/**
 * SCTP INIT / INIT ACK chunk (RFC 4960 §3.3.2 / §3.3.3) — the first step of the
 * SCTP four-way handshake that brings up the WebRTC data-channel association.
 *
 * Laundered from webrtc-rs's rtc-sctp `chunk_init.rs`. INIT and INIT ACK share
 * the same body (a fixed 16-byte header plus TLV parameters), distinguished by
 * the chunk type; `isAck` selects which.
 */
module webrtc.sctp.chunk.init;

import std.exception : enforce;

import webrtc.sctp.packet : Chunk, CT_INIT, CT_INIT_ACK;
import webrtc.sctp.wire : be16, be32, read16, read32;
import webrtc.sctp.param : Param, parseParams, serializeParams;

private enum size_t INIT_FIXED_SIZE = 16;

/// An INIT or INIT ACK chunk body.
struct InitChunk
{
	bool isAck;
	uint initiateTag;
	uint advertisedReceiverWindowCredit;
	ushort numOutboundStreams;
	ushort numInboundStreams;
	uint initialTsn;
	Param[] params;

	/// Build a generic chunk for the packet layer. The INIT flags byte is
	/// reserved and MUST be zero (RFC 4960 §3.3.2).
	Chunk toChunk() const @safe pure nothrow
	{
		ubyte[] v;
		v ~= be32(initiateTag);
		v ~= be32(advertisedReceiverWindowCredit);
		v ~= be16(numOutboundStreams);
		v ~= be16(numInboundStreams);
		v ~= be32(initialTsn);
		v ~= serializeParams(params);
		return Chunk(isAck ? CT_INIT_ACK : CT_INIT, 0, v);
	}

	/// Parse an INIT / INIT ACK chunk. Throws on wrong type or short body.
	static InitChunk fromChunk(const Chunk c) @safe pure
	{
		enforce(c.typ == CT_INIT || c.typ == CT_INIT_ACK, "sctp: not an INIT chunk");
		enforce(c.value.length >= INIT_FIXED_SIZE, "sctp: INIT chunk too short");
		InitChunk i;
		i.isAck = c.typ == CT_INIT_ACK;
		i.initiateTag = read32(c.value, 0);
		i.advertisedReceiverWindowCredit = read32(c.value, 4);
		i.numOutboundStreams = read16(c.value, 8);
		i.numInboundStreams = read16(c.value, 10);
		i.initialTsn = read32(c.value, 12);
		i.params = parseParams(c.value[INIT_FIXED_SIZE .. $]);
		return i;
	}
}
