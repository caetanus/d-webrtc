/**
 * SCTP SACK chunk (RFC 4960 §3.3.4) — Selective Acknowledgement: the receiver
 * tells the sender the cumulative TSN it has, plus gap-ack blocks and duplicate
 * TSNs. Drives retransmission and flow control for the data channel.
 *
 * Laundered from webrtc-rs's rtc-sctp `chunk_selective_ack.rs`.
 */
module webrtc.sctp.chunk.sack;

import std.exception : enforce;

import webrtc.sctp.packet : Chunk, CT_SACK;
import webrtc.sctp.wire : be16, be32, read16, read32;

private enum size_t SACK_FIXED_SIZE = 12;

/// A gap-ack block: a run of received TSNs, as offsets from the cumulative ack.
struct GapAckBlock
{
	ushort start;
	ushort end;
}

/// A SACK chunk body.
struct SackChunk
{
	uint cumulativeTsnAck;
	uint advertisedReceiverWindowCredit;
	GapAckBlock[] gapAckBlocks;
	uint[] duplicateTsn;

	/// Build a generic chunk for the packet layer.
	Chunk toChunk() const @safe pure nothrow
	{
		ubyte[] v;
		v ~= be32(cumulativeTsnAck);
		v ~= be32(advertisedReceiverWindowCredit);
		v ~= be16(cast(ushort) gapAckBlocks.length);
		v ~= be16(cast(ushort) duplicateTsn.length);
		foreach (ref g; gapAckBlocks)
		{
			v ~= be16(g.start);
			v ~= be16(g.end);
		}
		foreach (t; duplicateTsn)
			v ~= be32(t);
		return Chunk(CT_SACK, 0, v);
	}

	/// Parse a SACK chunk. Throws on wrong type or a body too short for its
	/// declared block/duplicate counts.
	static SackChunk fromChunk(const Chunk c) @safe pure
	{
		enforce(c.typ == CT_SACK, "sctp: not a SACK chunk");
		enforce(c.value.length >= SACK_FIXED_SIZE, "sctp: SACK chunk too short");
		SackChunk s;
		s.cumulativeTsnAck = read32(c.value, 0);
		s.advertisedReceiverWindowCredit = read32(c.value, 4);
		immutable nGap = read16(c.value, 8);
		immutable nDup = read16(c.value, 10);
		enforce(c.value.length >= SACK_FIXED_SIZE + 4 * nGap + 4 * nDup,
			"sctp: SACK chunk truncated");

		size_t off = SACK_FIXED_SIZE;
		foreach (_; 0 .. nGap)
		{
			s.gapAckBlocks ~= GapAckBlock(read16(c.value, off), read16(c.value, off + 2));
			off += 4;
		}
		foreach (_; 0 .. nDup)
		{
			s.duplicateTsn ~= read32(c.value, off);
			off += 4;
		}
		return s;
	}
}
