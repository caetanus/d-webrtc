/**
 * SCTP variable-length parameters (RFC 4960 §3.2.1) — the Type-Length-Value
 * blocks carried by INIT / INIT ACK (and others). A generic Param plus list
 * parse/serialize; the specific parameter meanings the data-channel path cares
 * about (state cookie, supported extensions, forward-TSN) are named constants.
 *
 * Laundered from webrtc-rs's rtc-sctp `param/*`.
 */
module webrtc.sctp.param;

import std.exception : enforce;

import webrtc.sctp.packet : paddingSize;
import webrtc.sctp.wire : be16, read16;

// Parameter types the data-channel path uses (RFC 4960 / RFC 3758 / RFC 5061).
enum ushort PARAM_STATE_COOKIE = 7;
enum ushort PARAM_SUPPORTED_EXTENSIONS = 0x8008;
enum ushort PARAM_FORWARD_TSN_SUPPORTED = 49_152; // 0xC000

private enum size_t PARAM_HEADER_LENGTH = 4;

/// One TLV parameter: a type and its raw value (unpadded).
struct Param
{
	ushort typ;
	ubyte[] value;
}

/// Parse a padded TLV parameter list from `data`.
Param[] parseParams(scope const(ubyte)[] data) @safe pure
{
	Param[] params;
	size_t off;
	while (off + PARAM_HEADER_LENGTH <= data.length)
	{
		immutable typ = read16(data, off);
		immutable len = read16(data, off + 2);
		enforce(len >= PARAM_HEADER_LENGTH, "sctp: bad parameter length");
		enforce(off + len <= data.length, "sctp: parameter truncated");
		params ~= Param(typ, data[off + PARAM_HEADER_LENGTH .. off + len].dup);
		off += len + paddingSize(len);
	}
	return params;
}

/// Serialize a TLV parameter list with 4-byte padding between entries.
ubyte[] serializeParams(const Param[] params) @safe pure nothrow
{
	ubyte[] buf;
	foreach (ref p; params)
	{
		immutable len = PARAM_HEADER_LENGTH + p.value.length;
		buf ~= be16(p.typ);
		buf ~= be16(cast(ushort) len);
		buf ~= p.value;
		foreach (_; 0 .. paddingSize(len))
			buf ~= 0;
	}
	return buf;
}
