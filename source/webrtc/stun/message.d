/**
 * STUN message structure (RFC 5389 §6) — the lean subset webrtc-direct's ICE
 * connectivity checks need.
 *
 * Laundered from webrtc-rs's sans-io `rtc-stun` (`src/message.rs`,
 * `src/attributes.rs`), keeping the WIRE format faithful (verified against the
 * RFC 5769 test vectors) while dropping the pion-style zero-alloc buffering and
 * the TURN/long-term-credential machinery we don't use. A STUN message here is a
 * plain struct that encodes/decodes directly, the same idiom as our protobuf and
 * multiaddr codecs.
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |0 0|     STUN Message Type     |         Message Length        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Magic Cookie                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                     Transaction ID (96 bits)                  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
module webrtc.stun.message;

import std.exception : enforce;

/// Fixed value distinguishing STUN packets when multiplexed (RFC 5389 §6).
enum uint MAGIC_COOKIE = 0x2112_A442;
/// The 20-byte STUN message header.
enum size_t MESSAGE_HEADER_SIZE = 20;
/// Length of the transaction id, in bytes (96 bits).
enum size_t TRANSACTION_ID_SIZE = 12;

/// A STUN transaction id.
alias TransactionId = ubyte[TRANSACTION_ID_SIZE];

// STUN message types (class + method, RFC 5389 §6). Only Binding is needed.
enum ushort BINDING_REQUEST = 0x0001;
enum ushort BINDING_SUCCESS_RESPONSE = 0x0101;
enum ushort BINDING_ERROR_RESPONSE = 0x0111;

// The attribute types we use on the webrtc-direct / ICE path. TURN, legacy
// MAPPED-ADDRESS, REALM/NONCE (long-term credentials), etc. are deliberately
// omitted (RFC 5389 §18.2, RFC 8445 §7.1).
enum ushort ATTR_USERNAME = 0x0006;
enum ushort ATTR_MESSAGE_INTEGRITY = 0x0008;
enum ushort ATTR_ERROR_CODE = 0x0009;
enum ushort ATTR_XOR_MAPPED_ADDRESS = 0x0020;
enum ushort ATTR_PRIORITY = 0x0024;
enum ushort ATTR_USE_CANDIDATE = 0x0025;
enum ushort ATTR_FINGERPRINT = 0x8028;
enum ushort ATTR_ICE_CONTROLLED = 0x8029;
enum ushort ATTR_ICE_CONTROLLING = 0x802A;

/// FINGERPRINT is the CRC-32 XOR'ed with this fixed value (RFC 5389 §15.5).
enum uint FINGERPRINT_XOR_VALUE = 0x5354_554e;
private enum size_t FP_TLV = 8; // FINGERPRINT attribute total size: 4 header + 4 value

// CRC-32/ISO-HDLC (a.k.a. the zlib/gzip CRC-32) as a big-endian-ready u32.
// std.digest.crc.crc32Of returns the checksum little-endian.
private uint crc32Value(scope const(ubyte)[] data) @safe
{
	import std.digest.crc : crc32Of;

	auto d = crc32Of(data);
	return d[0] | (cast(uint) d[1] << 8) | (cast(uint) d[2] << 16) | (cast(uint) d[3] << 24);
}

/// One STUN attribute: a type and its raw value (unpadded).
struct Attribute
{
	ushort typ;
	ubyte[] value;
}

/// A decoded STUN message.
struct Message
{
	ushort typ;
	TransactionId transactionId;
	Attribute[] attributes;

	/// First attribute of `t`, or null if absent.
	const(ubyte)[] get(ushort t) const @safe pure nothrow
	{
		foreach (ref a; attributes)
			if (a.typ == t)
				return a.value;
		return null;
	}

	bool contains(ushort t) const @safe pure nothrow
	{
		foreach (ref a; attributes)
			if (a.typ == t)
				return true;
		return false;
	}

	/// The padded attribute region (no header).
	private ubyte[] encodeBody() const @safe pure
	{
		ubyte[] body_;
		foreach (ref a; attributes)
		{
			body_ ~= [cast(ubyte)(a.typ >> 8), cast(ubyte)(a.typ & 0xff)];
			body_ ~= [cast(ubyte)(a.value.length >> 8), cast(ubyte)(a.value.length & 0xff)];
			body_ ~= a.value;
			while (body_.length % 4 != 0)
				body_ ~= 0; // pad to 4-byte boundary
		}
		return body_;
	}

	/// The 20-byte header for a message whose padded body is `bodyLen` bytes.
	private ubyte[] header(size_t bodyLen) const @safe pure
	{
		ubyte[] buf;
		buf ~= [cast(ubyte)(typ >> 8), cast(ubyte)(typ & 0xff)];
		buf ~= [cast(ubyte)(bodyLen >> 8), cast(ubyte)(bodyLen & 0xff)];
		buf ~= [cast(ubyte)(MAGIC_COOKIE >> 24), cast(ubyte)(MAGIC_COOKIE >> 16),
			cast(ubyte)(MAGIC_COOKIE >> 8), cast(ubyte)(MAGIC_COOKIE & 0xff)];
		buf ~= transactionId[];
		return buf;
	}

	/// Serialize to the STUN wire format. Each attribute is padded to a 4-byte
	/// boundary; the header length counts the padded attribute region.
	ubyte[] encode() const @safe pure
	{
		auto body_ = encodeBody();
		return header(body_.length) ~ body_;
	}

	/// Append a FINGERPRINT attribute (RFC 5389 §15.5): CRC-32/ISO-HDLC of the
	/// message up to (but excluding) FINGERPRINT — computed with the header
	/// length already counting the FINGERPRINT TLV — XOR'ed with 0x5354554e.
	void addFingerprint() @safe
	{
		auto body_ = encodeBody();
		auto prefix = header(body_.length + FP_TLV) ~ body_;
		immutable v = crc32Value(prefix) ^ FINGERPRINT_XOR_VALUE;
		attributes ~= Attribute(ATTR_FINGERPRINT,
			[cast(ubyte)(v >> 24), cast(ubyte)(v >> 16), cast(ubyte)(v >> 8), cast(ubyte) v]);
	}

	/// Verify a trailing FINGERPRINT attribute. Returns false if it is absent,
	/// the wrong size, or the checksum mismatches.
	bool checkFingerprint() const @safe
	{
		if (attributes.length == 0)
			return false;
		auto last = attributes[$ - 1];
		if (last.typ != ATTR_FINGERPRINT || last.value.length != 4)
			return false;
		immutable got = (cast(uint) last.value[0] << 24) | (cast(uint) last.value[1] << 16)
			| (cast(uint) last.value[2] << 8) | last.value[3];
		// Rebuild the message without the FINGERPRINT attribute and recompute.
		Message m;
		m.typ = typ;
		m.transactionId = transactionId;
		foreach (ref a; attributes[0 .. $ - 1])
			m.attributes ~= Attribute(a.typ, a.value.dup);
		auto body_ = m.encodeBody();
		auto prefix = m.header(body_.length + FP_TLV) ~ body_;
		return got == (crc32Value(prefix) ^ FINGERPRINT_XOR_VALUE);
	}

	/// Parse a STUN message. Throws on a malformed header or truncated attribute.
	static Message decode(scope const(ubyte)[] data) @safe pure
	{
		enforce(data.length >= MESSAGE_HEADER_SIZE, "stun: short message");
		immutable cookie = (cast(uint) data[4] << 24) | (cast(uint) data[5] << 16)
			| (cast(uint) data[6] << 8) | data[7];
		enforce(cookie == MAGIC_COOKIE, "stun: bad magic cookie");

		Message m;
		m.typ = cast(ushort)((data[0] << 8) | data[1]);
		immutable len = (data[2] << 8) | data[3];
		m.transactionId = data[8 .. 20][0 .. TRANSACTION_ID_SIZE];

		enforce(MESSAGE_HEADER_SIZE + len <= data.length, "stun: truncated body");
		auto body_ = data[MESSAGE_HEADER_SIZE .. MESSAGE_HEADER_SIZE + len];
		size_t i;
		while (i + 4 <= body_.length)
		{
			immutable at = cast(ushort)((body_[i] << 8) | body_[i + 1]);
			immutable al = (body_[i + 2] << 8) | body_[i + 3];
			i += 4;
			enforce(i + al <= body_.length, "stun: truncated attribute");
			m.attributes ~= Attribute(at, body_[i .. i + al].dup);
			i += al;
			while (i % 4 != 0) // skip padding
				i++;
		}
		return m;
	}
}

/// Whether `b` looks like a STUN message (for demultiplexing). Does not
/// guarantee successful decoding (RFC 5389 §7.4 / §11).
bool isStunMessage(scope const(ubyte)[] b) @safe pure nothrow @nogc
{
	if (b.length < MESSAGE_HEADER_SIZE)
		return false;
	immutable cookie = (cast(uint) b[4] << 24) | (cast(uint) b[5] << 16)
		| (cast(uint) b[6] << 8) | b[7];
	return cookie == MAGIC_COOKIE;
}
