/**
 * STUN (RFC 5389 / RFC 8489): the message, the attributes ICE needs,
 * MESSAGE-INTEGRITY (HMAC-SHA1), FINGERPRINT (CRC-32 xor), XOR-MAPPED-ADDRESS,
 * ERROR-CODE.
 *
 * Written from the RFC. Pinned to RFC 5769's four sample messages byte for
 * byte: each decodes, its MESSAGE-INTEGRITY verifies against the sample's own
 * precomputed HMAC with the RFC's password, its FINGERPRINT verifies, and the
 * address it carries reads back. Integrity and fingerprint are computed over
 * the bytes as received — a sender pads with what it likes and its HMAC covers
 * that — so a decoded message remembers its raw bytes and only re-encodes when
 * a caller built or altered it.
 *
 * Every length on the wire is checked against the bytes present before a copy.
 * A malformed message throws; nothing here returns a status to inspect.
 */
module webrtc.stun.message;

import std.digest.crc : CRC32;
import std.digest.hmac : HMAC;
import std.digest.sha : SHA1;
import std.exception : enforce;

import libsodium.randombytes : randombytes_buf;

alias TransactionId = ubyte[12];

enum uint magicCookie = 0x2112A442;
private enum size_t headerLen = 20;
/// A message larger than this we will not hold.
enum size_t maxMessageLen = 4096;

enum ushort bindingRequest = 0x0001;
enum ushort bindingIndication = 0x0011;
enum ushort bindingSuccess = 0x0101;
enum ushort bindingError = 0x0111;

enum ushort attrMappedAddress = 0x0001;
enum ushort attrUsername = 0x0006;
enum ushort attrMessageIntegrity = 0x0008;
enum ushort attrErrorCode = 0x0009;
enum ushort attrRealm = 0x0014;
enum ushort attrNonce = 0x0015;
enum ushort attrXorMappedAddress = 0x0020;
enum ushort attrPriority = 0x0024;
enum ushort attrUseCandidate = 0x0025;
enum ushort attrSoftware = 0x8022;
enum ushort attrFingerprint = 0x8028;
enum ushort attrIceControlled = 0x8029;
enum ushort attrIceControlling = 0x802A;

enum ubyte familyIpv4 = 0x01;
enum ubyte familyIpv6 = 0x02;

struct Attribute
{
	ushort typ;
	ubyte[] value;
}

struct Message
{
	ushort typ;
	TransactionId transactionId;
	Attribute[] attributes;

	// When decoded: the bytes exactly as they arrived, and the offset of each
	// attribute's TLV within them. Integrity/fingerprint are verified over these
	// so a peer's padding is covered; a message we build or alter has raw==null
	// and is re-encoded instead.
	private const(ubyte)[] raw;
	private size_t[] tlvOffsets;

	const(ubyte)[] get(ushort t) const @safe pure nothrow
	{
		foreach (ref a; attributes)
			if (a.typ == t)
				return a.value;
		return null;
	}

	bool has(ushort t) const @safe pure nothrow
	{
		foreach (ref a; attributes)
			if (a.typ == t)
				return true;
		return false;
	}

	static TransactionId randomTransactionId() @trusted
	{
		TransactionId id;
		randombytes_buf(id.ptr, id.length);
		return id;
	}

	// --- encode / decode ------------------------------------------------------------

	ubyte[] encode() const @safe pure
	{
		auto body_ = attributesBytes(attributes);
		return headerBytes(cast(ushort) body_.length) ~ body_;
	}

	private ubyte[] headerBytes(ushort bodyLength) const @safe pure nothrow
	{
		ubyte[] h = [
			cast(ubyte)(typ >> 8), cast(ubyte)(typ & 0xff),
			cast(ubyte)(bodyLength >> 8), cast(ubyte)(bodyLength & 0xff),
			0x21, 0x12, 0xA4, 0x42,
		];
		return h ~ transactionId[];
	}

	private ubyte[] attributesBytes(const(Attribute)[] attrs) const @safe pure
	{
		ubyte[] body_;
		foreach (ref a; attrs)
		{
			body_ ~= cast(ubyte)(a.typ >> 8);
			body_ ~= cast(ubyte)(a.typ & 0xff);
			body_ ~= cast(ubyte)(a.value.length >> 8);
			body_ ~= cast(ubyte)(a.value.length & 0xff);
			body_ ~= a.value;
			while (body_.length % 4 != 0)
				body_ ~= 0;
		}
		return body_;
	}

	static Message decode(scope const(ubyte)[] data) @safe pure
	{
		enforce(data.length >= headerLen, "stun: short header");
		enforce(data.length <= maxMessageLen, "stun: message too large");
		enforce((data[0] & 0xC0) == 0, "stun: top two bits must be zero");
		enforce(data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42,
			"stun: bad magic cookie");
		immutable length = (data[2] << 8) | data[3];
		enforce(length % 4 == 0, "stun: length not a multiple of four");
		enforce(headerLen + length <= data.length, "stun: truncated body");

		Message m;
		m.typ = cast(ushort)((data[0] << 8) | data[1]);
		m.transactionId[] = data[8 .. 20];
		m.raw = data[0 .. headerLen + length].dup;
		size_t pos = headerLen;
		immutable end = headerLen + length;
		while (pos < end)
		{
			enforce(pos + 4 <= end, "stun: truncated attribute header");
			immutable t = cast(ushort)((data[pos] << 8) | data[pos + 1]);
			immutable l = (data[pos + 2] << 8) | data[pos + 3];
			enforce(pos + 4 + l <= end, "stun: attribute runs past the message");
			m.tlvOffsets ~= pos;
			m.attributes ~= Attribute(t, data[pos + 4 .. pos + 4 + l].dup);
			pos += 4 + l;
			while (pos % 4 != 0 && pos < end)
				pos++;
		}
		return m;
	}

	// --- MESSAGE-INTEGRITY (RFC 5389 §15.4) -----------------------------------------

	void addMessageIntegrity(const(ubyte)[] key) @safe pure
	{
		raw = null; // built by us now
		attributes ~= Attribute(attrMessageIntegrity, integrityOver(key, attributes.length).dup);
	}

	bool checkMessageIntegrity(const(ubyte)[] key) const @safe pure
	{
		foreach (i, ref a; attributes)
			if (a.typ == attrMessageIntegrity)
			{
				if (a.value.length != 20)
					return false;
				return integrityOver(key, i)[] == a.value;
			}
		return false;
	}

	// HMAC-SHA1 over everything up to attribute `count`, with the header length
	// set as if a 24-byte MESSAGE-INTEGRITY followed.
	private ubyte[20] integrityOver(const(ubyte)[] key, size_t count) const @safe pure
	{
		auto bytes = prefixThrough(count, 24);
		auto h = HMAC!SHA1(key);
		h.put(bytes);
		return h.finish();
	}

	/// The long-term key MD5(username ":" realm ":" password), password SASLprep'd.
	static ubyte[16] longTermKey(string username, string realm, string password) @safe pure
	{
		import std.digest.md : md5Of;

		return md5Of(username ~ ":" ~ realm ~ ":" ~ password);
	}

	// --- FINGERPRINT (RFC 5389 §15.5) -----------------------------------------------

	void addFingerprint() @safe pure
	{
		raw = null;
		immutable v = fingerprintOver(attributes.length);
		attributes ~= Attribute(attrFingerprint,
			[cast(ubyte)(v >> 24), cast(ubyte)(v >> 16), cast(ubyte)(v >> 8), cast(ubyte) v]);
	}

	bool checkFingerprint() const @safe pure
	{
		foreach (i, ref a; attributes)
			if (a.typ == attrFingerprint)
				return a.value.length == 4
					&& ((cast(uint) a.value[0] << 24) | (cast(uint) a.value[1] << 16)
						| (cast(uint) a.value[2] << 8) | a.value[3]) == fingerprintOver(i);
		return false;
	}

	private uint fingerprintOver(size_t count) const @safe pure
	{
		auto bytes = prefixThrough(count, 8); // the 8 bytes of FINGERPRINT count in the header length
		CRC32 crc;
		crc.put(bytes);
		auto d = crc.finish(); // little-endian
		return (cast(uint) d[0] | (cast(uint) d[1] << 8) | (cast(uint) d[2] << 16) | (cast(uint) d[3] << 24))
			^ 0x5354554e;
	}

	// The message truncated to the first `count` attributes, with the header
	// length adjusted for a following `trailer`-byte attribute. Uses the raw
	// bytes as received when they are still intact, else our own encoding.
	private ubyte[] prefixThrough(size_t count, size_t trailer) const @safe pure
	{
		ubyte[] bytes;
		if (raw !is null && count <= tlvOffsets.length && intact(count))
			bytes = (count < tlvOffsets.length ? raw[0 .. tlvOffsets[count]] : raw).dup;
		else
			bytes = headerBytes(0) ~ attributesBytes(attributes[0 .. count]);
		immutable len = bytes.length - headerLen + trailer;
		bytes[2] = cast(ubyte)(len >> 8);
		bytes[3] = cast(ubyte)(len & 0xff);
		return bytes;
	}

	// The first `count` attributes still match the raw bytes they came from.
	private bool intact(size_t count) const @safe pure nothrow
	{
		foreach (i; 0 .. count)
		{
			immutable at = tlvOffsets[i] + 4;
			auto v = attributes[i].value;
			if (at + v.length > raw.length || raw[at .. at + v.length] != v)
				return false;
		}
		return true;
	}
}

/// The top two bits zero and the cookie present: STUN, not DTLS, on one socket.
bool isStunMessage(scope const(ubyte)[] data) @safe pure nothrow @nogc
{
	return data.length >= headerLen && (data[0] & 0xC0) == 0
		&& data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42;
}

/// XOR-MAPPED-ADDRESS (RFC 5389 §15.2).
struct XorMappedAddress
{
	ubyte[] ip; /// 4 or 16 bytes
	ushort port;

	ubyte[] encode(TransactionId txid) const @safe pure
	{
		enforce(ip.length == 4 || ip.length == 16, "stun: address must be 4 or 16 bytes");
		immutable xport = port ^ cast(ushort)(magicCookie >> 16);
		ubyte[] out_ = [cast(ubyte) 0, ip.length == 4 ? familyIpv4 : familyIpv6,
			cast(ubyte)(xport >> 8), cast(ubyte)(xport & 0xff)];
		foreach (i, b; ip)
			out_ ~= cast(ubyte)(b ^ maskByte(i, txid));
		return out_;
	}

	static XorMappedAddress decode(scope const(ubyte)[] v, TransactionId txid) @safe pure
	{
		enforce(v.length >= 8, "stun: XOR-MAPPED-ADDRESS too short");
		immutable len = v[1] == familyIpv4 ? 4 : v[1] == familyIpv6 ? 16 : 0;
		enforce(len != 0, "stun: unknown address family");
		enforce(v.length == 4 + len, "stun: address length does not match its family");
		XorMappedAddress a;
		a.port = cast(ushort)(((v[2] << 8) | v[3]) ^ (magicCookie >> 16));
		a.ip = new ubyte[len];
		foreach (i; 0 .. len)
			a.ip[i] = cast(ubyte)(v[4 + i] ^ maskByte(i, txid));
		return a;
	}

	private static ubyte maskByte(size_t i, TransactionId txid) @safe pure nothrow @nogc
	{
		return i < 4 ? cast(ubyte)(magicCookie >> (8 * (3 - i))) : txid[i - 4];
	}
}
