/**
 * XOR-MAPPED-ADDRESS attribute (RFC 5389 §15.2) — how a STUN Binding response
 * carries the peer's reflexive transport address, obfuscated by XOR-ing it with
 * the magic cookie and transaction id.
 *
 * Laundered from webrtc-rs's `rtc-stun/src/xoraddr.rs`, keeping only the encode/
 * decode (the pion `Setter`/`Getter` plumbing is dropped).
 */
module webrtc.stun.xoraddr;

import std.exception : enforce;

import webrtc.stun.message : MAGIC_COOKIE, TransactionId, TRANSACTION_ID_SIZE;

/// Address family markers in a MAPPED-ADDRESS-style value.
enum ubyte FAMILY_IPV4 = 0x01;
enum ubyte FAMILY_IPV6 = 0x02;

/// A decoded XOR-MAPPED-ADDRESS: the raw IP octets (4 or 16) and the port.
struct XorMappedAddress
{
	ubyte[] ip; // 4 bytes (IPv4) or 16 bytes (IPv6)
	ushort port;

	// The XOR key: the magic cookie followed by the transaction id.
	private static ubyte[4 + TRANSACTION_ID_SIZE] xorKey(const TransactionId txid) @safe pure nothrow
	{
		ubyte[4 + TRANSACTION_ID_SIZE] key;
		key[0 .. 4] = [cast(ubyte)(MAGIC_COOKIE >> 24), cast(ubyte)(MAGIC_COOKIE >> 16),
			cast(ubyte)(MAGIC_COOKIE >> 8), cast(ubyte)(MAGIC_COOKIE & 0xff)];
		key[4 .. $] = txid[];
		return key;
	}

	/// Encode as the attribute value (family, x-port, x-address).
	ubyte[] encode(const TransactionId txid) const @safe pure
	{
		enforce(ip.length == 4 || ip.length == 16, "xoraddr: bad IP length");
		immutable fam = ip.length == 4 ? FAMILY_IPV4 : FAMILY_IPV6;
		immutable xport = cast(ushort)(port ^ (MAGIC_COOKIE >> 16));
		auto key = xorKey(txid);

		ubyte[] v;
		v ~= [cast(ubyte) 0, fam]; // family is 16-bit, high byte 0
		v ~= [cast(ubyte)(xport >> 8), cast(ubyte)(xport & 0xff)];
		foreach (i, b; ip)
			v ~= cast(ubyte)(b ^ key[i]);
		return v;
	}

	/// Decode from an attribute value. Throws on a malformed/short value.
	static XorMappedAddress decode(scope const(ubyte)[] value, const TransactionId txid) @safe pure
	{
		enforce(value.length > 4, "xoraddr: short value");
		immutable fam = value[1];
		enforce(fam == FAMILY_IPV4 || fam == FAMILY_IPV6, "xoraddr: bad family");
		immutable want = fam == FAMILY_IPV4 ? 4 : 16;
		enforce(value.length == 4 + want, "xoraddr: bad address length");

		immutable port = cast(ushort)(((value[2] << 8) | value[3]) ^ (MAGIC_COOKIE >> 16));
		auto key = xorKey(txid);
		auto raw = value[4 .. $];
		ubyte[] ip;
		foreach (i, b; raw)
			ip ~= cast(ubyte)(b ^ key[i]);
		return XorMappedAddress(ip, port);
	}
}
