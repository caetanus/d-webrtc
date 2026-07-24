module tests.stun.xoraddr_test;

import webrtc.stun.message : TransactionId;
import webrtc.stun.xoraddr;
import fluent.asserts : should;

// Transaction id from the RFC 5769 §2.1 sample response.
private enum TransactionId RFC5769_TXID = [
	0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

@("XOR-MAPPED-ADDRESS encodes the RFC 5769 IPv4 sample (192.0.2.1:32853)")
unittest
{
	auto x = XorMappedAddress(cast(ubyte[])[192, 0, 2, 1], cast(ushort) 32853);
	// family 0x0001, x-port 0xa147, x-address 0xe112a643 (RFC 5769 §2.1).
	x.encode(RFC5769_TXID).should.equal(
		cast(ubyte[])[0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
}

@("XOR-MAPPED-ADDRESS round-trips IPv4 and IPv6")
unittest
{
	auto v4 = XorMappedAddress(cast(ubyte[])[10, 11, 12, 13], cast(ushort) 4242);
	auto b4 = XorMappedAddress.decode(v4.encode(RFC5769_TXID), RFC5769_TXID);
	b4.ip.should.equal(cast(ubyte[])[10, 11, 12, 13]);
	b4.port.should.equal(cast(ushort) 4242);

	ubyte[16] ip6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
	auto v6 = XorMappedAddress(ip6.dup, cast(ushort) 5060);
	auto b6 = XorMappedAddress.decode(v6.encode(RFC5769_TXID), RFC5769_TXID);
	b6.ip.should.equal(ip6[]);
	b6.port.should.equal(cast(ushort) 5060);
}

@("XOR-MAPPED-ADDRESS decode rejects malformed values")
unittest
{
	XorMappedAddress.decode(cast(ubyte[])[0, 1, 2, 3], RFC5769_TXID)
		.should.throwException!Exception; // too short
	// family IPv4 but address is 16 bytes.
	auto bad = new ubyte[4 + 16];
	bad[1] = FAMILY_IPV4;
	XorMappedAddress.decode(bad, RFC5769_TXID).should.throwException!Exception;
}
