module tests.stun.message_test;

import webrtc.stun.message;
import fluent.asserts : should;

private ubyte[] unhex(string h)
{
	import std.conv : to;

	ubyte[] r;
	string clean;
	foreach (c; h)
		if (c != ' ' && c != '\n' && c != '\t')
			clean ~= c;
	for (size_t i = 0; i + 1 < clean.length; i += 2)
		r ~= clean[i .. i + 2].to!ubyte(16);
	return r;
}

// RFC 5769 uses this short-term password for §2.1–§2.3.
private enum rfcPassword = "VOkJxbRl1RmTxUk/WvJxBt";
private enum TransactionId rfcTxid = [
	0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

private enum sampleRequest = "
00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86
fa 87 df ae 80 22 00 10 53 54 55 4e 20 74 65 73
74 20 63 6c 69 65 6e 74 00 24 00 04 6e 00 01 ff
80 29 00 08 93 2f f9 b1 51 26 3b 36 00 06 00 09
65 76 74 6a 3a 68 36 76 59 20 20 20 00 08 00 14
9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49
c1 b5 71 a2 80 28 00 04 e5 7a 3b cf";

private enum sampleIpv4Response = "
01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86
fa 87 df ae 80 22 00 0b 74 65 73 74 20 76 65 63
74 6f 72 20 00 20 00 08 00 01 a1 47 e1 12 a6 43
00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9
2a f9 ba 53 f0 6b e7 d7 80 28 00 04 c0 7d 4c 96";

private enum sampleIpv6Response = "
01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86
fa 87 df ae 80 22 00 0b 74 65 73 74 20 76 65 63
74 6f 72 20 00 20 00 14 00 02 a1 47 01 13 a9 fa
a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9 00 08 00 14
a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75
bf e3 ed 41 80 28 00 04 c8 fb 0b 4c";

private enum sampleLongTerm = "
00 01 00 60 21 12 a4 42 78 ad 34 33 c6 ad 72 c0
29 da 41 2e 00 06 00 12 e3 83 9e e3 83 88 e3 83
aa e3 83 83 e3 82 af e3 82 b9 00 00 00 15 00 1c
66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34
6f 4c 39 46 53 54 76 79 36 34 73 41 00 14 00 0b
65 78 61 6d 70 6c 65 2e 6f 72 67 00 00 08 00 14
f6 70 24 65 6d d6 4a 3e 02 b8 e0 71 2e 85 c9 a2
8c a8 96 66";

// The whole point: decode a foreign message and verify its OWN precomputed
// HMAC — not a self-round-trip.
@("RFC 5769 §2.1: the sample request decodes; its integrity and fingerprint verify")
unittest
{
	auto m = Message.decode(unhex(sampleRequest));
	m.typ.should.equal(bindingRequest);
	m.transactionId[].should.equal(rfcTxid[]);
	(cast(string) m.get(attrSoftware)).should.equal("STUN test client");
	m.get(attrPriority).should.equal(cast(ubyte[])[0x6e, 0x00, 0x01, 0xff]);
	m.get(attrIceControlled).should.equal(cast(ubyte[])[0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36]);
	(cast(string) m.get(attrUsername)).should.equal("evtj:h6vY");
	m.checkMessageIntegrity(cast(ubyte[]) rfcPassword).should.equal(true);
	m.checkMessageIntegrity(cast(ubyte[]) "not it").should.equal(false);
	m.checkFingerprint().should.equal(true);
}

// The USERNAME is 9 bytes padded to 12 with three 0x20 spaces; the HMAC covers
// those bytes exactly as sent. A decoder that normalised padding would fail.
@("RFC 5769 §2.1: integrity is over the bytes as received, spaces and all")
unittest
{
	auto raw = unhex(sampleRequest);
	raw[73 .. 76].should.equal(cast(ubyte[])[0x20, 0x20, 0x20]);
	Message.decode(raw).checkMessageIntegrity(cast(ubyte[]) rfcPassword).should.equal(true);
}

@("RFC 5769 §2.2: the IPv4 response carries 192.0.2.1:32853 and verifies")
unittest
{
	auto m = Message.decode(unhex(sampleIpv4Response));
	auto a = XorMappedAddress.decode(m.get(attrXorMappedAddress), m.transactionId);
	a.ip.should.equal(cast(ubyte[])[192, 0, 2, 1]);
	a.port.should.equal(cast(ushort) 32853);
	m.checkMessageIntegrity(cast(ubyte[]) rfcPassword).should.equal(true);
	m.checkFingerprint().should.equal(true);
}

@("RFC 5769 §2.3: the IPv6 response carries its address and verifies")
unittest
{
	auto m = Message.decode(unhex(sampleIpv6Response));
	auto a = XorMappedAddress.decode(m.get(attrXorMappedAddress), m.transactionId);
	a.ip.should.equal(cast(ubyte[])[0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
	a.port.should.equal(cast(ushort) 32853);
	m.checkMessageIntegrity(cast(ubyte[]) rfcPassword).should.equal(true);
	m.checkFingerprint().should.equal(true);
}

@("RFC 5769 §2.4: long-term credentials verify with the MD5(user:realm:pass) key")
unittest
{
	auto m = Message.decode(unhex(sampleLongTerm));
	(cast(string) m.get(attrRealm)).should.equal("example.org");
	(cast(string) m.get(attrNonce)).should.equal("f//499k954d6OL34oL9FSTvy64sA");
	auto key = Message.longTermKey(cast(string) m.get(attrUsername), "example.org", "TheMatrIX");
	m.checkMessageIntegrity(key[]).should.equal(true);
}

@("stun: a length past the message is refused before allocation")
unittest
{
	auto a = unhex(sampleRequest);
	a[3] = 0xff; // body length far beyond what is present
	Message.decode(a).should.throwException!Exception;
	auto b = unhex(sampleRequest);
	b[23] = 0x40; // USERNAME claims 64 bytes inside a shorter body
	Message.decode(b).should.throwException!Exception;
	Message.decode(new ubyte[20]).should.throwException!Exception; // zero cookie
}

@("stun: isStunMessage tells STUN from other traffic")
unittest
{
	isStunMessage(unhex(sampleRequest)).should.equal(true);
	auto bad = unhex(sampleRequest);
	bad[4] = 0;
	isStunMessage(bad).should.equal(false);
	isStunMessage(cast(ubyte[])[1, 2, 3]).should.equal(false);
}

// What we build, a foreign peer would accept: round-trip our own signed message.
@("stun: a message we build verifies after decode")
unittest
{
	Message m;
	m.typ = bindingRequest;
	m.transactionId = rfcTxid;
	m.attributes ~= Attribute(attrUsername, cast(ubyte[]) "user:peer".dup);
	m.attributes ~= Attribute(attrPriority, cast(ubyte[])[0x6e, 0, 1, 0xff]);
	m.addMessageIntegrity(cast(ubyte[]) rfcPassword);
	m.addFingerprint();
	auto back = Message.decode(m.encode);
	back.checkMessageIntegrity(cast(ubyte[]) rfcPassword).should.equal(true);
	back.checkFingerprint().should.equal(true);
	auto enc = m.encode;
	((enc[2] << 8) | enc[3]).should.equal(cast(int)(enc.length - 20));
}

@("stun: XOR-MAPPED-ADDRESS round-trips v4 and v6")
unittest
{
	auto v4 = XorMappedAddress(cast(ubyte[])[10, 0, 0, 1], 4242);
	auto b4 = XorMappedAddress.decode(v4.encode(rfcTxid), rfcTxid);
	b4.ip.should.equal(cast(ubyte[])[10, 0, 0, 1]);
	b4.port.should.equal(cast(ushort) 4242);
	ubyte[16] ip6 = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
	auto v6 = XorMappedAddress(ip6.dup, 5060);
	XorMappedAddress.decode(v6.encode(rfcTxid), rfcTxid).ip.should.equal(ip6[]);
}
