module tests.sctp.packet_test;

import webrtc.sctp.packet;
import fluent.asserts : should;

// The checksum algorithm is anchored to its universally published check value.
@("sctp: CRC32c matches its published check value")
unittest
{
	crc32c(cast(ubyte[]) "123456789").should.equal(0xE306_9283u);
	crc32c([]).should.equal(0u);
}

// The real vectors: two SCTP packets produced by scapy — a wholly independent
// implementation that lays out the wire and computes CRC32c itself. Our decoder
// must accept them and read back exactly what scapy put in. Because these bytes
// come from another stack, a symmetric bug in our own encode/decode (a swapped
// port, a wrong offset, a big-endian checksum store) cannot hide here: scapy did
// not share it.

// SCTP INIT: sport 5000, dport 5000, verification tag 0 (an INIT carries 0), one
// INIT chunk (type 1, length 20) with init-tag 0x12345678, a_rwnd 106496,
// 1024/1024 streams, initial TSN 0x1000.
private immutable ubyte[] scapyInit = [
	0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x16, 0xde, 0x25, 0x9a,
	0x01, 0x00, 0x00, 0x14, 0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0xa0, 0x00,
	0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x00,
];

// SCTP DATA: sport 49152, dport 5000, tag 0xDEADBEEF, one DATA chunk (type 0,
// flags B|E = 0x03, length 18) TSN 1, stream 0, seq 0, PPID 53, payload "hi",
// followed by two padding bytes scapy added after the final chunk.
private immutable ubyte[] scapyData = [
	0xc0, 0x00, 0x13, 0x88, 0xde, 0xad, 0xbe, 0xef, 0x94, 0x0b, 0x27, 0x86,
	0x00, 0x03, 0x00, 0x12, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x35, 0x68, 0x69, 0x00, 0x00,
];

@("sctp: a foreign INIT packet from scapy decodes; its checksum verifies")
unittest
{
	auto p = Packet.decode(scapyInit);
	p.srcPort.should.equal(cast(ushort) 5000);
	p.dstPort.should.equal(cast(ushort) 5000);
	p.verificationTag.should.equal(0u);
	p.chunks.length.should.equal(1);
	p.chunks[0].typ.should.equal(cast(ubyte) ChunkType.init);
	p.chunks[0].flags.should.equal(cast(ubyte) 0);
	// init-tag, a_rwnd, out/in streams, initial TSN — 16 bytes, big-endian.
	p.chunks[0].value.should.equal(cast(ubyte[])[
		0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0xa0, 0x00,
		0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x10, 0x00,
	]);
}

@("sctp: a foreign DATA packet decodes with distinct ports and trailing padding")
unittest
{
	auto p = Packet.decode(scapyData);
	// Distinct ports prove we did not transpose src and dst.
	p.srcPort.should.equal(cast(ushort) 49152);
	p.dstPort.should.equal(cast(ushort) 5000);
	p.verificationTag.should.equal(0xDEAD_BEEFu);
	// The two trailing pad bytes are not a second chunk.
	p.chunks.length.should.equal(1);
	p.chunks[0].typ.should.equal(cast(ubyte) ChunkType.data);
	p.chunks[0].flags.should.equal(cast(ubyte) 0x03);
	p.chunks[0].value.length.should.equal(14);
	p.chunks[0].value[$ - 2 .. $].should.equal(cast(ubyte[]) "hi");
}

// Re-encoding a decoded foreign packet reproduces it byte for byte (padding and
// checksum included), so our encoder agrees with scapy's wire, not just ours.
@("sctp: re-encoding a foreign packet reproduces its bytes")
unittest
{
	Packet.decode(scapyInit).encode.should.equal(scapyInit);
	Packet.decode(scapyData).encode.should.equal(scapyData);
}

// A single flipped byte after a valid foreign packet is rejected by the checksum.
@("sctp: a corrupted packet fails the checksum")
unittest
{
	auto bytes = scapyInit.dup;
	bytes[$ - 1] ^= 0x01;
	Packet.decode(bytes).should.throwException!Exception;
}

// The 12-byte common header alone is a valid packet carrying no chunks.
@("sctp: a header-only packet decodes to zero chunks")
unittest
{
	ubyte[] hdr = [0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0, 0, 0, 0];
	auto p = Packet.decode(withChecksum(hdr));
	p.chunks.length.should.equal(0);
	p.srcPort.should.equal(cast(ushort) 1);
	p.dstPort.should.equal(cast(ushort) 2);
}

// A chunk whose value is empty (length exactly the 4-byte header) is accepted.
@("sctp: a zero-length-value chunk is accepted")
unittest
{
	ubyte[] pkt = [
		0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0, 0, 0, 0,
		ChunkType.cookieAck, 0x00, 0x00, 0x04, // len 4, no value
	];
	auto p = Packet.decode(withChecksum(pkt));
	p.chunks.length.should.equal(1);
	p.chunks[0].typ.should.equal(cast(ubyte) ChunkType.cookieAck);
	p.chunks[0].value.length.should.equal(0);
}

// The malformed matrix: each of these has a VALID checksum, so it is the length
// check being exercised, not the CRC. All must throw before any copy.
@("sctp: malformed chunk lengths are refused")
unittest
{
	// A chunk length below the 4-byte chunk header.
	foreach (ubyte badLen; [0, 1, 2, 3])
	{
		ubyte[] pkt = [
			0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0, 0, 0, 0,
			ChunkType.data, 0x00, 0x00, badLen,
		];
		Packet.decode(withChecksum(pkt)).should.throwException!Exception;
	}

	// A chunk length that runs past the packet.
	ubyte[] past = [
		0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0, 0, 0, 0,
		ChunkType.data, 0x00, 0xff, 0xff, 0x01, 0x02,
	];
	Packet.decode(withChecksum(past)).should.throwException!Exception;

	// A chunk header truncated mid-way (two bytes where four are needed).
	ubyte[] truncated = [
		0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0x00, 0x01,
	];
	Packet.decode(withChecksum(truncated)).should.throwException!Exception;

	// Shorter than the common header.
	Packet.decode(cast(ubyte[])[0, 1, 2, 3]).should.throwException!Exception;

	// Larger than we will hold.
	auto huge = new ubyte[70_000];
	Packet.decode(huge).should.throwException!Exception;
}

// Set the checksum field to a valid CRC32c so a test exercises the length checks
// rather than the checksum. Mirrors the little-endian store in the codec.
private ubyte[] withChecksum(ubyte[] pkt)
{
	pkt[8 .. 12] = 0;
	immutable c = crc32c(pkt);
	pkt[8] = cast(ubyte)(c & 0xff);
	pkt[9] = cast(ubyte)(c >> 8);
	pkt[10] = cast(ubyte)(c >> 16);
	pkt[11] = cast(ubyte)(c >> 24);
	return pkt;
}
