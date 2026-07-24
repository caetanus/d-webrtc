module tests.sctp.packet_test;

import webrtc.sctp.packet;
import fluent.asserts : should;

@("SCTP packet round-trips through marshal/unmarshal with a valid CRC-32C")
unittest
{
	Packet p;
	p.sourcePort = 5000;
	p.destinationPort = 5000;
	p.verificationTag = 0x1234_5678;
	p.chunks ~= Chunk(CT_COOKIE_ACK, 0, []);
	p.chunks ~= Chunk(CT_PAYLOAD_DATA, 3, cast(ubyte[])[1, 2, 3]); // 3 bytes → padded

	auto raw = p.marshal;
	auto back = Packet.unmarshal(raw);

	back.sourcePort.should.equal(cast(ushort) 5000);
	back.destinationPort.should.equal(cast(ushort) 5000);
	back.verificationTag.should.equal(0x1234_5678u);
	back.chunks.length.should.equal(2);
	back.chunks[0].typ.should.equal(CT_COOKIE_ACK);
	back.chunks[0].value.length.should.equal(0);
	back.chunks[1].typ.should.equal(CT_PAYLOAD_DATA);
	back.chunks[1].flags.should.equal(cast(ubyte) 3);
	back.chunks[1].value.should.equal(cast(ubyte[])[1, 2, 3]);
}

@("SCTP unmarshal rejects a corrupt checksum and a short packet")
unittest
{
	Packet p;
	p.sourcePort = 1;
	p.destinationPort = 2;
	p.verificationTag = 3;
	p.chunks ~= Chunk(CT_COOKIE_ACK, 0, []);

	auto raw = p.marshal.dup;
	raw[0] ^= 0xff; // corrupt a header byte → checksum fails
	Packet.unmarshal(raw).should.throwException!Exception;
	Packet.unmarshal(cast(ubyte[])[1, 2, 3]).should.throwException!Exception; // too small
}
