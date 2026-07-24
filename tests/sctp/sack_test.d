module tests.sctp.sack_test;

import webrtc.sctp.packet : Packet;
import webrtc.sctp.chunk.sack;
import fluent.asserts : should;

@("SCTP SACK round-trips cumulative ack, gap blocks and duplicate TSNs")
unittest
{
	SackChunk s;
	s.cumulativeTsnAck = 1000;
	s.advertisedReceiverWindowCredit = 128 * 1024;
	s.gapAckBlocks ~= GapAckBlock(2, 3);
	s.gapAckBlocks ~= GapAckBlock(5, 5);
	s.duplicateTsn ~= 998;

	auto back = SackChunk.fromChunk(s.toChunk());
	back.cumulativeTsnAck.should.equal(1000u);
	back.advertisedReceiverWindowCredit.should.equal(cast(uint)(128 * 1024));
	back.gapAckBlocks.length.should.equal(2);
	back.gapAckBlocks[0].start.should.equal(cast(ushort) 2);
	back.gapAckBlocks[0].end.should.equal(cast(ushort) 3);
	back.gapAckBlocks[1].start.should.equal(cast(ushort) 5);
	back.duplicateTsn.should.equal(cast(uint[])[998]);
}

@("SCTP SACK survives a full packet marshal/unmarshal")
unittest
{
	SackChunk s;
	s.cumulativeTsnAck = 7;
	s.advertisedReceiverWindowCredit = 65_536;

	Packet p;
	p.verificationTag = 0xabcddcba;
	p.chunks ~= s.toChunk();
	auto back = Packet.unmarshal(p.marshal);
	auto s2 = SackChunk.fromChunk(back.chunks[0]);
	s2.cumulativeTsnAck.should.equal(7u);
	s2.gapAckBlocks.length.should.equal(0);
}
