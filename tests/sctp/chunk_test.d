module tests.sctp.chunk_test;

import webrtc.sctp.packet : Packet, Chunk;
import webrtc.sctp.chunk.data;
import webrtc.sctp.chunk.init;
import webrtc.sctp.param;
import fluent.asserts : should;

@("SCTP DATA chunk round-trips its flags and header fields")
unittest
{
	DataChunk d;
	d.beginningFragment = true;
	d.endingFragment = true;
	d.unordered = true;
	d.tsn = 100;
	d.streamIdentifier = 1;
	d.streamSequenceNumber = 5;
	d.payloadType = PPID_STRING;
	d.userData = cast(ubyte[]) "hello".dup;

	auto back = DataChunk.fromChunk(d.toChunk());
	back.beginningFragment.should.equal(true);
	back.endingFragment.should.equal(true);
	back.unordered.should.equal(true);
	back.immediateSack.should.equal(false);
	back.tsn.should.equal(100u);
	back.streamIdentifier.should.equal(cast(ushort) 1);
	back.streamSequenceNumber.should.equal(cast(ushort) 5);
	back.payloadType.should.equal(PPID_STRING);
	back.userData.should.equal(cast(ubyte[]) "hello");
}

@("SCTP INIT chunk round-trips fixed header + parameters")
unittest
{
	InitChunk i;
	i.initiateTag = 0xdead_beef;
	i.advertisedReceiverWindowCredit = 65_536;
	i.numOutboundStreams = 1024;
	i.numInboundStreams = 1024;
	i.initialTsn = 1;
	i.params ~= Param(PARAM_FORWARD_TSN_SUPPORTED, []);
	i.params ~= Param(PARAM_SUPPORTED_EXTENSIONS, cast(ubyte[])[192, 130]);

	auto back = InitChunk.fromChunk(i.toChunk());
	back.isAck.should.equal(false);
	back.initiateTag.should.equal(0xdead_beefu);
	back.advertisedReceiverWindowCredit.should.equal(65_536u);
	back.numOutboundStreams.should.equal(cast(ushort) 1024);
	back.numInboundStreams.should.equal(cast(ushort) 1024);
	back.initialTsn.should.equal(1u);
	back.params.length.should.equal(2);
	back.params[0].typ.should.equal(PARAM_FORWARD_TSN_SUPPORTED);
	back.params[1].typ.should.equal(PARAM_SUPPORTED_EXTENSIONS);
	back.params[1].value.should.equal(cast(ubyte[])[192, 130]);
}

@("SCTP DATA chunk survives a full packet marshal/unmarshal")
unittest
{
	DataChunk d;
	d.beginningFragment = true;
	d.endingFragment = true;
	d.tsn = 42;
	d.streamIdentifier = 3;
	d.payloadType = PPID_BINARY;
	d.userData = cast(ubyte[])[0xca, 0xfe, 0xba, 0xbe, 0x01]; // 5 bytes → padded

	Packet p;
	p.sourcePort = 5000;
	p.destinationPort = 5000;
	p.verificationTag = 0x11223344;
	p.chunks ~= d.toChunk();

	auto back = Packet.unmarshal(p.marshal);
	back.chunks.length.should.equal(1);
	auto d2 = DataChunk.fromChunk(back.chunks[0]);
	d2.tsn.should.equal(42u);
	d2.payloadType.should.equal(PPID_BINARY);
	d2.userData.should.equal(cast(ubyte[])[0xca, 0xfe, 0xba, 0xbe, 0x01]);
}
