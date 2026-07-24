module tests.datachannel.message_test;

import webrtc.datachannel.message;
import fluent.asserts : should;

@("DATA_CHANNEL_OPEN round-trips label + protocol + reliability")
unittest
{
	DataChannelOpen o;
	o.channelType = ChannelType.reliable;
	o.priority = 256;
	o.reliabilityParameter = 0;
	o.label = cast(ubyte[]) "chat".dup;
	o.protocol = cast(ubyte[]) "proto".dup;

	auto raw = o.marshal;
	raw[0].should.equal(MESSAGE_TYPE_OPEN);
	raw.length.should.equal(cast(size_t)(12 + 4 + 5)); // header + label + protocol

	auto back = DataChannelOpen.unmarshal(raw);
	back.channelType.should.equal(ChannelType.reliable);
	back.priority.should.equal(cast(ushort) 256);
	back.reliabilityParameter.should.equal(0u);
	(cast(string) back.label).should.equal("chat");
	(cast(string) back.protocol).should.equal("proto");
}

@("DATA_CHANNEL_OPEN encodes the RFC 8832 header layout for an unordered channel")
unittest
{
	DataChannelOpen o;
	o.channelType = ChannelType.partialReliableRexmitUnordered; // 0x81
	o.priority = 0;
	o.reliabilityParameter = 5;
	o.label = [];
	o.protocol = [];

	o.marshal.should.equal(cast(ubyte[])[
		0x03, // DATA_CHANNEL_OPEN
		0x81, // channel type
		0x00, 0x00, // priority
		0x00, 0x00, 0x00, 0x05, // reliability parameter
		0x00, 0x00, // label length
		0x00, 0x00 // protocol length
	]);
}

@("DATA_CHANNEL_ACK marshals to a single type byte and is recognised")
unittest
{
	marshalAck().should.equal(cast(ubyte[])[0x02]);
	isAck(marshalAck()).should.equal(true);
	isAck(cast(ubyte[])[0x03]).should.equal(false);
}

@("DATA_CHANNEL_OPEN unmarshal rejects truncated messages")
unittest
{
	DataChannelOpen.unmarshal(cast(ubyte[])[0x03, 0x00]).should.throwException!Exception; // short
	// Declares a 5-byte label but has none.
	auto bad = cast(ubyte[])[0x03, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0];
	DataChannelOpen.unmarshal(bad).should.throwException!Exception;
}
