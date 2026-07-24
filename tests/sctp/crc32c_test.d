module tests.sctp.crc32c_test;

import webrtc.sctp.crc32c;
import fluent.asserts : should;

@("CRC-32C matches the Castagnoli check vector")
unittest
{
	// The canonical CRC-32C("123456789") = 0xE3069283.
	crc32c(cast(ubyte[]) "123456789").should.equal(0xE306_9283u);
	crc32c([]).should.equal(0u);
}
