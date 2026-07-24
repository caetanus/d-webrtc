module tests.sctp.reassembly_test;

import webrtc.sctp.chunk.data : DataChunk;
import webrtc.sctp.reassembly;
import fluent.asserts : should;

private DataChunk mk(uint tsn, ushort ssn, bool b, bool e, bool unordered, string data)
{
	DataChunk d;
	d.tsn = tsn;
	d.streamIdentifier = 0;
	d.streamSequenceNumber = ssn;
	d.beginningFragment = b;
	d.endingFragment = e;
	d.unordered = unordered;
	d.userData = cast(ubyte[]) data.dup;
	return d;
}

@("reassembly delivers a single unfragmented ordered message")
unittest
{
	auto q = ReassemblyQueue(0);
	q.push(mk(1, 0, true, true, false, "hello")).should.equal(true);
	q.isReadable.should.equal(true);
	auto m = q.read();
	m.isNull.should.equal(false);
	(cast(string) m.get.toPayload).should.equal("hello");
	q.isReadable.should.equal(false);
}

@("reassembly joins ordered fragments (B/middle/E)")
unittest
{
	auto q = ReassemblyQueue(0);
	q.push(mk(1, 0, true, false, false, "foo")).should.equal(false);
	q.push(mk(2, 0, false, false, false, "bar")).should.equal(false);
	q.push(mk(3, 0, false, true, false, "baz")).should.equal(true);
	(cast(string) q.read().get.toPayload).should.equal("foobarbaz");
}

@("reassembly reorders fragments that arrive out of TSN order")
unittest
{
	auto q = ReassemblyQueue(0);
	q.push(mk(3, 0, false, true, false, "baz")); // E arrives first
	q.push(mk(1, 0, true, false, false, "foo")); // B
	q.push(mk(2, 0, false, false, false, "bar")); // middle → completes
	q.isReadable.should.equal(true);
	(cast(string) q.read().get.toPayload).should.equal("foobarbaz");
}

@("reassembly delivers unordered messages immediately")
unittest
{
	auto q = ReassemblyQueue(0);
	q.push(mk(5, 0, true, true, true, "unord")).should.equal(true);
	(cast(string) q.read().get.toPayload).should.equal("unord");
}

@("reassembly gates ordered delivery on stream sequence number")
unittest
{
	auto q = ReassemblyQueue(0);
	// SSN 1 arrives (complete) but must wait for SSN 0.
	q.push(mk(2, 1, true, true, false, "second"));
	q.isReadable.should.equal(false);
	q.push(mk(1, 0, true, true, false, "first"));
	q.isReadable.should.equal(true);
	(cast(string) q.read().get.toPayload).should.equal("first");
	(cast(string) q.read().get.toPayload).should.equal("second");
	q.read().isNull.should.equal(true);
}
