module tests.sctp.pending_test;

import webrtc.sctp.queue.payload : PayloadData;
import webrtc.sctp.queue.pending;
import fluent.asserts : should;

private PayloadData mk(bool unordered, bool beginning, bool ending, string data)
{
	PayloadData p;
	p.data.unordered = unordered;
	p.data.beginningFragment = beginning;
	p.data.endingFragment = ending;
	p.data.userData = cast(ubyte[]) data.dup;
	return p;
}

@("pending queue prefers unordered, tracks bytes and length")
unittest
{
	PendingQueue q;
	q.push(mk(false, true, true, "ordered"));
	q.push(mk(true, true, true, "unord"));
	q.length.should.equal(cast(size_t) 2);
	q.getNumBytes().should.equal(cast(size_t)("ordered".length + "unord".length));

	// Unordered is served first.
	(cast(string) q.peek().get.data.userData).should.equal("unord");
	auto p = q.pop(true, true);
	(cast(string) p.get.data.userData).should.equal("unord");
	q.length.should.equal(cast(size_t) 1);
}

@("pending queue keeps a multi-fragment message contiguous via the selected latch")
unittest
{
	PendingQueue q;
	// An ordered 3-fragment message...
	q.push(mk(false, true, false, "A1"));
	q.push(mk(false, false, false, "A2"));
	q.push(mk(false, false, true, "A3"));
	// ...and an unordered message queued meanwhile.
	q.push(mk(true, true, true, "U"));

	// Start the ordered message; the latch now forces the rest from ordered,
	// even though the caller could ask for unordered.
	(cast(string) q.pop(true, false).get.data.userData).should.equal("A1");
	(cast(string) q.pop(true, true).get.data.userData).should.equal("A2"); // stays ordered
	(cast(string) q.pop(true, true).get.data.userData).should.equal("A3"); // ending → unlatch
	// Now the unordered message is available.
	(cast(string) q.pop(true, true).get.data.userData).should.equal("U");
	q.isEmpty.should.equal(true);
}
