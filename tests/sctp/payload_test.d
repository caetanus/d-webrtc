module tests.sctp.payload_test;

import webrtc.sctp.chunk.data : DataChunk;
import webrtc.sctp.queue.payload;
import fluent.asserts : should;

private PayloadData mkP(uint tsn, size_t bytes = 4)
{
	PayloadData p;
	p.data.tsn = tsn;
	p.data.userData = new ubyte[bytes];
	return p;
}

@("payload queue builds a single contiguous gap-ack block")
unittest
{
	PayloadQueue q;
	q.push(mkP(1), 0).should.equal(true);
	q.push(mkP(2), 0).should.equal(true);
	q.push(mkP(3), 0).should.equal(true);

	auto blocks = q.getGapAckBlocks(0);
	blocks.length.should.equal(1);
	blocks[0].start.should.equal(cast(ushort) 1);
	blocks[0].end.should.equal(cast(ushort) 3);
}

@("payload queue splits gap-ack blocks around a missing TSN")
unittest
{
	PayloadQueue q;
	foreach (t; [1u, 2u, 4u, 5u]) // 3 missing
		q.push(mkP(t), 0);

	auto blocks = q.getGapAckBlocks(0);
	blocks.length.should.equal(2);
	blocks[0].start.should.equal(cast(ushort) 1);
	blocks[0].end.should.equal(cast(ushort) 2);
	blocks[1].start.should.equal(cast(ushort) 4);
	blocks[1].end.should.equal(cast(ushort) 5);
}

@("payload queue records duplicate and too-old TSNs")
unittest
{
	PayloadQueue q;
	q.push(mkP(5), 0).should.equal(true);
	q.push(mkP(5), 0).should.equal(false); // already queued → duplicate
	q.push(mkP(2), 3).should.equal(false); // ≤ cumulative TSN 3 → duplicate
	q.popDuplicates().should.equal(cast(uint[])[5, 2]);
	q.popDuplicates().length.should.equal(0); // drained
}

@("payload queue marks acked (frees bytes) and pops the oldest TSN")
unittest
{
	PayloadQueue q;
	q.push(mkP(1, 10), 0);
	q.push(mkP(2, 10), 0);
	q.getNumBytes().should.equal(cast(size_t) 20);

	q.markAsAcked(1).should.equal(cast(size_t) 10);
	q.getNumBytes().should.equal(cast(size_t) 10);

	q.pop(2).isNull.should.equal(true); // 2 is not the oldest
	auto c = q.pop(1);
	c.isNull.should.equal(false);
	c.get.tsn.should.equal(1u);
	q.length.should.equal(cast(size_t) 1);
}
