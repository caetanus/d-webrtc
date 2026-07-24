/**
 * SCTP payload (TSN) queue — used on both sides of an association: on receive to
 * track which TSNs arrived (and produce SACK gap-ack blocks + duplicate lists),
 * and on send to hold in-flight DATA chunks until a SACK acknowledges them.
 *
 * Laundered from webrtc-rs's rtc-sctp `queue/payload_queue.rs`. rust threads the
 * sender bookkeeping through `ChunkPayloadData`; we keep the wire `DataChunk`
 * pure (see chunk/data.d) and wrap it here in [`PayloadData`] with the send-side
 * state (acked / retransmit / …).
 */
module webrtc.sctp.queue.payload;

import std.typecons : Nullable, nullable;

import webrtc.sctp.chunk.data : DataChunk;
import webrtc.sctp.chunk.sack : GapAckBlock;
import webrtc.sctp.sna : sna32lt, sna32lte;

/// A DATA chunk plus the association's send-side state for it.
struct PayloadData
{
	DataChunk data; // wire fields (tsn, streams, ppid, user data, B/E/U flags)
	bool acked;
	bool retransmit;
	bool abandoned;
	uint nSent;
	uint missIndicator;
	long since = -1; // send time (ms) of the first transmission, for RTT; -1 = unset

	uint tsn() const @safe pure nothrow @nogc
	{
		return data.tsn;
	}
}

/// A TSN-keyed queue of payload chunks, kept in serial-number order.
struct PayloadQueue
{
	private PayloadData[uint] chunkMap;
	uint[] sorted; // TSNs in serial-number order
	private uint[] dupTsn;
	private size_t nBytes;

	private void insertSorted(uint tsn) @safe pure nothrow
	{
		size_t i;
		while (i < sorted.length && sna32lt(sorted[i], tsn))
			i++;
		sorted = sorted[0 .. i] ~ tsn ~ sorted[i .. $];
	}

	bool canPush(const PayloadData p, uint cumulativeTsn) const @safe pure nothrow
	{
		return !((p.tsn in chunkMap) !is null || sna32lte(p.tsn, cumulativeTsn));
	}

	/// Push a chunk. If its TSN is already queued or ≤ the cumulative TSN it is
	/// recorded as a duplicate (retrievable via popDuplicates) and false returned.
	bool push(PayloadData p, uint cumulativeTsn) @safe pure nothrow
	{
		if ((p.tsn in chunkMap) !is null || sna32lte(p.tsn, cumulativeTsn))
		{
			dupTsn ~= p.tsn;
			return false;
		}
		nBytes += p.data.userData.length;
		insertSorted(p.tsn);
		chunkMap[p.tsn] = p;
		return true;
	}

	/// Push a chunk unconditionally (used for the in-flight queue, where TSNs are
	/// freshly assigned and never duplicate or lag the cumulative point).
	void pushNoCheck(PayloadData p) @safe pure nothrow
	{
		nBytes += p.data.userData.length;
		insertSorted(p.tsn);
		chunkMap[p.tsn] = p;
	}

	/// Pop only if the oldest queued TSN equals `tsn`.
	Nullable!PayloadData pop(uint tsn) @safe pure nothrow
	{
		if (sorted.length && sorted[0] == tsn)
		{
			if (auto c = tsn in chunkMap)
			{
				sorted = sorted[1 .. $];
				nBytes -= c.data.userData.length;
				auto val = *c;
				chunkMap.remove(tsn);
				return nullable(val);
			}
		}
		return Nullable!PayloadData.init;
	}

	PayloadData* get(uint tsn) @safe pure nothrow
	{
		return tsn in chunkMap;
	}

	uint[] popDuplicates() @safe pure nothrow
	{
		auto d = dupTsn;
		dupTsn = [];
		return d;
	}

	/// Build the SACK gap-ack blocks relative to `cumulativeTsn`.
	GapAckBlock[] getGapAckBlocks(uint cumulativeTsn) const @safe pure nothrow
	{
		if (sorted.length == 0)
			return [];
		GapAckBlock b;
		GapAckBlock[] blocks;
		foreach (i, tsn; sorted)
		{
			immutable ushort diff = tsn >= cumulativeTsn ? cast(ushort)(tsn - cumulativeTsn) : 0;
			if (i == 0)
			{
				b.start = diff;
				b.end = diff;
			}
			else if (b.end + 1 == diff)
				b.end += 1;
			else
			{
				blocks ~= b;
				b.start = diff;
				b.end = diff;
			}
		}
		blocks ~= b;
		return blocks;
	}

	/// Mark a queued TSN acknowledged, releasing its payload. Returns the number
	/// of user-data bytes freed.
	size_t markAsAcked(uint tsn) @safe pure nothrow
	{
		if (auto c = tsn in chunkMap)
		{
			c.acked = true;
			c.retransmit = false;
			immutable n = c.data.userData.length;
			nBytes -= n;
			c.data.userData = [];
			return n;
		}
		return 0;
	}

	void markAllToRetransmit() @safe pure nothrow
	{
		foreach (ref c; chunkMap)
			if (!c.acked && !c.abandoned)
				c.retransmit = true;
	}

	size_t getNumBytes() const @safe pure nothrow @nogc
	{
		return nBytes;
	}

	size_t length() const @safe pure nothrow @nogc
	{
		return chunkMap.length;
	}

	bool isEmpty() const @safe pure nothrow @nogc
	{
		return chunkMap.length == 0;
	}
}
