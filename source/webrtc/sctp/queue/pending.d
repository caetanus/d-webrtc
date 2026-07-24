/**
 * SCTP send-side pending queue — buffers outbound user messages (already split
 * into DATA chunks) before they are assigned a TSN and sent, keeping unordered
 * and ordered streams separate.
 *
 * Laundered from webrtc-rs's rtc-sctp `queue/pending_queue.rs`. The `selected`
 * latch ensures that once the first fragment of a message is dequeued, the rest
 * of that message's fragments are taken from the same queue before switching —
 * so fragments of different messages are never interleaved on the wire.
 */
module webrtc.sctp.queue.pending;

import std.typecons : Nullable, nullable;

import webrtc.sctp.queue.payload : PayloadData;

/// A two-queue (unordered/ordered) FIFO of outbound DATA chunks.
struct PendingQueue
{
	private PayloadData[] unorderedQueue;
	private PayloadData[] orderedQueue;
	private size_t queueLen;
	private size_t nBytes;
	private bool selected;
	private bool unorderedIsSelected;

	void push(PayloadData c) @safe pure nothrow
	{
		nBytes += c.data.userData.length;
		if (c.data.unordered)
			unorderedQueue ~= c;
		else
			orderedQueue ~= c;
		queueLen++;
	}

	/// The next chunk that would be popped, or null if empty.
	Nullable!PayloadData peek() @safe pure nothrow
	{
		if (selected)
		{
			auto q = unorderedIsSelected ? unorderedQueue : orderedQueue;
			return q.length ? nullable(q[0]) : Nullable!PayloadData.init;
		}
		if (unorderedQueue.length)
			return nullable(unorderedQueue[0]);
		if (orderedQueue.length)
			return nullable(orderedQueue[0]);
		return Nullable!PayloadData.init;
	}

	/// Dequeue the next chunk. When no message is mid-send, the caller passes the
	/// desired `beginningFragment`/`unordered` selection; once a multi-fragment
	/// message starts, subsequent calls continue it until its ending fragment.
	Nullable!PayloadData pop(bool beginningFragment, bool unordered) @safe pure nothrow
	{
		Nullable!PayloadData popped;
		if (selected)
		{
			popped = unorderedIsSelected ? popFront(unorderedQueue) : popFront(orderedQueue);
			if (!popped.isNull && popped.get.data.endingFragment)
				selected = false;
		}
		else
		{
			if (!beginningFragment)
				return Nullable!PayloadData.init;
			if (unordered)
			{
				popped = popFront(unorderedQueue);
				if (!popped.isNull && !popped.get.data.endingFragment)
				{
					selected = true;
					unorderedIsSelected = true;
				}
			}
			else
			{
				popped = popFront(orderedQueue);
				if (!popped.isNull && !popped.get.data.endingFragment)
				{
					selected = true;
					unorderedIsSelected = false;
				}
			}
		}

		if (!popped.isNull)
		{
			nBytes -= popped.get.data.userData.length;
			queueLen--;
		}
		return popped;
	}

	private static Nullable!PayloadData popFront(ref PayloadData[] q) @safe pure nothrow
	{
		if (q.length == 0)
			return Nullable!PayloadData.init;
		auto v = q[0];
		q = q[1 .. $];
		return nullable(v);
	}

	size_t getNumBytes() const @safe pure nothrow @nogc
	{
		return nBytes;
	}

	size_t length() const @safe pure nothrow @nogc
	{
		return queueLen;
	}

	bool isEmpty() const @safe pure nothrow @nogc
	{
		return queueLen == 0;
	}
}
