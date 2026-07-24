/**
 * SCTP receive-side reassembly (RFC 4960 §6.9) — reorders arriving DATA chunks
 * by TSN and reassembles fragments into whole user messages, honouring ordered
 * (per stream-sequence-number) vs unordered delivery. This is what turns the
 * TSN-tagged fragment stream into the messages a data channel delivers.
 *
 * Laundered from webrtc-rs's rtc-sctp `queue/reassembly_queue.rs`. The rust code
 * tiebreaks ordered-vs-unordered readiness by wall-clock `Instant`; we use a
 * monotonic insertion counter instead — same FIFO-by-arrival semantics, but
 * deterministic (and no forbidden clock reads). PR-SCTP forward-TSN pruning is
 * left for the association layer.
 */
module webrtc.sctp.reassembly;

import std.typecons : Nullable, nullable;

import webrtc.sctp.chunk.data : DataChunk;
import webrtc.sctp.sna : sna32lt, sna16lt, sna16lte, sna16gt;

/// A set of fragments that share a stream-sequence-number, reassembled in TSN
/// order into one message.
struct Chunks
{
	ushort ssn;
	uint ppi; // payload protocol identifier
	DataChunk[] chunks;
	ulong arrival; // insertion order (FIFO tiebreaker)

	size_t len() const @safe pure nothrow @nogc
	{
		size_t l;
		foreach (ref c; chunks)
			l += c.userData.length;
		return l;
	}

	bool isEmpty() const @safe pure nothrow @nogc
	{
		return len == 0;
	}

	/// A complete set: ≥1 chunk, begins with B, ends with E, contiguous TSNs.
	bool isComplete() const @safe pure nothrow @nogc
	{
		if (chunks.length == 0 || !chunks[0].beginningFragment || !chunks[$ - 1].endingFragment)
			return false;
		uint lastTsn;
		foreach (i, ref c; chunks)
		{
			if (i > 0 && c.tsn != lastTsn + 1)
				return false;
			lastTsn = c.tsn;
		}
		return true;
	}

	/// Concatenate the fragment payloads into one message.
	ubyte[] toPayload() const @safe pure nothrow
	{
		ubyte[] buf;
		foreach (ref c; chunks)
			buf ~= c.userData;
		return buf;
	}

	/// Insert `chunk` in TSN order; returns whether the set is now complete.
	bool push(DataChunk chunk) @safe pure nothrow
	{
		size_t i;
		while (i < chunks.length && sna32lt(chunks[i].tsn, chunk.tsn))
			i++;
		chunks = chunks[0 .. i] ~ chunk ~ chunks[i .. $];
		return isComplete();
	}
}

/// Per-stream reassembly queue.
struct ReassemblyQueue
{
	ushort si; // stream identifier
	ushort nextSsn; // expected SSN for the next ordered message
	Chunks[] ordered;
	Chunks[] unordered;
	DataChunk[] unorderedChunks;
	size_t nBytes;
	private ulong arrivalSeq;

	this(ushort si) @safe pure nothrow @nogc
	{
		this.si = si;
	}

	/// Accept a DATA chunk. Returns true if a complete message became readable.
	bool push(DataChunk chunk) @safe pure nothrow
	{
		if (chunk.streamIdentifier != si)
			return false;

		if (chunk.unordered)
		{
			nBytes += chunk.userData.length;
			size_t i;
			while (i < unorderedChunks.length && sna32lt(unorderedChunks[i].tsn, chunk.tsn))
				i++;
			unorderedChunks = unorderedChunks[0 .. i] ~ chunk ~ unorderedChunks[i .. $];

			auto cset = findCompleteUnorderedChunkSet();
			if (!cset.isNull)
			{
				unordered ~= cset.get;
				return true;
			}
			return false;
		}

		// Ordered: drop chunks for already-delivered SSNs.
		if (sna16lt(chunk.streamSequenceNumber, nextSsn))
			return false;
		nBytes += chunk.userData.length;

		immutable ssn = chunk.streamSequenceNumber;
		size_t i;
		while (i < ordered.length && sna16lt(ordered[i].ssn, ssn))
			i++;
		if (i < ordered.length && ordered[i].ssn == ssn)
			return ordered[i].push(chunk);

		auto cset = Chunks(ssn, chunk.payloadType, [], arrivalSeq++);
		immutable ok = cset.push(chunk);
		ordered = ordered[0 .. i] ~ cset ~ ordered[i .. $];
		return ok;
	}

	/// Whether a complete message is available to read.
	bool isReadable() const @safe pure nothrow @nogc
	{
		if (unordered.length)
			return true;
		if (ordered.length)
		{
			auto cset = ordered[0];
			if (cset.isComplete() && sna16lte(cset.ssn, nextSsn))
				return true;
		}
		return false;
	}

	/// Pop the next complete message (unordered/ordered, FIFO by arrival for
	/// ties), or null if none is ready.
	Nullable!Chunks read() @safe pure nothrow
	{
		bool haveUnordered = unordered.length > 0;
		bool haveOrdered = ordered.length > 0 && ordered[0].isComplete()
			&& !sna16gt(ordered[0].ssn, nextSsn);

		if (haveUnordered && haveOrdered)
		{
			if (unordered[0].arrival < ordered[0].arrival)
				return popUnordered();
			return popOrdered();
		}
		if (haveUnordered)
			return popUnordered();
		if (haveOrdered)
			return popOrdered();
		return Nullable!Chunks.init;
	}

	private Nullable!Chunks popUnordered() @safe pure nothrow
	{
		auto c = unordered[0];
		unordered = unordered[1 .. $];
		subtractNumBytes(c.len);
		return nullable(c);
	}

	private Nullable!Chunks popOrdered() @safe pure nothrow
	{
		auto c = ordered[0];
		ordered = ordered[1 .. $];
		if (c.ssn == nextSsn)
			nextSsn = cast(ushort)(nextSsn + 1);
		subtractNumBytes(c.len);
		return nullable(c);
	}

	// Scan unorderedChunks for a contiguous B..E fragment run and extract it.
	private Nullable!Chunks findCompleteUnorderedChunkSet() @safe pure nothrow
	{
		long startIdx = -1;
		size_t nChunks;
		uint lastTsn;
		bool found;

		foreach (i, ref c; unorderedChunks)
		{
			if (c.beginningFragment)
			{
				startIdx = i;
				nChunks = 1;
				lastTsn = c.tsn;
				if (c.endingFragment)
				{
					found = true;
					break;
				}
				continue;
			}
			if (startIdx < 0)
				continue;
			if (c.tsn != lastTsn + 1)
			{
				startIdx = -1;
				continue;
			}
			nChunks++;
			lastTsn = c.tsn;
			if (c.endingFragment)
			{
				found = true;
				break;
			}
		}

		if (!found)
			return Nullable!Chunks.init;

		immutable s = cast(size_t) startIdx;
		auto set = unorderedChunks[s .. s + nChunks].dup;
		unorderedChunks = unorderedChunks[0 .. s] ~ unorderedChunks[s + nChunks .. $];
		return nullable(Chunks(0, set[0].payloadType, set, arrivalSeq++));
	}

	private void subtractNumBytes(size_t n) @safe pure nothrow @nogc
	{
		nBytes = nBytes >= n ? nBytes - n : 0;
	}
}
