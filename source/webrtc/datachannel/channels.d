/**
 * WebRTC data channels over SCTP, sans-io (RFC 8832 DCEP, RFC 8831 PPIDs). This
 * layer turns an SCTP association into named, reliable message channels: it does
 * not touch a socket, it drives the association below it.
 *
 * libp2p webrtc-direct opens one *negotiated* channel with stream id 0 (agreed
 * out of band, no DCEP handshake) and runs the Noise handshake over it; further
 * libp2p streams open channels through DCEP. A channel is closed by resetting its
 * SCTP stream (the RFC 6525 reset the association already implements).
 *
 * DCEP itself is sent reliably and in order over SCTP, so this layer needs no
 * timer — a lost DATA_CHANNEL_OPEN or ACK is the association's problem, not ours.
 * The application drives it: open/openNegotiated/send/close change state and
 * hand chunks to the association; events() turns what the association delivered
 * into channel opened / message / closed events.
 */
module webrtc.datachannel.channels;

import std.exception : enforce;

import webrtc.sctp.association : Association, Role, Message;

// RFC 8831 §8: the payload protocol identifiers WebRTC uses on SCTP.
enum uint ppidDcep = 50;
enum uint ppidString = 51;
enum uint ppidBinary = 53;
enum uint ppidStringEmpty = 56;
enum uint ppidBinaryEmpty = 57;

// RFC 8832 §5.1: DCEP message types.
private enum ubyte dcepOpen = 0x03;
private enum ubyte dcepAck = 0x02;
private enum ubyte channelReliable = 0x00; // reliable, ordered
private enum size_t maxLabelLen = 8192; // bound the accepted label/protocol
private enum size_t maxChannels = 30_000; // bound concurrent channels (Law 1)

enum ChannelEventKind
{
	opened,
	message,
	closed,
}

struct ChannelEvent
{
	ChannelEventKind kind;
	ushort channel;
	bool binary; // for message events
	ubyte[] data; // for message events (empty for an empty message)
	string label; // for opened events (from a DCEP OPEN)
	string protocol;
	bool remote; // opened events: true if the PEER opened the channel (an inbound
	// channel to accept), false if it is our own open being acknowledged
}

final class DataChannels
{
	private Association assoc;
	private Role role;
	private bool[ushort] openChannels; // established channels
	private bool[ushort] opening; // DCEP OPEN sent by us, awaiting ACK
	private ushort nextEven = 2; // the DTLS client uses even ids; 0 is the negotiated channel
	private ushort nextOdd = 1; // the DTLS server uses odd ids

	this(Association assoc, Role role) @safe
	{
		this.assoc = assoc;
		this.role = role;
	}

	/// A pre-agreed channel needing no DCEP handshake — libp2p's Noise channel is
	/// the negotiated id-0 channel. Both peers call this with the same id.
	void openNegotiated(ushort id) @safe
	{
		openChannels[id] = true;
	}

	/// Open a channel with DCEP: pick a stream id by our DTLS role, send
	/// DATA_CHANNEL_OPEN, and wait for the ACK. Returns the stream id.
	ushort open(string label, string protocol) @safe
	{
		enforce(label.length <= maxLabelLen && protocol.length <= maxLabelLen,
			"datachannel: label or protocol too long");
		enforce(openChannels.length + opening.length < maxChannels, "datachannel: too many channels");
		immutable id = nextFreeId();
		// Send before mutating state, so a throw (not established, buffer full)
		// leaves no phantom half-open channel or burned id.
		assoc.send(id, ppidDcep, encodeOpen(label, protocol));
		opening[id] = true;
		return id;
	}

	// The next unused stream id for our DTLS role: the client uses even ids
	// (skipping the reserved 0), the server odd, scanning past ids in use and
	// wrapping, so a long-lived connection reusing ids never collides.
	private ushort nextFreeId() @safe
	{
		foreach (_; 0 .. 32_768)
		{
			ushort id;
			if (role == Role.client)
			{
				id = nextEven;
				nextEven = nextEven >= 65_534 ? 2 : cast(ushort)(nextEven + 2);
			}
			else
			{
				id = nextOdd;
				nextOdd = nextOdd >= 65_535 ? 1 : cast(ushort)(nextOdd + 2);
			}
			if (id != 0 && !(id in openChannels) && !(id in opening))
				return id;
		}
		throw new Exception("datachannel: no free stream id");
	}

	/// Send a message on a channel. An empty message uses the RFC 8831 empty PPID
	/// with a single padding byte, since SCTP will not carry a zero-length DATA.
	void send(ushort id, scope const(ubyte)[] data, bool binary) @safe
	{
		// A channel we are still opening may already carry data (RFC 8832 §6
		// permits sending before the ACK), so accept `opening` too.
		enforce(id in openChannels || id in opening, "datachannel: send on a channel that is not open");
		if (data.length == 0)
			assoc.send(id, binary ? ppidBinaryEmpty : ppidStringEmpty, [cast(ubyte) 0]);
		else
			assoc.send(id, binary ? ppidBinary : ppidString, data);
	}

	/// Close a channel by resetting its SCTP stream.
	void close(ushort id, long now) @safe
	{
		if (id in openChannels)
			openChannels.remove(id);
		opening.remove(id);
		assoc.resetStream(id, now);
	}

	bool isOpen(ushort id) const @safe pure nothrow
	{
		return (id in openChannels) !is null;
	}

	/// Turn what the association delivered into channel events: DCEP OPEN/ACK are
	/// consumed here (and answered), application messages become message events,
	/// and a peer's stream reset becomes a closed event.
	ChannelEvent[] events() @safe
	{
		ChannelEvent[] evs;
		foreach (m; assoc.receive())
		{
			if (m.ppid == ppidDcep)
				handleDcep(m, evs);
			else if (m.streamId in openChannels)
				evs ~= messageEvent(m); // data only for a channel that is open
			// else: data on a stream that was never opened — drop it
		}
		foreach (s; assoc.takeResetStreams())
		{
			// Only a stream we knew as a channel produces a closed event.
			immutable known = (s in openChannels) !is null || (s in opening) !is null;
			openChannels.remove(s);
			opening.remove(s);
			if (known)
				evs ~= ChannelEvent(ChannelEventKind.closed, s);
		}
		return evs;
	}

	// --- DCEP ------------------------------------------------------------------------------

	private void handleDcep(ref Message m, ref ChannelEvent[] evs) @safe
	{
		if (m.data.length < 1)
			return;
		if (m.data[0] == dcepOpen)
		{
			if (m.streamId == 0)
				return; // id 0 is the negotiated channel; never DCEP-opened
			string label, protocol;
			if (!decodeOpen(m.data, label, protocol))
				return; // malformed: drop
			immutable alreadyOpen = (m.streamId in openChannels) !is null;
			openChannels[m.streamId] = true;
			ackOpen(m.streamId); // (re-)acknowledge; a lost ACK must be answerable
			if (!alreadyOpen) // a duplicate OPEN on a live channel does not re-open it
			{
				if (openChannels.length + opening.length <= maxChannels)
					evs ~= ChannelEvent(ChannelEventKind.opened, m.streamId, false, null,
						label, protocol, true); // remote = the peer opened this channel
			}
		}
		else if (m.data[0] == dcepAck)
		{
			if (m.streamId in opening)
			{
				opening.remove(m.streamId);
				openChannels[m.streamId] = true;
				evs ~= ChannelEvent(ChannelEventKind.opened, m.streamId);
			}
		}
	}

	// Acknowledge an OPEN. The ACK must never turn an inbound packet into a thrown
	// exception (Law 4): if the send buffer is full, drop it — the peer's DCEP
	// retransmit will prompt another ACK.
	private void ackOpen(ushort id) @safe
	{
		try
			assoc.send(id, ppidDcep, [dcepAck]);
		catch (Exception)
		{
		}
	}

	private ChannelEvent messageEvent(ref Message m) @safe
	{
		immutable binary = m.ppid == ppidBinary || m.ppid == ppidBinaryEmpty;
		immutable empty = m.ppid == ppidStringEmpty || m.ppid == ppidBinaryEmpty;
		return ChannelEvent(ChannelEventKind.message, m.streamId, binary, empty ? null : m.data);
	}

	private ubyte[] encodeOpen(string label, string protocol) @safe
	{
		ubyte[] v = new ubyte[12];
		v[0] = dcepOpen;
		v[1] = channelReliable;
		// Priority (2) and Reliability Parameter (4) are zero for a reliable
		// ordered channel; v[2..8] stay zero.
		writeBe16(v[8 .. 10], cast(ushort) label.length);
		writeBe16(v[10 .. 12], cast(ushort) protocol.length);
		v ~= cast(const(ubyte)[]) label;
		v ~= cast(const(ubyte)[]) protocol;
		return v;
	}

	private bool decodeOpen(scope const(ubyte)[] v, out string label, out string protocol) @safe
	{
		if (v.length < 12)
			return false;
		immutable labelLen = readBe16(v[8 .. 10]);
		immutable protoLen = readBe16(v[10 .. 12]);
		if (labelLen > maxLabelLen || protoLen > maxLabelLen)
			return false;
		if (12 + labelLen + protoLen > v.length)
			return false;
		label = cast(string) v[12 .. 12 + labelLen].idup;
		protocol = cast(string) v[12 + labelLen .. 12 + labelLen + protoLen].idup;
		return true;
	}
}

private ushort readBe16(scope const(ubyte)[] b) @safe pure nothrow @nogc
{
	return cast(ushort)((b[0] << 8) | b[1]);
}

private void writeBe16(ubyte[] b, ushort v) @safe pure nothrow @nogc
{
	b[0] = cast(ubyte)(v >> 8);
	b[1] = cast(ubyte)(v & 0xff);
}
