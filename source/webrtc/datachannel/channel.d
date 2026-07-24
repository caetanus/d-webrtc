/**
 * Data channels over SCTP — the DCEP (RFC 8832) handshake and user-message
 * routing that turn an established SCTP association into WebRTC data channels.
 *
 * Laundered from webrtc-rs's rtc-datachannel `data_channel/mod.rs`, distilled to
 * a sans-io manager: it owns an [`Association`], opens channels (sending
 * DATA_CHANNEL_OPEN), accepts incoming ones (replying DATA_CHANNEL_ACK), and
 * maps user data to/from the right SCTP stream with the WebRTC PPIDs. Call
 * `poll()` after each association pump to advance the DCEP state and collect
 * delivered messages.
 *
 * Stream-identifier parity follows RFC 8832 §6: the side that will be the DTLS
 * client uses even stream ids, the DTLS server odd. DTLS role is not wired yet,
 * so we map Side.client → even and Side.server → odd (the usual convention).
 */
module webrtc.datachannel.channel;

import std.typecons : Nullable, nullable;

import webrtc.sctp.association : Association, Side, InboundMessage;
import webrtc.sctp.chunk.data : PPID_DCEP, PPID_STRING, PPID_BINARY,
	PPID_STRING_EMPTY, PPID_BINARY_EMPTY;
import webrtc.datachannel.message : DataChannelOpen, ChannelType, MESSAGE_TYPE_OPEN,
	marshalAck, isAck;

/// A data channel's DCEP lifecycle state.
enum ChannelState
{
	connecting, // OPEN sent, awaiting ACK (or OPEN received, ACK sent)
	open,
	closed,
}

/// How a channel should be opened (RFC 8832 §5.1).
struct DataChannelConfig
{
	string label;
	string protocol;
	bool ordered = true;
	ChannelType channelType = ChannelType.reliable;
	ushort priority;
	uint reliabilityParameter;
}

/// A user message delivered on a channel.
struct ChannelMessage
{
	ushort streamId;
	bool isString; // true = UTF-8 string channel, false = binary
	ubyte[] data; // empty for the WebRTC "empty message" PPIDs
}

/// Drives DCEP and user-data routing over a single SCTP association.
final class DataChannels
{
	private Association assoc;
	private ushort nextStreamId;
	private ChannelState[ushort] channels;
	private DataChannelConfig[ushort] configs;
	private ChannelMessage[] inbound;
	private ushort[] accepted; // stream ids of newly accepted incoming channels

	this(Association assoc, Side side)
	{
		this.assoc = assoc;
		// DTLS-client parity = even, DTLS-server parity = odd (RFC 8832 §6).
		this.nextStreamId = side == Side.client ? 0 : 1;
	}

	/// Open a new outgoing channel. Allocates a stream id, sends a
	/// DATA_CHANNEL_OPEN, and returns the stream id (the channel handle).
	ushort open(DataChannelConfig cfg)
	{
		immutable sid = nextStreamId;
		nextStreamId += 2;

		DataChannelOpen o;
		o.channelType = cfg.channelType;
		o.priority = cfg.priority;
		o.reliabilityParameter = cfg.reliabilityParameter;
		o.label = cast(ubyte[]) cfg.label.dup;
		o.protocol = cast(ubyte[]) cfg.protocol.dup;

		// DCEP messages MUST be ordered + reliable (RFC 8832 §6).
		assoc.send(sid, PPID_DCEP, o.marshal, true);
		channels[sid] = ChannelState.connecting;
		configs[sid] = cfg;
		return sid;
	}

	/// Send a user message on an open channel. `isString` selects the string vs
	/// binary PPID; an empty payload uses the WebRTC "empty" PPID with a single
	/// zero byte on the wire (SCTP forbids truly empty user messages).
	void send(ushort sid, scope const(ubyte)[] data, bool isString)
	{
		uint ppid;
		if (isString)
			ppid = data.length ? PPID_STRING : PPID_STRING_EMPTY;
		else
			ppid = data.length ? PPID_BINARY : PPID_BINARY_EMPTY;

		auto payload = data.length ? data.dup : cast(ubyte[])[0];
		immutable ordered = configs.get(sid, DataChannelConfig.init).ordered;
		assoc.send(sid, ppid, payload, ordered);
	}

	/// Drain everything the association has delivered: run the DCEP handshake for
	/// control messages, and queue user messages for `receive`. Call this after
	/// each association pump.
	void poll()
	{
		for (auto m = assoc.receive(); !m.isNull; m = assoc.receive())
		{
			auto msg = m.get;
			if (msg.ppid == PPID_DCEP)
				handleDcep(msg.streamId, msg.data);
			else
				inbound ~= toChannelMessage(msg);
		}
	}

	/// Pop the next delivered user message, or null if none is ready.
	Nullable!ChannelMessage receive() @safe pure nothrow
	{
		if (inbound.length == 0)
			return Nullable!ChannelMessage.init;
		auto m = inbound[0];
		inbound = inbound[1 .. $];
		return nullable(m);
	}

	/// Drain the stream ids of channels accepted (opened by the peer) since the
	/// last call.
	ushort[] takeAccepted() @safe pure nothrow
	{
		auto a = accepted;
		accepted = [];
		return a;
	}

	/// The DCEP state of a channel (closed if unknown).
	ChannelState channelState(ushort sid) const @safe
	{
		if (auto s = sid in channels)
			return *s;
		return ChannelState.closed;
	}

	// ---- internals ------------------------------------------------------------

	private void handleDcep(ushort sid, ubyte[] data)
	{
		if (data.length && data[0] == MESSAGE_TYPE_OPEN)
		{
			// Incoming channel: adopt its parameters, become open, reply ACK.
			auto o = DataChannelOpen.unmarshal(data);
			DataChannelConfig cfg;
			cfg.channelType = o.channelType;
			cfg.priority = o.priority;
			cfg.reliabilityParameter = o.reliabilityParameter;
			cfg.label = cast(string) o.label.idup;
			cfg.protocol = cast(string) o.protocol.idup;
			cfg.ordered = (o.channelType & 0x80) == 0;
			configs[sid] = cfg;
			channels[sid] = ChannelState.open;
			accepted ~= sid;
			assoc.send(sid, PPID_DCEP, marshalAck(), true);
		}
		else if (isAck(data))
		{
			// Our OPEN was accepted.
			channels[sid] = ChannelState.open;
		}
	}

	private static ChannelMessage toChannelMessage(InboundMessage msg) @safe pure nothrow
	{
		immutable isString = msg.ppid == PPID_STRING || msg.ppid == PPID_STRING_EMPTY;
		immutable isEmpty = msg.ppid == PPID_STRING_EMPTY || msg.ppid == PPID_BINARY_EMPTY;
		return ChannelMessage(msg.streamId, isString, isEmpty ? [] : msg.data);
	}
}
