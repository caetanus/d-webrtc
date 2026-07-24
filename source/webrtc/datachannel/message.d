/**
 * DCEP — the Data Channel Establishment Protocol (RFC 8832). These are the
 * control messages sent over the reserved SCTP stream (PPID 50, DCEP) to open a
 * WebRTC data channel: DATA_CHANNEL_OPEN and its DATA_CHANNEL_ACK.
 *
 * Laundered from webrtc-rs's rtc-datachannel `message/*`. Self-contained: it sits
 * above SCTP and just marshals/parses these messages; the association delivers
 * them as PPID-50 user data.
 */
module webrtc.datachannel.message;

import std.exception : enforce;

/// DCEP message types (the first byte of a DCEP message).
enum ubyte MESSAGE_TYPE_ACK = 0x02;
enum ubyte MESSAGE_TYPE_OPEN = 0x03;

/// Channel type / reliability (RFC 8832 §5.1). The 0x80 bit marks unordered.
enum ChannelType : ubyte
{
	reliable = 0x00,
	reliableUnordered = 0x80,
	partialReliableRexmit = 0x01,
	partialReliableRexmitUnordered = 0x81,
	partialReliableTimed = 0x02,
	partialReliableTimedUnordered = 0x82,
}

private enum size_t OPEN_HEADER_LEN = 12; // msgtype(1)+chtype(1)+prio(2)+rel(4)+labelLen(2)+protoLen(2)

/// A DATA_CHANNEL_OPEN message.
struct DataChannelOpen
{
	ChannelType channelType;
	ushort priority;
	uint reliabilityParameter;
	ubyte[] label;
	ubyte[] protocol;

	/// Marshal to the full DCEP message (leading message-type byte included).
	ubyte[] marshal() const @safe pure
	{
		enforce(label.length <= ushort.max && protocol.length <= ushort.max,
			"dcep: label/protocol too long");
		ubyte[] b;
		b ~= MESSAGE_TYPE_OPEN;
		b ~= cast(ubyte) channelType;
		b ~= [cast(ubyte)(priority >> 8), cast(ubyte)(priority & 0xff)];
		b ~= [cast(ubyte)(reliabilityParameter >> 24), cast(ubyte)(reliabilityParameter >> 16),
			cast(ubyte)(reliabilityParameter >> 8), cast(ubyte)(reliabilityParameter & 0xff)];
		b ~= [cast(ubyte)(label.length >> 8), cast(ubyte)(label.length & 0xff)];
		b ~= [cast(ubyte)(protocol.length >> 8), cast(ubyte)(protocol.length & 0xff)];
		b ~= label;
		b ~= protocol;
		return b;
	}

	/// Parse a DATA_CHANNEL_OPEN message (including its leading type byte).
	static DataChannelOpen unmarshal(scope const(ubyte)[] data) @safe pure
	{
		enforce(data.length >= OPEN_HEADER_LEN, "dcep: OPEN too short");
		enforce(data[0] == MESSAGE_TYPE_OPEN, "dcep: not a DATA_CHANNEL_OPEN");
		DataChannelOpen o;
		o.channelType = cast(ChannelType) data[1];
		o.priority = cast(ushort)((data[2] << 8) | data[3]);
		o.reliabilityParameter = (cast(uint) data[4] << 24) | (cast(uint) data[5] << 16)
			| (cast(uint) data[6] << 8) | data[7];
		immutable labelLen = (data[8] << 8) | data[9];
		immutable protoLen = (data[10] << 8) | data[11];
		enforce(OPEN_HEADER_LEN + labelLen + protoLen <= data.length, "dcep: OPEN truncated");
		o.label = data[OPEN_HEADER_LEN .. OPEN_HEADER_LEN + labelLen].dup;
		o.protocol = data[OPEN_HEADER_LEN + labelLen .. OPEN_HEADER_LEN + labelLen + protoLen].dup;
		return o;
	}
}

/// Marshal a DATA_CHANNEL_ACK message.
ubyte[] marshalAck() @safe pure nothrow
{
	return [MESSAGE_TYPE_ACK];
}

/// Whether `data` is a DATA_CHANNEL_ACK.
bool isAck(scope const(ubyte)[] data) @safe pure nothrow @nogc
{
	return data.length >= 1 && data[0] == MESSAGE_TYPE_ACK;
}
