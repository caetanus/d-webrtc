module tests.datachannel.channel_test;

import webrtc.sctp.association : Association, Side;
import webrtc.datachannel.channel;
import webrtc.datachannel.message : ChannelType;
import fluent.asserts : should;

// Bring two associations to Established, then drive the DCEP managers on top:
// each round shuttles SCTP packets both ways and lets each manager process what
// its association delivered (running the DCEP handshake and queuing user data).
private struct Link
{
	Association ca, sa;
	DataChannels c, s;

	static Link make()
	{
		Link l;
		l.ca = new Association(Side.client, 0x1111_1111, 100, 0);
		l.sa = new Association(Side.server, 0x2222_2222, 200, 0);
		foreach (_; 0 .. 8) // handshake
		{
			foreach (p; l.ca.gatherOutbound(0))
				l.sa.handleInbound(p, 0);
			foreach (p; l.sa.gatherOutbound(0))
				l.ca.handleInbound(p, 0);
			if (l.ca.isEstablished && l.sa.isEstablished)
				break;
		}
		l.c = new DataChannels(l.ca, Side.client);
		l.s = new DataChannels(l.sa, Side.server);
		return l;
	}

	void pump(int rounds = 16)
	{
		foreach (_; 0 .. rounds)
		{
			bool moved;
			foreach (p; ca.gatherOutbound(0))
			{
				sa.handleInbound(p, 0);
				moved = true;
			}
			foreach (p; sa.gatherOutbound(0))
			{
				ca.handleInbound(p, 0);
				moved = true;
			}
			c.poll();
			s.poll();
			if (!moved)
				break;
		}
	}
}

@("DCEP OPEN/ACK handshake opens a channel on both ends")
unittest
{
	auto l = Link.make();
	l.ca.isEstablished.should.equal(true);

	DataChannelConfig cfg;
	cfg.label = "chat";
	cfg.protocol = "proto";
	immutable sid = l.c.open(cfg);
	l.pump();

	// Server saw the incoming channel and both sides consider it open.
	l.s.takeAccepted().should.equal([sid]);
	l.c.channelState(sid).should.equal(ChannelState.open);
	l.s.channelState(sid).should.equal(ChannelState.open);
}

@("data channel carries string messages both ways after DCEP")
unittest
{
	auto l = Link.make();
	immutable sid = l.c.open(DataChannelConfig("chat", "proto"));
	l.pump();

	l.c.send(sid, cast(ubyte[]) "hi from client".dup, true);
	l.s.send(sid, cast(ubyte[]) "hi from server".dup, true);
	l.pump();

	auto atServer = l.s.receive();
	auto atClient = l.c.receive();
	atServer.isNull.should.equal(false);
	atClient.isNull.should.equal(false);
	atServer.get.isString.should.equal(true);
	(cast(string) atServer.get.data).should.equal("hi from client");
	(cast(string) atClient.get.data).should.equal("hi from server");
}

@("data channel delivers an empty message via the WebRTC empty PPID")
unittest
{
	auto l = Link.make();
	immutable sid = l.c.open(DataChannelConfig("d", ""));
	l.pump();

	l.c.send(sid, [], false); // empty binary message
	l.pump();

	auto m = l.s.receive();
	m.isNull.should.equal(false);
	m.get.isString.should.equal(false);
	m.get.data.length.should.equal(cast(size_t) 0); // received as truly empty
}
