/**
 * PeerConnection — the WebRTC transport stack assembled into one sans-io driver.
 * It stacks the four layers this library provides and shuttles data between
 * them, so a caller deals only with UDP datagrams below and data channels above:
 *
 *     DataChannels (DCEP)            — application messages
 *        │  association.send / receive
 *     SCTP Association               — reliable, multiplexed streams
 *        │  runs *inside* DTLS: assoc bytes ⇄ dtls app-data
 *     DTLS transport                 — encryption, cert-fingerprint pinning
 *        │  ciphertext datagrams
 *     ICE Agent                      — connectivity over UDP host candidates
 *        │  STUN, multiplexed on the same path as DTLS
 *     UDP (the caller's socket)
 *
 * On the wire, ICE's STUN and DTLS's ciphertext share the one selected path and
 * are demultiplexed by `isStunMessage`. Everything is sans-io: feed inbound
 * datagrams with `handleDatagram`, drain outbound with `gatherOutbound`, and
 * pass `now` (ms) for timers. Roles follow the libp2p webrtc-direct convention:
 * the dialer is ICE-controlling / DTLS-client / SCTP-client, the listener the
 * mirror.
 */
module webrtc.connection;

import std.typecons : Nullable;

import libsodium : randombytes_random;

import webrtc.stun.message : isStunMessage;
import webrtc.ice.agent : Agent, Credentials, TransportAddr, OutboundStun;
import webrtc.ice.attributes : Role;
import webrtc.ice.candidate : Candidate;
import webrtc.dtls.certificate : Certificate;
import webrtc.dtls.transport : DtlsTransport, DtlsRole;
import webrtc.sctp.association : Association, Side;
import webrtc.datachannel.channel : DataChannels, DataChannelConfig, ChannelMessage;

/// Which end of the connection this is (fixes every layer's role).
enum Perspective
{
	dialer, // ICE-controlling, DTLS-client, SCTP-client
	listener,
}

/// An outbound UDP datagram: `data` to send from local address `src` to `dst`.
struct Datagram
{
	TransportAddr src;
	TransportAddr dst;
	ubyte[] data;
}

/// The assembled WebRTC transport for one peer.
final class PeerConnection
{
	private Perspective perspective;
	private Agent ice;
	private DtlsTransport dtls;
	private Certificate cert;
	private Association sctp;
	private DataChannels channels_;

	private bool dtlsStarted;
	private bool sctpStarted;
	private TransportAddr localAddr;
	private TransportAddr remoteAddr;
	private Datagram[] outQueue;

	this(Perspective p, Credentials localIce, ulong tieBreaker, Certificate certificate)
	{
		perspective = p;
		cert = certificate;
		immutable role = p == Perspective.dialer ? Role.controlling : Role.controlled;
		ice = new Agent(role, localIce, tieBreaker);
	}

	// ---- setup ----------------------------------------------------------------

	void addLocalCandidate(Candidate c)
	{
		ice.addLocalCandidate(c);
	}

	void setRemoteIce(Credentials remote, Candidate remoteCandidate)
	{
		ice.setRemoteCredentials(remote);
		ice.addRemoteCandidate(remoteCandidate);
	}

	// ---- observation ----------------------------------------------------------

	bool iceConnected() const
	{
		return ice.isConnected;
	}

	bool dtlsConnected() const
	{
		return dtls !is null && dtls.isConnected;
	}

	/// Whether the SCTP association has finished its handshake — the point at
	/// which data channels can carry messages.
	bool isReady() const
	{
		return sctp !is null && sctp.isEstablished;
	}

	/// The DTLS peer certificate fingerprint (for certhash pinning). Only valid
	/// once DTLS has connected.
	ubyte[32] peerFingerprint()
	{
		return dtls.peerFingerprint();
	}

	/// The data-channel manager (valid once DTLS is up and SCTP has started).
	DataChannels channels()
	{
		return channels_;
	}

	// ---- sans-io surface ------------------------------------------------------

	/// Feed an inbound UDP datagram that arrived at `to` from `from`.
	void handleDatagram(scope const(ubyte)[] data, TransportAddr from, TransportAddr to, long now)
	{
		if (isStunMessage(data))
		{
			ice.handleInbound(data, from, to, now);
			return;
		}
		if (!dtlsStarted)
			return; // DTLS not up yet — drop stray ciphertext
		dtls.feed(data);
		if (!dtls.isConnected)
			dtls.handshake();
		pumpDtlsInbound(now);
	}

	/// Drive every layer and drain the datagrams to put on the wire.
	Datagram[] gatherOutbound(long now)
	{
		// 1. ICE connectivity checks.
		foreach (o; ice.gatherOutbound(now))
			outQueue ~= Datagram(o.src, o.dst, o.data);

		// 2. Once ICE selects a pair, bring up DTLS over it.
		if (ice.isConnected && !dtlsStarted)
			startDtls();
		if (dtlsStarted && !dtls.isConnected)
			dtls.handshake();

		// 3. Once DTLS is up, run SCTP inside it.
		if (dtlsStarted && dtls.isConnected && !sctpStarted)
			startSctp(now);
		if (sctpStarted)
		{
			channels_.poll();
			foreach (pkt; sctp.gatherOutbound(now))
				dtls.send(pkt); // SCTP packet -> DTLS app-data (ciphertext in wbio)
		}

		// 4. Drain all DTLS ciphertext (handshake records + encrypted SCTP) as
		// datagrams on the selected path.
		if (dtlsStarted)
			foreach (d; dtls.gatherOutbound())
				outQueue ~= Datagram(localAddr, remoteAddr, d);

		auto outs = outQueue;
		outQueue = [];
		return outs;
	}

	// ---- internals ------------------------------------------------------------

	private void startDtls()
	{
		auto pair = ice.selectedPair();
		if (pair.isNull)
			return;
		localAddr = pair.get[0];
		remoteAddr = pair.get[1];
		immutable role = perspective == Perspective.dialer ? DtlsRole.client : DtlsRole.server;
		dtls = new DtlsTransport(role, cert);
		dtlsStarted = true;
		dtls.handshake(); // client emits the ClientHello here
	}

	private void startSctp(long now)
	{
		immutable side = perspective == Perspective.dialer ? Side.client : Side.server;
		// Non-zero verification tag and initial TSN, per RFC 4960.
		immutable tag = randNonZero();
		immutable tsn = randNonZero();
		sctp = new Association(side, tag, tsn, now);
		channels_ = new DataChannels(sctp, side);
		sctpStarted = true;
	}

	// Decrypt and dispatch any DTLS application data (SCTP packets) waiting.
	private void pumpDtlsInbound(long now)
	{
		if (!dtls.isConnected)
			return;
		if (dtlsStarted && dtls.isConnected && !sctpStarted)
			startSctp(now);
		for (auto m = dtls.receive(); m.length != 0; m = dtls.receive())
			sctp.handleInbound(m, now);
		if (sctpStarted)
			channels_.poll();
	}

	private static uint randNonZero()
	{
		auto v = randombytes_random();
		return v == 0 ? 1 : v;
	}
}
