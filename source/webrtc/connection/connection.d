/**
 * The webrtc-direct connection, sans-io: the four layers assembled into one
 * object the caller drives with datagrams and a clock. It owns no socket and no
 * fiber — the consumer (libp2p-dlang) reads UDP, calls handleInbound, and writes
 * whatever gatherOutbound returns.
 *
 * Inbound datagrams on the one path are demultiplexed by their first bits: a
 * STUN message goes to the ICE agent, anything else is DTLS ciphertext. The
 * handshake climbs the layers in order — ICE nominates a pair, DTLS 1.2 runs over
 * it, the peer's certificate fingerprint is pinned against the expected certhash,
 * then SCTP comes up inside DTLS and the negotiated data channel (id 0, libp2p's
 * Noise channel) opens. SCTP packets are DTLS-encrypted on the way out and
 * decrypted on the way in; ICE checks and DTLS records share the path.
 *
 * Perspective fixes every role at once: the dialer is ICE-controlling, the DTLS
 * client and the SCTP client; the listener is their opposites.
 *
 * Closing is sequenced: SCTP shuts down (draining data) and then DTLS sends its
 * close_notify, so the peer sees an orderly end rather than a dropped path.
 */
module webrtc.connection.connection;

import webrtc.dtls.certificate : Certificate;
import webrtc.dtls.transport : DtlsTransport, DtlsRole;
import webrtc.datachannel.channels : DataChannels, ChannelEvent, ChannelEventKind;
import webrtc.ice.agent : Agent, IceRole = Role, Credentials, TransportAddr, ConnectionState;
import webrtc.ice.candidate : Candidate;
import webrtc.sctp.association : Association, SctpRole = Role, AssocState;


enum Perspective
{
	dialer, // ICE controlling, DTLS client, SCTP client
	listener, // ICE controlled, DTLS server, SCTP server
}

enum ConnState
{
	connecting,
	connected,
	closing,
	closed,
	failed,
}

/// A datagram to send to `dst` on the shared path.
struct OutboundDatagram
{
	TransportAddr dst;
	ubyte[] data;
}

/// The negotiated data channel libp2p runs its Noise handshake over.
enum ushort noiseChannel = 0;

final class Connection
{
	private Perspective perspective;
	private TransportAddr local;
	private Agent ice;
	private Certificate cert;
	private DtlsTransport dtls;
	private Association assoc;
	private DataChannels dc;

	private ConnState st = ConnState.connecting;
	private bool haveExpectedFp;
	private ubyte[32] expectedFp;
	private bool dtlsDriving; // ICE has a pair; DTLS may run
	private bool fingerprintPinned;
	private bool sctpStarted;
	private bool negotiatedOpened;
	private bool closeRequested;
	private ChannelEvent[] pendingEvents;

	this(Perspective p, Certificate cert, TransportAddr local, Credentials localCreds,
		ulong iceTiebreaker) @safe
	{
		this.perspective = p;
		this.local = local;
		this.cert = cert;
		this.ice = new Agent(p == Perspective.dialer ? IceRole.controlling : IceRole.controlled,
			localCreds, iceTiebreaker);
		this.dtls = new DtlsTransport(p == Perspective.dialer ? DtlsRole.client : DtlsRole.server,
			cert);
		this.assoc = new Association(p == Perspective.dialer ? SctpRole.client : SctpRole.server,
			5000, 5000);
		this.dc = new DataChannels(assoc, p == Perspective.dialer ? SctpRole.client : SctpRole.server);
	}

	// --- setup ------------------------------------------------------------------------------

	void addLocalCandidate(Candidate c) @safe
	{
		ice.addLocalCandidate(c);
	}

	void addRemoteCandidate(Candidate c) @safe
	{
		ice.addRemoteCandidate(c);
	}

	void setRemoteCredentials(Credentials c) @safe
	{
		ice.setRemoteCredentials(c);
	}

	/// Pin the peer to this SHA-256 certificate fingerprint (the certhash from the
	/// remote multiaddr). Without it the DTLS peer is accepted unpinned.
	void setExpectedFingerprint(ubyte[32] fp) @safe
	{
		expectedFp = fp;
		haveExpectedFp = true;
	}

	/// Our certificate fingerprint, to advertise as our certhash.
	ubyte[32] localFingerprint() @safe
	{
		return cert.sha256Fingerprint();
	}

	/// The peer's certificate fingerprint (valid once connected). The listener
	/// uses it to name the remote; the dialer already pinned it.
	ubyte[32] peerFingerprint() @safe
	{
		return dtls.peerFingerprint();
	}

	// --- observation ------------------------------------------------------------------------

	ConnState state() const @safe pure nothrow @nogc
	{
		return st;
	}

	DataChannels channels() @safe pure nothrow @nogc
	{
		return dc;
	}

	/// Channel events (opened / message / closed) since the last call.
	ChannelEvent[] poll() @safe
	{
		auto e = pendingEvents;
		pendingEvents = null;
		return e;
	}

	// --- the sans-io surface ----------------------------------------------------------------

	void handleInbound(scope const(ubyte)[] datagram, TransportAddr from, long now) @safe
	{
		import webrtc.stun.message : isStunMessage;

		if (isStunMessage(datagram))
			ice.handleInbound(datagram, from, local, now);
		else if (dtlsDriving)
		{
			dtls.feedInbound(datagram);
			pumpSctpIn(now);
		}
		advance(now);
	}

	OutboundDatagram[] gatherOutbound(long now) @safe
	{
		advance(now);
		OutboundDatagram[] outs;
		foreach (o; ice.gatherOutbound(now))
			outs ~= OutboundDatagram(o.dst, o.data);
		if (dtlsDriving)
			foreach (rec; dtls.takeOutbound())
				outs ~= OutboundDatagram(remoteAddr(), rec);
		return outs;
	}

	void handleTimeout(long now) @safe
	{
		ice.handleTimeout(now);
		if (dtlsDriving && !dtls.isHandshakeComplete)
			dtls.handleTimeout(); // retransmit a lost DTLS handshake flight
		advance(now);
	}

	/// Begin a graceful close: SCTP shuts down, then DTLS close_notify. Called
	/// before SCTP is up, it ends the connection at once.
	void close(long now) @safe
	{
		if (st == ConnState.closed || st == ConnState.failed)
			return;
		closeRequested = true;
		st = ConnState.closing;
		if (assoc.isEstablished)
			assoc.shutdown(now); // drain then SHUTDOWN
		else if (sctpStarted)
			assoc.abort(); // SCTP still coming up: abort it rather than wait
		advance(now);
	}

	/// Close at once: abort SCTP and send a DTLS close_notify immediately, so a
	/// peer that is leaving (e.g. a process exiting) tells the far end to tear the
	/// connection down now rather than after a timeout. The close_notify surfaces
	/// through the next gatherOutbound.
	void closeNow() @safe
	{
		if (st == ConnState.closed || st == ConnState.failed)
			return;
		if (sctpStarted)
			assoc.abort();
		if (dtlsDriving && dtls.isHandshakeComplete)
			dtls.close(); // close_notify
		st = ConnState.closed;
	}

	// --- state machine ----------------------------------------------------------------------

	private void advance(long now) @safe
	{
		if (st == ConnState.closed || st == ConnState.failed)
			return;

		if (ice.connectionState == ConnectionState.failed)
		{
			st = ConnState.failed;
			return;
		}

		// Terminal close: finish as soon as SCTP is done (or never started), so a
		// close during ICE/DTLS/SCTP-handshake reaches Closed instead of hanging.
		if (st == ConnState.closing && (!sctpStarted || assoc.state == AssocState.closed
				|| assoc.state == AssocState.failed))
		{
			if (dtlsDriving && dtls.isHandshakeComplete)
				dtls.close();
			st = ConnState.closed;
			return;
		}

		// ICE has selected a pair: DTLS may now run over it.
		if (!dtlsDriving && ice.isConnected)
		{
			dtlsDriving = true;
		}

		if (dtlsDriving && !dtls.isHandshakeComplete)
		{
			try
				dtls.handshake();
			catch (Exception)
			{
				st = ConnState.failed;
				return;
			}
		}

		// DTLS just completed: pin the peer fingerprint, then bring SCTP up. An
		// absent expected fingerprint FAILS the connection — webrtc-direct's
		// certhash is mandatory, and law 5 owns the comparison (fail closed).
		if (dtlsDriving && dtls.isHandshakeComplete && !fingerprintPinned)
		{
			fingerprintPinned = true;
			// The dialer MUST pin — webrtc-direct puts the server's certhash in the
			// address, so an absent expected fingerprint is a fail-closed error. The
			// listener has no certhash for the client (the client's libp2p identity
			// is proven later over Noise), so it accepts the peer cert unpinned.
			if (haveExpectedFp)
			{
				if (!dtls.verifyPeerFingerprint(expectedFp))
				{
					st = ConnState.failed;
					return;
				}
			}
			else if (perspective == Perspective.dialer)
			{
				st = ConnState.failed;
				return;
			}
			sctpStarted = true;
			if (perspective == Perspective.dialer && !closeRequested)
				assoc.connect(now);
		}

		if (sctpStarted)
		{
			pumpSctpIn(now); // drain any app-data buffered behind the Finished record
			assoc.handleTimeout(now);

			if (assoc.isEstablished && !negotiatedOpened)
			{
				negotiatedOpened = true;
				dc.openNegotiated(noiseChannel);
				pendingEvents ~= ChannelEvent(ChannelEventKind.opened, noiseChannel);
				if (st == ConnState.connecting)
					st = ConnState.connected;
			}

			// Move SCTP output out through DTLS.
			foreach (pkt; assoc.takeOutbound(now))
				dtls.write(pkt);

			if (assoc.state == AssocState.failed)
				st = ConnState.failed;
		}

		// Surface any channel events the association delivered.
		if (negotiatedOpened)
			pendingEvents ~= dc.events();
	}

	// Decrypt DTLS app-data records into SCTP packets.
	private void pumpSctpIn(long now) @safe
	{
		if (!dtls.isHandshakeComplete)
			return;
		while (true)
		{
			auto rec = dtls.read();
			if (rec.length == 0)
				break;
			assoc.handleInbound(rec, now);
		}
	}

	private TransportAddr remoteAddr() @safe
	{
		TransportAddr l, r;
		if (ice.selectedPair(l, r))
			return r;
		return TransportAddr.init;
	}
}
