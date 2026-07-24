/**
 * ICE agent — the connectivity-check state machine (RFC 8445 §7) distilled to
 * the webrtc-direct subset: UDP *host* candidates only, short-term credentials
 * (ufrag/pwd), a controlling and a controlled role, STUN Binding checks secured
 * by MESSAGE-INTEGRITY + FINGERPRINT, and USE-CANDIDATE nomination yielding a
 * selected pair.
 *
 * Laundered from webrtc-rs's rtc-ice `agent/mod.rs` + `agent_selector.rs`,
 * distilled hard: no gathering/mDNS/TURN/srflx/relay/ICE-TCP, no role-conflict
 * switching (the libp2p webrtc-direct handshake fixes the roles — dialer
 * controlling, listener controlled — so a conflict never arises), no keepalive.
 *
 * Sans-io, like the SCTP association: feed inbound STUN with `handleInbound`
 * (tagged with the transport addresses it arrived on), drain outbound STUN with
 * `gatherOutbound`, and drive checks with `now` (caller-supplied ms). The driver
 * owns the sockets; this owns only the protocol.
 */
module webrtc.ice.agent;

import std.typecons : Nullable, nullable, tuple;

import libsodium : randombytes_buf;

import webrtc.stun.message : Message, Attribute, TransactionId, TRANSACTION_ID_SIZE,
	BINDING_REQUEST, BINDING_SUCCESS_RESPONSE, ATTR_XOR_MAPPED_ADDRESS, isStunMessage;
import webrtc.stun.xoraddr : XorMappedAddress;
import webrtc.ice.attributes : Role, addPriority, getPriority, addUseCandidate, hasUseCandidate,
	addControl, addUsername, getUsername;
import webrtc.ice.candidate : Candidate, CandidateType;

/// A transport address (IP + UDP port) — how the driver tags STUN packets.
struct TransportAddr
{
	string ip;
	ushort port;

	bool opEquals(const TransportAddr o) const @safe pure nothrow @nogc scope
	{
		return port == o.port && ip == o.ip;
	}

	size_t toHash() const @safe pure nothrow @nogc scope
	{
		return (cast(size_t) port << 1) ^ ip.hashOf;
	}
}

/// Short-term ICE credentials (RFC 8445 §7.2.2): the ufrag/pwd pair exchanged
/// out of band (in libp2p, via the SDP munged from the Noise handshake).
struct Credentials
{
	string ufrag;
	string pwd;
}

/// The overall connectivity state of the agent (a lean subset of RFC 8445's).
enum ConnectionState
{
	newState,
	checking,
	connected,
	closed,
}

private enum PairState
{
	waiting,
	inProgress,
	succeeded,
	failed,
}

private struct Pair
{
	size_t local;
	size_t remote;
	PairState state = PairState.waiting;
	bool nominated;
}

private struct PendingRequest
{
	TransactionId id;
	TransportAddr destination;
	bool isUseCandidate;
	long timestamp;
}

/// A STUN packet to send: `src` is the local candidate it leaves from, `dst` the
/// remote address it goes to.
struct OutboundStun
{
	TransportAddr src;
	TransportAddr dst;
	ubyte[] data;
}

/// A single ICE agent.
final class Agent
{
	private Role role;
	private ulong tieBreaker;
	private Credentials localCreds;
	private Nullable!Credentials remoteCreds;

	private Candidate[] localCands;
	private Candidate[] remoteCands;
	private Pair[] pairs;
	private PendingRequest[] pending;
	private Nullable!size_t selected;
	private bool nominationInFlight;

	private ConnectionState state_ = ConnectionState.newState;
	private OutboundStun[] outQueue;
	private ConnectionState[] events;

	this(Role role, Credentials local, ulong tieBreaker)
	{
		this.role = role;
		this.localCreds = local;
		this.tieBreaker = tieBreaker;
	}

	// ---- configuration --------------------------------------------------------

	void addLocalCandidate(Candidate c) @safe pure nothrow
	{
		localCands ~= c;
	}

	void setRemoteCredentials(Credentials c) @safe pure nothrow
	{
		remoteCreds = c;
	}

	/// Add a remote candidate and form a pair with every local candidate.
	void addRemoteCandidate(Candidate c) @safe pure nothrow
	{
		immutable ri = remoteCands.length;
		remoteCands ~= c;
		foreach (li; 0 .. localCands.length)
			pairs ~= Pair(li, ri);
		if (state_ == ConnectionState.newState)
			setState(ConnectionState.checking);
	}

	// ---- observation ----------------------------------------------------------

	ConnectionState connectionState() const @safe pure nothrow @nogc
	{
		return state_;
	}

	bool isConnected() const @safe pure nothrow @nogc
	{
		return state_ == ConnectionState.connected;
	}

	/// The selected local/remote transport addresses, once connected.
	Nullable!(TransportAddr[2]) selectedPair() const @safe pure nothrow
	{
		if (selected.isNull)
			return Nullable!(TransportAddr[2]).init;
		auto p = pairs[selected.get];
		TransportAddr[2] addrs = [candAddr(localCands[p.local]), candAddr(remoteCands[p.remote])];
		return nullable(addrs);
	}

	/// Drain a connection-state-change event, or null if none pending.
	Nullable!ConnectionState pollEvent() @safe pure nothrow
	{
		if (events.length == 0)
			return Nullable!ConnectionState.init;
		auto e = events[0];
		events = events[1 .. $];
		return nullable(e);
	}

	// ---- sans-io surface ------------------------------------------------------

	/// Drive connectivity checks (send/retransmit/nominate) and drain the STUN
	/// packets the agent wants to send.
	OutboundStun[] gatherOutbound(long now)
	{
		contact(now);
		auto outs = outQueue;
		outQueue = [];
		return outs;
	}

	/// Feed an inbound STUN packet that arrived at local address `to` from `from`.
	void handleInbound(scope const(ubyte)[] data, TransportAddr from, TransportAddr to, long now)
	{
		if (!isStunMessage(data))
			return;
		Message m;
		try
			m = Message.decode(data);
		catch (Exception)
			return;

		immutable li = findLocalCandidate(to);
		if (li.isNull)
			return;

		if (remoteCreds.isNull)
			return;

		if (m.typ == BINDING_SUCCESS_RESPONSE)
		{
			if (!m.checkMessageIntegrity(strKey(remoteCreds.get.pwd)))
				return;
			auto ri = findRemoteCandidate(from);
			if (ri.isNull)
				return;
			handleSuccessResponse(m, li.get, ri.get, from);
		}
		else if (m.typ == BINDING_REQUEST)
		{
			// Validate USERNAME (localUfrag:remoteUfrag) and MESSAGE-INTEGRITY
			// under our local password (the peer signed with our pwd == its
			// "remote" pwd).
			immutable wantUser = localCreds.ufrag ~ ":" ~ remoteCreds.get.ufrag;
			string gotUser;
			try
				gotUser = m.getUsername;
			catch (Exception)
				return;
			if (gotUser != wantUser)
				return;
			if (!m.checkMessageIntegrity(strKey(localCreds.pwd)))
				return;

			auto ri = findRemoteCandidate(from);
			if (ri.isNull)
			{
				// Peer-reflexive: learn the remote from the request's source.
				addRemoteCandidate(Candidate(CandidateType.peerReflexive, from.ip, from.port));
				ri = findRemoteCandidate(from);
			}
			if (!ri.isNull)
				handleBindingRequest(m, li.get, ri.get, now);
		}
	}

	// ---- connectivity checks --------------------------------------------------

	// Periodic driver: ping unchecked pairs, and (controlling) nominate a
	// succeeded pair once one exists.
	private void contact(long now)
	{
		if (remoteCreds.isNull || state_ == ConnectionState.closed)
			return;
		if (!selected.isNull)
			return; // connected; nothing more to drive (no keepalive here)

		if (role == Role.controlling)
		{
			// Nominate the first succeeded pair (host-only: any succeeded pair is
			// the best available). The controlled side selects when our
			// USE-CANDIDATE check lands on its succeeded pair.
			if (!nominationInFlight)
			{
				foreach (idx, ref p; pairs)
					if (p.state == PairState.succeeded)
					{
						p.nominated = true;
						nominationInFlight = true;
						pingPair(idx, now, true);
						return;
					}
			}
		}
		pingAllWaiting(now);
	}

	private void pingAllWaiting(long now)
	{
		foreach (idx, ref p; pairs)
			if (p.state == PairState.waiting)
			{
				p.state = PairState.inProgress;
				pingPair(idx, now, false);
			}
	}

	// Send a Binding request on a pair (optionally carrying USE-CANDIDATE).
	private void pingPair(size_t idx, long now, bool useCandidate)
	{
		auto p = pairs[idx];
		auto rc = remoteCreds.get;
		Message m;
		m.typ = BINDING_REQUEST;
		m.transactionId = newTransactionId();
		addUsername(m, rc.ufrag ~ ":" ~ localCreds.ufrag);
		if (useCandidate)
			addUseCandidate(m);
		addControl(m, role, tieBreaker);
		addPriority(m, localCands[p.local].priority);
		m.addMessageIntegrity(strKey(rc.pwd));
		m.addFingerprint();

		immutable dst = candAddr(remoteCands[p.remote]);
		pending ~= PendingRequest(m.transactionId, dst, useCandidate, now);
		outQueue ~= OutboundStun(candAddr(localCands[p.local]), dst, m.encode);
	}

	// Reply to a Binding request with a Binding success, and drive nomination.
	private void handleBindingRequest(ref Message req, size_t li, size_t ri, long now)
	{
		sendBindingSuccess(req, li, ri);

		immutable pi = findOrAddPair(li, ri);
		if (role == Role.controlled && req.hasUseCandidate)
		{
			// RFC 8445 §7.3.1.5: nomination. If our own check already succeeded on
			// this pair, select it; otherwise trigger a check so it can.
			if (pairs[pi].state == PairState.succeeded)
			{
				if (selected.isNull)
					setSelected(pi);
			}
			else if (pairs[pi].state == PairState.waiting)
			{
				pairs[pi].state = PairState.inProgress;
				pingPair(pi, now, false);
			}
		}
	}

	private void sendBindingSuccess(ref Message req, size_t li, size_t ri)
	{
		immutable remoteAddr = candAddr(remoteCands[ri]);
		Message outm;
		outm.typ = BINDING_SUCCESS_RESPONSE;
		outm.transactionId = req.transactionId; // echo the request's id

		auto octets = parseIpv4(remoteAddr.ip);
		if (!octets.isNull)
		{
			auto xma = XorMappedAddress(octets.get.dup, remoteAddr.port);
			outm.attributes ~= Attribute(ATTR_XOR_MAPPED_ADDRESS, xma.encode(outm.transactionId));
		}
		outm.addMessageIntegrity(strKey(localCreds.pwd));
		outm.addFingerprint();
		outQueue ~= OutboundStun(candAddr(localCands[li]), remoteAddr, outm.encode);
	}

	private void handleSuccessResponse(ref Message m, size_t li, size_t ri, TransportAddr from)
	{
		auto pr = takePending(m.transactionId);
		if (pr.isNull)
			return; // unknown transaction
		if (!(pr.get.destination == from))
			return; // symmetric-NAT guard: source must match where we sent

		immutable pi = findOrAddPair(li, ri);
		pairs[pi].state = PairState.succeeded;

		if (pr.get.isUseCandidate && selected.isNull)
			setSelected(pi); // our nomination completed (controlling side)
	}

	// ---- helpers --------------------------------------------------------------

	private void setSelected(size_t pi) @safe pure nothrow
	{
		selected = pi;
		pairs[pi].nominated = true;
		setState(ConnectionState.connected);
	}

	private void setState(ConnectionState s) @safe pure nothrow
	{
		if (state_ == s)
			return;
		state_ = s;
		events ~= s;
	}

	private Nullable!size_t findLocalCandidate(TransportAddr a) const @safe pure nothrow
	{
		foreach (i, ref c; localCands)
			if (candAddr(c) == a)
				return nullable(i);
		return Nullable!size_t.init;
	}

	private Nullable!size_t findRemoteCandidate(TransportAddr a) const @safe pure nothrow
	{
		foreach (i, ref c; remoteCands)
			if (candAddr(c) == a)
				return nullable(i);
		return Nullable!size_t.init;
	}

	private size_t findOrAddPair(size_t li, size_t ri) @safe pure nothrow
	{
		foreach (i, ref p; pairs)
			if (p.local == li && p.remote == ri)
				return i;
		immutable idx = pairs.length;
		pairs ~= Pair(li, ri);
		return idx;
	}

	private Nullable!PendingRequest takePending(TransactionId id) @safe pure nothrow
	{
		foreach (i, ref pr; pending)
			if (pr.id == id)
			{
				auto v = pr;
				pending = pending[0 .. i] ~ pending[i + 1 .. $];
				return nullable(v);
			}
		return Nullable!PendingRequest.init;
	}

	private TransactionId newTransactionId() @trusted
	{
		TransactionId id;
		randombytes_buf(id.ptr, TRANSACTION_ID_SIZE);
		return id;
	}
}

private TransportAddr candAddr(const Candidate c) @safe pure nothrow
{
	return TransportAddr(c.address, c.port);
}

private const(ubyte)[] strKey(string s) @trusted pure nothrow
{
	return cast(const(ubyte)[]) s;
}

// Parse a dotted-decimal IPv4 literal into 4 octets (null if not IPv4).
private Nullable!(ubyte[4]) parseIpv4(string s) @safe pure nothrow
{
	ubyte[4] out_;
	size_t n; // octet index
	uint v; // current octet accumulator
	size_t digits;
	foreach (ch; s)
	{
		if (ch == '.')
		{
			if (digits == 0 || n >= 3)
				return Nullable!(ubyte[4]).init;
			out_[n++] = cast(ubyte) v;
			v = 0;
			digits = 0;
		}
		else if (ch >= '0' && ch <= '9')
		{
			v = v * 10 + (ch - '0');
			if (++digits > 3 || v > 255)
				return Nullable!(ubyte[4]).init;
		}
		else
			return Nullable!(ubyte[4]).init;
	}
	if (digits == 0 || n != 3)
		return Nullable!(ubyte[4]).init;
	out_[n] = cast(ubyte) v;
	return nullable(out_);
}
