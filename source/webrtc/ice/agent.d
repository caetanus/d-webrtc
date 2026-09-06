/**
 * The ICE agent (RFC 8445), sans-io. It never touches a socket, opens no fiber,
 * and never reads the clock: candidates and inbound STUN go in with the caller's
 * `now` (a `long` of milliseconds), connectivity checks and responses come out,
 * and a pair is selected once one is nominated. The engine spawns nothing, so no
 * concurrency primitive lives here — the consumer owns the one fiber that pumps
 * the socket.
 *
 * The controlling side checks its pairs, nominates the first to succeed by
 * sending a second check carrying USE-CANDIDATE, and selects that pair when the
 * nomination check is answered. The controlled side answers checks, learns the
 * peer as peer-reflexive from a check off an address it did not know, and selects
 * the pair the peer nominates once its own check on that pair has also succeeded
 * — in either order, so a USE-CANDIDATE that arrives before the local check
 * completes is remembered and honoured on completion.
 *
 * Short-term credentials (RFC 8445 §7.1.2): a check from A to B is signed with
 * B's password and carries USERNAME "B-ufrag:A-ufrag"; the response is signed
 * with the responder's own password. So an outbound check signs with the remote
 * password, an inbound request is verified with the local password, and an
 * inbound response is verified with the remote password.
 *
 * Retransmission follows the §14 schedule (a fixed RTO, capped tries); a pair
 * with no answer fails, and when every pair has failed and none was selected the
 * agent reaches its Failed end state. Once connected, consent freshness (RFC
 * 7675) keeps the selected pair alive with periodic Binding requests, and the
 * connection fails if consent is not refreshed in time. An ICE restart re-runs
 * checking under new credentials.
 */
module webrtc.ice.agent;

import std.algorithm.searching : canFind;
import std.algorithm.sorting : sort;
import std.array : split;
import std.conv : to;
import std.string : representation;

import webrtc.ice.candidate : Candidate, CandidateType;
import webrtc.stun.message;

/// Which side breaks nomination ties. Exchanged out of band (in libp2p, decided
/// by the dialer/listener roles of the connection being upgraded).
enum Role
{
	controlling,
	controlled,
}

enum ConnectionState
{
	newState,
	checking,
	connected,
	failed,
}

/// A transport address: how the driver tags a datagram it received or will send.
struct TransportAddr
{
	string ip;
	ushort port;
}

/// Short-term credentials (ufrag/pwd), exchanged out of band.
struct Credentials
{
	string ufrag;
	string pwd;
}

/// A STUN packet to send from `src` (a local candidate) to `dst`.
struct OutboundStun
{
	TransportAddr src;
	TransportAddr dst;
	ubyte[] data;
}

// RFC 8445 §14: pacing (Ta), the retransmission timer (RTO), and the cap on
// tries before a pair is abandoned. Milliseconds, to match the caller's `now`.
private enum long taMs = 50;
private enum long rtoMs = 500;
private enum size_t maxTries = 7;
// RFC 7675 consent freshness: a Binding request on the selected pair every
// ~5 s keeps the path alive, and consent is lost if no valid response arrives
// within 30 s — at which point the pair, and the connection, fail.
private enum long consentIntervalMs = 5_000;
private enum long consentTimeoutMs = 30_000;

private enum PairState
{
	frozen,
	waiting,
	inProgress,
	succeeded,
	failed,
}

private struct Pair
{
	Candidate local;
	Candidate remote;
	PairState state = PairState.waiting;
	ulong priority; /// §6.1.2.3, for ordering the check list
	TransactionId txid; /// the in-flight connectivity check
	TransactionId nomTxid; /// the in-flight nomination check (controlling)
	long sentAt; /// ms; when the current try went out
	size_t tries;
	bool nominated; /// we chose this pair (controlling) …
	bool nominationSent; /// … and its USE-CANDIDATE check went out
	bool remoteNominated; /// a check with USE-CANDIDATE arrived for it (controlled)

	TransportAddr localAddr() const @safe pure nothrow
	{
		return TransportAddr(local.address, local.port);
	}

	TransportAddr remoteAddr() const @safe pure nothrow
	{
		return TransportAddr(remote.address, remote.port);
	}
}

final class Agent
{
	private Role role;
	private Credentials local;
	private Credentials remote;
	private bool haveRemote;
	private ulong tieBreaker;

	private Candidate[] localCandidates;
	private Candidate[] remoteCandidates;
	private Pair[] pairs;
	private ConnectionState state = ConnectionState.newState;

	private bool haveSelected;
	private TransportAddr[2] selected;
	private uint selectedPriority; /// the selected local candidate's priority, for consent checks
	private bool startedAny; /// a first check has gone out
	private long lastCheckStart; /// ms; Ta pacing of new checks
	private TransactionId consentTxid; /// the in-flight consent check
	private long lastConsentSent; /// ms; when the last consent check went out
	private long lastConsentAt; /// ms; when consent was last confirmed by a response
	private OutboundStun[] outbox;

	this(Role role, Credentials local, ulong tieBreaker) @safe pure nothrow
	{
		this.role = role;
		this.local = local;
		this.tieBreaker = tieBreaker;
	}

	// --- setup ------------------------------------------------------------------------------

	void setRemoteCredentials(Credentials c) @safe pure nothrow
	{
		remote = c;
		haveRemote = true;
	}

	void addLocalCandidate(Candidate c) @safe pure
	{
		if (localCandidates.canFind!(x => x.address == c.address && x.port == c.port))
			return;
		localCandidates ~= c;
		formPairs();
	}

	void addRemoteCandidate(Candidate c) @safe pure
	{
		if (remoteCandidates.canFind!(x => x.address == c.address && x.port == c.port))
			return;
		remoteCandidates ~= c;
		formPairs();
	}

	/// ICE restart (RFC 8445 §9): new credentials for both sides, the check state
	/// thrown away, and checking begun afresh over the existing candidates. A
	/// connection that had been selected is no longer, until a pair is nominated
	/// again.
	void restart(Credentials newLocal, Credentials newRemote) @safe pure
	{
		local = newLocal;
		remote = newRemote;
		haveRemote = true;
		pairs = null;
		state = ConnectionState.newState;
		haveSelected = false;
		startedAny = false;
		lastCheckStart = 0;
		consentTxid = TransactionId.init;
		lastConsentSent = 0;
		lastConsentAt = 0;
		formPairs();
	}

	// --- observation ------------------------------------------------------------------------

	bool isConnected() const @safe pure nothrow
	{
		return state == ConnectionState.connected;
	}

	ConnectionState connectionState() const @safe pure nothrow
	{
		return state;
	}

	/// The chosen (local, remote) pair once connected; absent before then.
	bool selectedPair(out TransportAddr localAddr, out TransportAddr remoteAddr) const @safe pure nothrow
	{
		if (!haveSelected)
			return false;
		localAddr = selected[0];
		remoteAddr = selected[1];
		return true;
	}

	// --- the sans-io triad ------------------------------------------------------------------

	/// Advance timers: start due checks (paced by Ta), retransmit, fail pairs.
	void handleTimeout(long now) @safe
	{
		schedule(now);
	}

	/// Everything queued to send now. Runs the scheduler first so a caller that
	/// only ever calls this still makes progress; the scheduler is idempotent at
	/// a given `now`, so calling handleTimeout beforehand costs nothing.
	OutboundStun[] gatherOutbound(long now) @safe
	{
		schedule(now);
		auto o = outbox;
		outbox = null;
		return o;
	}

	/// Feed a received datagram. Non-STUN and malformed packets are ignored (the
	/// caller demultiplexes STUN from DTLS; a decode failure is not our decision
	/// to escalate). A well-formed check or response drives the state machine.
	void handleInbound(scope const(ubyte)[] data, TransportAddr from, TransportAddr to, long now) @safe
	{
		if (!isStunMessage(data))
			return;
		Message m;
		try
			m = Message.decode(data);
		catch (Exception)
			return;

		if (m.typ == bindingRequest)
			handleRequest(m, from, to, now);
		else if (m.typ == bindingSuccess)
			handleResponse(m, from, to, now);
	}

	// --- inbound ----------------------------------------------------------------------------

	private void handleRequest(ref Message req, TransportAddr from, TransportAddr to, long now) @safe
	{
		if (!haveRemote)
			return;
		// Verified with our own password; the USERNAME the peer sent is
		// "our-ufrag:their-ufrag".
		if (!req.checkMessageIntegrity(local.pwd.representation))
			return;
		if (req.get(attrUsername) != (local.ufrag ~ ":" ~ remote.ufrag).representation)
			return;

		// A check off an address we do not know is a peer-reflexive candidate:
		// learn it, so the controlled side needs no remote candidate up front.
		if (!remoteCandidates.canFind!(x => x.address == from.ip && x.port == from.port))
			addRemoteCandidate(Candidate.peerReflexive(from.ip, from.port, from.ip.canFind(':')));

		// Answer with the mapped address, signed with our password.
		Message resp;
		resp.typ = bindingSuccess;
		resp.transactionId = req.transactionId;
		resp.attributes ~= Attribute(attrXorMappedAddress,
			XorMappedAddress(ipToBytes(from.ip), from.port).encode(req.transactionId));
		resp.addMessageIntegrity(local.pwd.representation);
		resp.addFingerprint();
		outbox ~= OutboundStun(to, from, resp.encode);

		// A nomination: mark the pair, and select it if our own check on it has
		// already succeeded (else select on that success later).
		if (req.has(attrUseCandidate))
			foreach (ref p; pairs)
				if (p.remoteAddr == from && p.localAddr == to)
				{
					p.remoteNominated = true;
					if (role == Role.controlled && p.state == PairState.succeeded)
						select(p, now);
				}
	}

	private void handleResponse(ref Message resp, TransportAddr from, TransportAddr to, long now) @safe
	{
		if (!resp.checkMessageIntegrity(remote.pwd.representation))
			return;

		// A consent check was answered: the path is still alive.
		if (haveSelected && resp.transactionId == consentTxid
			&& from == selected[1] && to == selected[0])
		{
			lastConsentAt = now;
			return;
		}

		foreach (ref p; pairs)
		{
			if (p.remoteAddr != from || p.localAddr != to)
				continue;

			// The nomination check was answered: the controlling side selects.
			if (p.nominationSent && resp.transactionId == p.nomTxid)
			{
				if (role == Role.controlling)
					select(p, now);
				return;
			}

			if (p.state == PairState.inProgress && resp.transactionId == p.txid)
			{
				p.state = PairState.succeeded;
				if (role == Role.controlling && !anyNominated)
				{
					// Nominate this pair: send a fresh check carrying USE-CANDIDATE;
					// selection waits for its answer.
					p.nominated = true;
					p.nominationSent = true;
					p.nomTxid = Message.randomTransactionId();
					outbox ~= checkFor(p, true);
				}
				else if (role == Role.controlled && p.remoteNominated)
					select(p, now);
				return;
			}
		}
	}

	// --- scheduler --------------------------------------------------------------------------

	private void schedule(long now) @safe
	{
		if (!haveRemote || localCandidates.length == 0)
			return;

		// Start one waiting pair per Ta, highest priority first.
		if (!startedAny || now - lastCheckStart >= taMs)
			foreach (ref p; pairs)
				if (p.state == PairState.waiting)
				{
					startCheck(p, now);
					outbox ~= checkFor(p, false);
					startedAny = true;
					lastCheckStart = now;
					break;
				}

		// Retransmit an unanswered check, or fail the pair once tries run out.
		foreach (ref p; pairs)
			if (p.state == PairState.inProgress && now - p.sentAt >= rtoMs)
			{
				if (p.tries >= maxTries)
				{
					p.state = PairState.failed;
					maybeFail();
				}
				else
				{
					p.tries++;
					p.sentAt = now;
					outbox ~= checkFor(p, false);
				}
			}

		// Consent freshness (RFC 7675) on the selected pair: lose consent and the
		// connection fails; otherwise send a consent check every interval.
		if (state == ConnectionState.connected)
		{
			if (now - lastConsentAt >= consentTimeoutMs)
				state = ConnectionState.failed;
			else if (now - lastConsentSent >= consentIntervalMs)
			{
				consentTxid = Message.randomTransactionId();
				outbox ~= consentCheck();
				lastConsentSent = now;
			}
		}
	}

	private void startCheck(ref Pair p, long now) @safe
	{
		p.state = PairState.inProgress;
		p.txid = Message.randomTransactionId();
		p.sentAt = now;
		p.tries = 1;
	}

	// A connectivity check on a pair; with USE-CANDIDATE it is the nomination
	// check and carries the nomination transaction id.
	private OutboundStun checkFor(ref Pair p, bool useCandidate) @safe
	{
		Message m;
		m.typ = bindingRequest;
		m.transactionId = useCandidate ? p.nomTxid : p.txid;
		m.attributes ~= Attribute(attrUsername, (remote.ufrag ~ ":" ~ local.ufrag).representation.dup);
		m.attributes ~= Attribute(attrPriority, be32(p.local.priority));
		m.attributes ~= Attribute(role == Role.controlling ? attrIceControlling : attrIceControlled,
			be64(tieBreaker));
		if (useCandidate)
			m.attributes ~= Attribute(attrUseCandidate, null);
		m.addMessageIntegrity(remote.pwd.representation);
		m.addFingerprint();
		return OutboundStun(p.localAddr, p.remoteAddr, m.encode);
	}

	// A consent check (RFC 7675): an ordinary authenticated Binding request on the
	// selected pair, tracked by consentTxid so its response refreshes consent.
	private OutboundStun consentCheck() @safe
	{
		Message m;
		m.typ = bindingRequest;
		m.transactionId = consentTxid;
		m.attributes ~= Attribute(attrUsername, (remote.ufrag ~ ":" ~ local.ufrag).representation.dup);
		m.attributes ~= Attribute(attrPriority, be32(selectedPriority));
		m.attributes ~= Attribute(role == Role.controlling ? attrIceControlling : attrIceControlled,
			be64(tieBreaker));
		m.addMessageIntegrity(remote.pwd.representation);
		m.addFingerprint();
		return OutboundStun(selected[0], selected[1], m.encode);
	}

	// --- bookkeeping ------------------------------------------------------------------------

	private void formPairs() @safe pure
	{
		foreach (l; localCandidates)
			foreach (r; remoteCandidates)
				if (!pairs.canFind!(p => p.localAddr == TransportAddr(l.address, l.port)
						&& p.remoteAddr == TransportAddr(r.address, r.port)))
				{
					Pair p;
					p.local = l;
					p.remote = r;
					p.priority = pairPriority(l.priority, r.priority);
					pairs ~= p;
				}
		pairs.sort!((a, b) => a.priority > b.priority);
		if (state == ConnectionState.newState && pairs.length > 0)
			state = ConnectionState.checking;
	}

	private bool anyNominated() const @safe pure nothrow
	{
		foreach (ref p; pairs)
			if (p.nominated)
				return true;
		return false;
	}

	private void select(ref Pair p, long now) @safe pure nothrow
	{
		selected = [p.localAddr, p.remoteAddr];
		selectedPriority = p.local.priority;
		haveSelected = true;
		state = ConnectionState.connected;
		// Consent starts fresh at selection; the first consent check follows an
		// interval later.
		lastConsentAt = now;
		lastConsentSent = now;
	}

	private void maybeFail() @safe pure nothrow
	{
		if (state == ConnectionState.connected)
			return;
		foreach (ref p; pairs)
			if (p.state != PairState.failed)
				return;
		if (pairs.length > 0)
			state = ConnectionState.failed;
	}

	// --- encoding helpers -------------------------------------------------------------------

	// RFC 8445 §6.1.2.3: 2^32·min(G,D) + 2·max(G,D) + (G>D ? 1 : 0), G being the
	// controlling agent's candidate priority.
	private ulong pairPriority(uint localPrio, uint remotePrio) const @safe pure nothrow @nogc
	{
		immutable g = role == Role.controlling ? localPrio : remotePrio;
		immutable d = role == Role.controlling ? remotePrio : localPrio;
		immutable lo = g < d ? g : d;
		immutable hi = g < d ? d : g;
		return (cast(ulong) lo << 32) + 2UL * hi + (g > d ? 1 : 0);
	}
}

private ubyte[] be32(uint v) @safe pure nothrow
{
	return [cast(ubyte)(v >> 24), cast(ubyte)(v >> 16), cast(ubyte)(v >> 8), cast(ubyte) v];
}

private ubyte[] be64(ulong v) @safe pure nothrow
{
	ubyte[] o = new ubyte[8];
	foreach (i; 0 .. 8)
		o[i] = cast(ubyte)(v >> (8 * (7 - i)));
	return o;
}

// The bytes of an address for XOR-MAPPED-ADDRESS. IPv4 is parsed; IPv6 is filled
// with zeros for now (host loopback checks are IPv4; a real IPv6 parse lands with
// server-reflexive candidates, which this layer is shaped to accept).
private ubyte[] ipToBytes(string ip) @safe pure
{
	if (ip.canFind(':'))
		return new ubyte[16];
	ubyte[] v;
	foreach (part; ip.split('.'))
		v ~= part.to!ubyte;
	return v;
}
