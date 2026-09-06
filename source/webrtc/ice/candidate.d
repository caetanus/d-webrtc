/**
 * ICE candidates (RFC 8445 §5.1). A candidate is a transport address we or the
 * peer might use, with the priority and foundation the check ordering needs.
 *
 * Only host candidates are built here. Server-reflexive and peer-reflexive
 * candidates arrive the same shape — a type, a base, an address — so the agent
 * treats them uniformly and nothing here changes when srflx is added. The
 * priority formula (§5.1.2.1) and the type preferences (§5.1.2.2) are the RFC's;
 * the foundation (§5.1.1.3) is any string that is equal across candidates
 * sharing a base, type and transport, which for a single host base is one value.
 */
module webrtc.ice.candidate;

import std.conv : to;

enum CandidateType
{
	host,
	serverReflexive,
	peerReflexive,
	relay,
}

// RFC 8445 §5.1.2.2: recommended type preferences (0–126).
private uint typePreference(CandidateType t) @safe pure nothrow @nogc
{
	final switch (t)
	{
	case CandidateType.host:
		return 126;
	case CandidateType.peerReflexive:
		return 110;
	case CandidateType.serverReflexive:
		return 100;
	case CandidateType.relay:
		return 0;
	}
}

struct Candidate
{
	CandidateType typ;
	string address; /// dotted IPv4 or bracketless IPv6
	ushort port;
	ubyte component = 1; /// RTP/data component is 1; we run a single component
	bool ipv6;
	uint priority;
	string foundation;

	/// A host candidate on a local address, with priority and foundation filled.
	static Candidate host(string address, ushort port, bool ipv6 = false) @safe pure
	{
		Candidate c;
		c.typ = CandidateType.host;
		c.address = address;
		c.port = port;
		c.ipv6 = ipv6;
		c.priority = computePriority(CandidateType.host, 65535, c.component);
		c.foundation = computeFoundation(CandidateType.host, address);
		return c;
	}

	/// A peer-reflexive candidate learned from an inbound check's source address.
	static Candidate peerReflexive(string address, ushort port, bool ipv6) @safe pure
	{
		Candidate c;
		c.typ = CandidateType.peerReflexive;
		c.address = address;
		c.port = port;
		c.ipv6 = ipv6;
		c.priority = computePriority(CandidateType.peerReflexive, 65535, c.component);
		c.foundation = computeFoundation(CandidateType.peerReflexive, address);
		return c;
	}
}

/// RFC 8445 §5.1.2.1: priority = 2^24·typePref + 2^8·localPref + (256 − component).
uint computePriority(CandidateType t, uint localPreference, ubyte component) @safe pure nothrow @nogc
{
	return (typePreference(t) << 24) + (localPreference << 8) + (256 - component);
}

// RFC 8445 §5.1.1.3: candidates with the same type, base and transport share a
// foundation. With one base per type here, the type and address determine it.
private string computeFoundation(CandidateType t, string address) @safe pure
{
	return to!string(cast(int) t) ~ "-" ~ address;
}
