/**
 * ICE candidates (RFC 8445 §5.1) — the local transport addresses an agent
 * offers for connectivity checks. webrtc-direct only ever uses UDP *host*
 * candidates (no TURN/mDNS/srflx/relay/ICE-TCP), so this is deliberately the
 * host-only subset: the candidate type table, the priority formula (§5.1.2.1),
 * and the foundation (§5.1.1.3).
 *
 * Laundered from webrtc-rs's rtc-ice `candidate/mod.rs`, keeping the parts a
 * lite, host-only agent needs. TCP local-preference (RFC 6544) is dropped with
 * the rest of the non-UDP path.
 */
module webrtc.ice.candidate;

import std.conv : to;
import std.string : representation;

import webrtc.sctp.crc32c : crc32c;

/// ICE candidate types and their RFC 8445 §5.1.2.2 recommended type preferences.
enum CandidateType : ubyte
{
	host,
	peerReflexive,
	serverReflexive,
	relay,
}

/// The recommended type-preference weight for a candidate type (§5.1.2.2).
ushort preference(CandidateType t) @safe pure nothrow @nogc
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

/// The SDP token for a candidate type ("host", "srflx", …).
string typeToken(CandidateType t) @safe pure nothrow
{
	final switch (t)
	{
	case CandidateType.host:
		return "host";
	case CandidateType.serverReflexive:
		return "srflx";
	case CandidateType.peerReflexive:
		return "prflx";
	case CandidateType.relay:
		return "relay";
	}
}

/// The RTP component id — data channels are a single component (§5.1.1).
enum ushort COMPONENT_RTP = 1;
/// When a host has a single address, local preference is the max (§5.1.2.1).
enum ushort DEFAULT_LOCAL_PREFERENCE = 65_535;

/// A UDP host candidate.
struct Candidate
{
	CandidateType typ = CandidateType.host;
	string address; // IP literal, e.g. "192.168.1.2" or "::1"
	ushort port;
	ushort component = COMPONENT_RTP;
	bool ipv6;
	ushort localPreference = DEFAULT_LOCAL_PREFERENCE;

	/// The candidate's priority (RFC 8445 §5.1.2.1):
	///   priority = 2^24·type-pref + 2^8·local-pref + (256 − component).
	uint priority() const @safe pure nothrow @nogc
	{
		return (1u << 24) * typ.preference + (1u << 8) * localPreference + (256 - component);
	}

	/// The candidate's foundation (RFC 8445 §5.1.1.3): a stable id shared by
	/// candidates of the same type/base/protocol. We compute the CRC-32C
	/// (iSCSI) of type‖address‖network-type, rendered as a decimal string —
	/// matching webrtc-rs.
	string foundation() const @safe pure nothrow
	{
		return crc32c((typeToken(typ) ~ address ~ networkToken()).representation).to!string;
	}

	private string networkToken() const @safe pure nothrow
	{
		return ipv6 ? "udp6" : "udp4";
	}
}
