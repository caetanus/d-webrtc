/**
 * ICE-specific STUN attributes carried on connectivity-check Binding requests
 * (RFC 8445 §7.1 / §16.1): PRIORITY, USE-CANDIDATE, ICE-CONTROLLING /
 * ICE-CONTROLLED (with their tie-breaker), and USERNAME. These sit on top of the
 * plain STUN [`Message`]; the generic MESSAGE-INTEGRITY / FINGERPRINT already
 * live there.
 *
 * Laundered from webrtc-rs's rtc-ice `attributes/*`, adapted to our struct-based
 * Message (append an Attribute to add, scan attributes to read) instead of the
 * rust Setter/Getter traits.
 */
module webrtc.ice.attributes;

import std.exception : enforce;

import webrtc.stun.message : Message, Attribute, ATTR_PRIORITY, ATTR_USE_CANDIDATE,
	ATTR_ICE_CONTROLLING, ATTR_ICE_CONTROLLED, ATTR_USERNAME;

/// The controlling/controlled role of an ICE agent (RFC 8445 §6.1).
enum Role
{
	controlling,
	controlled,
}

// ---- PRIORITY (32-bit) -------------------------------------------------------

/// Append a PRIORITY attribute.
void addPriority(ref Message m, uint priority) @safe pure nothrow
{
	m.attributes ~= Attribute(ATTR_PRIORITY, be32(priority));
}

/// Read the PRIORITY attribute. Throws if absent or malformed.
uint getPriority(const ref Message m) @safe pure
{
	auto v = m.get(ATTR_PRIORITY);
	enforce(v.length == 4, "ice: missing/short PRIORITY");
	return read32(v);
}

// ---- USE-CANDIDATE (flag) ----------------------------------------------------

/// Append the (empty) USE-CANDIDATE flag attribute.
void addUseCandidate(ref Message m) @safe pure nothrow
{
	m.attributes ~= Attribute(ATTR_USE_CANDIDATE, []);
}

/// Whether USE-CANDIDATE is set.
bool hasUseCandidate(const ref Message m) @safe pure nothrow
{
	return m.contains(ATTR_USE_CANDIDATE);
}

// ---- ICE-CONTROLLING / ICE-CONTROLLED (64-bit tie-breaker) -------------------

/// Append the role attribute carrying the agent's 64-bit tie-breaker.
void addControl(ref Message m, Role role, ulong tieBreaker) @safe pure nothrow
{
	immutable t = role == Role.controlling ? ATTR_ICE_CONTROLLING : ATTR_ICE_CONTROLLED;
	m.attributes ~= Attribute(t, be64(tieBreaker));
}

/// The role/tie-breaker carried by a message. Throws if neither attribute is
/// present or the value is malformed.
auto getControl(const ref Message m) @safe pure
{
	import std.typecons : tuple;

	if (auto v = m.get(ATTR_ICE_CONTROLLING))
	{
		enforce(v.length == 8, "ice: short ICE-CONTROLLING");
		return tuple(Role.controlling, read64(v));
	}
	if (auto v = m.get(ATTR_ICE_CONTROLLED))
	{
		enforce(v.length == 8, "ice: short ICE-CONTROLLED");
		return tuple(Role.controlled, read64(v));
	}
	throw new Exception("ice: no ICE-CONTROLLING/CONTROLLED attribute");
}

// ---- USERNAME ----------------------------------------------------------------

/// Append the USERNAME attribute ("<remote-ufrag>:<local-ufrag>", §7.2.2).
void addUsername(ref Message m, string username) @safe pure nothrow
{
	m.attributes ~= Attribute(ATTR_USERNAME, cast(ubyte[]) username.dup);
}

/// Read the USERNAME attribute. Throws if absent.
string getUsername(const ref Message m) @safe pure
{
	auto v = m.get(ATTR_USERNAME);
	enforce(v.length > 0, "ice: missing USERNAME");
	return cast(string) v.idup;
}

// ---- big-endian helpers ------------------------------------------------------

private ubyte[] be32(uint v) @safe pure nothrow
{
	return [cast(ubyte)(v >> 24), cast(ubyte)(v >> 16), cast(ubyte)(v >> 8), cast(ubyte) v];
}

private ubyte[] be64(ulong v) @safe pure nothrow
{
	ubyte[] b;
	foreach_reverse (i; 0 .. 8)
		b ~= cast(ubyte)(v >> (i * 8));
	return b;
}

private uint read32(scope const(ubyte)[] v) @safe pure nothrow @nogc
{
	return (cast(uint) v[0] << 24) | (cast(uint) v[1] << 16) | (cast(uint) v[2] << 8) | v[3];
}

private ulong read64(scope const(ubyte)[] v) @safe pure nothrow @nogc
{
	ulong r;
	foreach (i; 0 .. 8)
		r = (r << 8) | v[i];
	return r;
}
