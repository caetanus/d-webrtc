/**
 * Serial-number arithmetic (RFC 1982) — SCTP's TSNs (32-bit) and stream sequence
 * numbers (16-bit) wrap around, so ordering compares them modulo 2^n with a
 * half-range window rather than as plain integers.
 *
 * Laundered from webrtc-rs's rtc-sctp `util.rs`.
 */
module webrtc.sctp.sna;

// 32-bit (TSN) comparisons.
bool sna32lt(uint i1, uint i2) @safe pure nothrow @nogc
{
	return (i1 < i2 && i2 - i1 < 1u << 31) || (i1 > i2 && i1 - i2 > 1u << 31);
}

bool sna32lte(uint i1, uint i2) @safe pure nothrow @nogc
{
	return i1 == i2 || sna32lt(i1, i2);
}

bool sna32gt(uint i1, uint i2) @safe pure nothrow @nogc
{
	return (i1 < i2 && (i2 - i1) >= 1u << 31) || (i1 > i2 && (i1 - i2) <= 1u << 31);
}

bool sna32gte(uint i1, uint i2) @safe pure nothrow @nogc
{
	return i1 == i2 || sna32gt(i1, i2);
}

bool sna32eq(uint i1, uint i2) @safe pure nothrow @nogc
{
	return i1 == i2;
}

// 16-bit (stream sequence number) comparisons.
bool sna16lt(ushort i1, ushort i2) @safe pure nothrow @nogc
{
	return (i1 < i2 && cast(ushort)(i2 - i1) < 1 << 15)
		|| (i1 > i2 && cast(ushort)(i1 - i2) > 1 << 15);
}

bool sna16lte(ushort i1, ushort i2) @safe pure nothrow @nogc
{
	return i1 == i2 || sna16lt(i1, i2);
}

bool sna16gt(ushort i1, ushort i2) @safe pure nothrow @nogc
{
	return (i1 < i2 && cast(ushort)(i2 - i1) >= 1 << 15)
		|| (i1 > i2 && cast(ushort)(i1 - i2) <= 1 << 15);
}

bool sna16gte(ushort i1, ushort i2) @safe pure nothrow @nogc
{
	return i1 == i2 || sna16gt(i1, i2);
}
