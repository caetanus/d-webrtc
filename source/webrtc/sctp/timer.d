/**
 * SCTP retransmission timers and RTO management (RFC 4960 §6.3).
 *
 * Laundered from webrtc-rs's rtc-sctp `association/timer.rs`. Being sans-io, we
 * take the current time as a caller-supplied millisecond value (`now`) instead
 * of reading `Instant`, and use -1 for an unset timer — so the whole thing is
 * pure and deterministic.
 */
module webrtc.sctp.timer;

import std.math : abs;
import std.algorithm : min, clamp;

/// The default ACK delay, in ms.
enum ulong ACK_INTERVAL = 200;
private enum size_t MAX_INIT_RETRANS = 8;
private enum size_t PATH_MAX_RETRANS = 5;
enum size_t NO_MAX_RETRANS = size_t.max;
private enum size_t TIMER_COUNT = 6;

/// The distinct retransmission timers.
enum Timer
{
	t1Init = 0,
	t1Cookie = 1,
	t2Shutdown = 2,
	t3RTX = 3,
	reconfig = 4,
	ack = 5,
}

/// Per-timer maximum retransmission counts.
struct TimerConfig
{
	size_t maxT1InitRetrans = MAX_INIT_RETRANS;
	size_t maxT1CookieRetrans = MAX_INIT_RETRANS;
	size_t maxT2ShutdownRetrans = NO_MAX_RETRANS;
	size_t maxT3RtxRetrans = PATH_MAX_RETRANS;
	size_t maxReconfigRetrans = PATH_MAX_RETRANS;
	size_t maxAckRetrans = PATH_MAX_RETRANS;
}

/// A table of state for each kind of timer. Times are absolute ms; -1 = unset.
struct TimerTable
{
	private long[TIMER_COUNT] data = -1;
	private size_t[TIMER_COUNT] retrans;
	private size_t[TIMER_COUNT] maxRetrans;

	this(TimerConfig cfg) @safe pure nothrow @nogc
	{
		data[] = -1;
		maxRetrans = [
			cfg.maxT1InitRetrans, cfg.maxT1CookieRetrans, cfg.maxT2ShutdownRetrans,
			cfg.maxT3RtxRetrans, cfg.maxReconfigRetrans, cfg.maxAckRetrans
		];
	}

	long get(Timer t) const @safe pure nothrow @nogc
	{
		return data[t];
	}

	/// The earliest scheduled timeout, or -1 if none is set.
	long nextTimeout() const @safe pure nothrow @nogc
	{
		long best = -1;
		foreach (d; data)
			if (d >= 0 && (best < 0 || d < best))
				best = d;
		return best;
	}

	/// Arm `timer` to fire `interval` ms from `now`, backing the interval off
	/// exponentially by the retransmission count (except the ACK timer).
	void start(Timer t, long now, ulong interval) @safe pure nothrow @nogc
	{
		immutable iv = t == Timer.ack ? interval : calculateNextTimeout(interval, retrans[t]);
		data[t] = now + cast(long) iv;
	}

	/// Re-arm only if the timer is unset or already in the past.
	void restartIfStale(Timer t, long now, ulong interval) @safe pure nothrow @nogc
	{
		if (data[t] >= 0 && data[t] >= now)
			return;
		start(t, now, interval);
	}

	void stop(Timer t) @safe pure nothrow @nogc
	{
		data[t] = -1;
		retrans[t] = 0;
	}

	/// Test whether `timer` has expired by `after`. Returns (expired, failure,
	/// retransCount); on expiry the retransmission count is bumped and `failure`
	/// is set once it exceeds the configured maximum.
	auto isExpired(Timer t, long after) @safe pure nothrow @nogc
	{
		immutable expired = data[t] >= 0 && data[t] <= after;
		bool failure;
		if (expired)
		{
			retrans[t]++;
			if (retrans[t] > maxRetrans[t])
				failure = true;
		}
		import std.typecons : tuple;

		return tuple(expired, failure, retrans[t]);
	}
}

private enum ulong RTO_INITIAL = 3000;
private enum ulong RTO_MIN = 1000;
private enum ulong RTO_MAX = 60_000;
private enum ulong RTO_ALPHA = 1;
private enum ulong RTO_BETA = 2;
private enum ulong RTO_BASE = 8;

/// Manages the retransmission timeout (RFC 4960 §6.3.1): tracks smoothed RTT and
/// its variance, deriving the RTO in ms.
struct RtoManager
{
	ulong srtt;
	double rttvar = 0;
	ulong rto = RTO_INITIAL;
	bool noUpdate;

	/// Fold a new RTT measurement in; returns the (updated) smoothed RTT.
	ulong setNewRtt(ulong rtt) @safe pure nothrow @nogc
	{
		if (noUpdate)
			return srtt;

		if (srtt == 0)
		{
			srtt = rtt;
			rttvar = rtt / 2.0;
		}
		else
		{
			immutable d = cast(double) abs(cast(long) srtt - cast(long) rtt);
			rttvar = ((RTO_BASE - RTO_BETA) * rttvar + RTO_BETA * d) / RTO_BASE;
			srtt = ((RTO_BASE - RTO_ALPHA) * srtt + RTO_ALPHA * rtt) / RTO_BASE;
		}

		immutable r = srtt + cast(ulong)(4.0 * rttvar);
		rto = clamp(r, RTO_MIN, RTO_MAX);
		return srtt;
	}

	ulong getRto() const @safe pure nothrow @nogc
	{
		return rto;
	}

	void reset() @safe pure nothrow @nogc
	{
		if (noUpdate)
			return;
		srtt = 0;
		rttvar = 0;
		rto = RTO_INITIAL;
	}

	/// Force an RTO (used by tests / fixed-timeout paths).
	void setRto(ulong r, bool noUpdate) @safe pure nothrow @nogc
	{
		rto = r;
		this.noUpdate = noUpdate;
	}
}

/// Exponential backoff of a retransmission timeout (RFC 4960 §6.3.3 E2), capped
/// at RTO_MAX.
ulong calculateNextTimeout(ulong rto, size_t nRtos) @safe pure nothrow @nogc
{
	if (nRtos < 31)
		return min(rto << nRtos, RTO_MAX);
	return RTO_MAX;
}
