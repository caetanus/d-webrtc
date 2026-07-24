module tests.sctp.timer_test;

import webrtc.sctp.timer;
import fluent.asserts : should;

@("RTO manager derives RTO from RTT measurements (RFC 4960 §6.3.1)")
unittest
{
	RtoManager m;
	m.getRto().should.equal(3000UL); // RTO_INITIAL

	// First measurement: srtt=1000, rttvar=500, rto=1000+4*500=3000.
	m.setNewRtt(1000).should.equal(1000UL);
	m.getRto().should.equal(3000UL);

	// Second, identical: rttvar=(6*500+2*0)/8=375, srtt=(7*1000+1000)/8=1000,
	// rto=1000+4*375=2500.
	m.setNewRtt(1000).should.equal(1000UL);
	m.getRto().should.equal(2500UL);

	m.reset();
	m.getRto().should.equal(3000UL);
	m.srtt.should.equal(0UL);
}

@("RTO manager honours the no-update flag and RTO_MIN clamp")
unittest
{
	RtoManager m;
	m.setRto(5000, true); // no_update
	m.setNewRtt(10).should.equal(0UL); // no update → srtt unchanged (0)
	m.getRto().should.equal(5000UL);

	RtoManager m2;
	m2.setNewRtt(1); // srtt=1, rttvar=0.5, rto=1+2=3 → clamped up to RTO_MIN 1000
	m2.getRto().should.equal(1000UL);
}

@("calculateNextTimeout backs off exponentially, capped at RTO_MAX")
unittest
{
	calculateNextTimeout(1000, 0).should.equal(1000UL);
	calculateNextTimeout(1000, 1).should.equal(2000UL);
	calculateNextTimeout(1000, 3).should.equal(8000UL);
	calculateNextTimeout(1000, 6).should.equal(60_000UL); // 64000 capped
	calculateNextTimeout(1000, 40).should.equal(60_000UL);
}

@("timer table arms, finds the earliest, and expires with backoff/failure")
unittest
{
	auto t = TimerTable(TimerConfig());
	t.nextTimeout().should.equal(-1L);

	t.start(Timer.t3RTX, 1000, 500); // first arm: 1000 + 500 = 1500
	t.get(Timer.t3RTX).should.equal(1500L);
	t.start(Timer.ack, 1000, ACK_INTERVAL); // 1000 + 200 = 1200
	t.nextTimeout().should.equal(1200L); // ack is earliest

	// Not yet expired at 1400; expired at 1600.
	t.isExpired(Timer.t3RTX, 1400)[0].should.equal(false);
	auto e = t.isExpired(Timer.t3RTX, 1600);
	e[0].should.equal(true); // expired
	e[1].should.equal(false); // not yet a failure (1 <= max 5)
	e[2].should.equal(cast(size_t) 1); // retrans count

	t.stop(Timer.t3RTX);
	t.get(Timer.t3RTX).should.equal(-1L);
}
