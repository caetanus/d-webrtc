module tests.ice.attributes_test;

import webrtc.stun.message : Message, BINDING_REQUEST;
import webrtc.ice.attributes;
import fluent.asserts : should;

@("PRIORITY round-trips through a Binding request")
unittest
{
	Message m;
	m.typ = BINDING_REQUEST;
	m.addPriority(0x7EFF_FEFF);

	auto back = Message.decode(m.encode);
	back.getPriority.should.equal(0x7EFF_FEFFu);
}

@("USE-CANDIDATE is an empty flag that reads back as set")
unittest
{
	Message m;
	m.typ = BINDING_REQUEST;
	m.hasUseCandidate.should.equal(false);
	m.addUseCandidate();

	auto back = Message.decode(m.encode);
	back.hasUseCandidate.should.equal(true);
}

@("ICE-CONTROLLING carries role + tie-breaker")
unittest
{
	Message m;
	m.typ = BINDING_REQUEST;
	m.addControl(Role.controlling, 0x0123_4567_89AB_CDEF);

	auto back = Message.decode(m.encode);
	auto ctl = back.getControl;
	ctl[0].should.equal(Role.controlling);
	ctl[1].should.equal(0x0123_4567_89AB_CDEFUL);
}

@("ICE-CONTROLLED carries the controlled role")
unittest
{
	Message m;
	m.typ = BINDING_REQUEST;
	m.addControl(Role.controlled, 42);

	auto back = Message.decode(m.encode);
	auto ctl = back.getControl;
	ctl[0].should.equal(Role.controlled);
	ctl[1].should.equal(42UL);
}

@("USERNAME round-trips the ufrag pair")
unittest
{
	Message m;
	m.typ = BINDING_REQUEST;
	m.addUsername("RemOte:local");

	auto back = Message.decode(m.encode);
	back.getUsername.should.equal("RemOte:local");
}
