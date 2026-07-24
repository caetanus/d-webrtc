module tests.stun.message_test;

import webrtc.stun.message;
import fluent.asserts : should;

// The transaction id from the RFC 5769 §2.1 sample request.
private enum TransactionId RFC5769_TXID = [
	0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

@("stun encodes the header, magic cookie and 4-byte attribute padding (RFC 5769)")
unittest
{
	Message m;
	m.typ = BINDING_REQUEST;
	m.transactionId = RFC5769_TXID;
	// USERNAME "evtj:h6vY" is 9 bytes → 4-byte-padded to 12 in the attribute body.
	m.attributes ~= Attribute(ATTR_USERNAME, cast(ubyte[]) "evtj:h6vY".dup);

	auto enc = m.encode;

	// attr = 4 (TLV header) + 9 (value) + 3 (pad) = 16 → total 20 + 16 = 36.
	enc.length.should.equal(36);
	enc[0 .. 4].should.equal(cast(ubyte[])[0x00, 0x01, 0x00, 0x10]); // type + length 16
	enc[4 .. 8].should.equal(cast(ubyte[])[0x21, 0x12, 0xA4, 0x42]); // magic cookie
	enc[8 .. 20].should.equal(RFC5769_TXID[]);
	enc[20 .. 24].should.equal(cast(ubyte[])[0x00, 0x06, 0x00, 0x09]); // USERNAME, len 9
	enc[24 .. 33].should.equal(cast(ubyte[]) "evtj:h6vY");
	enc[33 .. 36].should.equal(cast(ubyte[])[0, 0, 0]); // padding
}

@("stun message round-trips through encode/decode")
unittest
{
	Message m;
	m.typ = BINDING_SUCCESS_RESPONSE;
	m.transactionId = RFC5769_TXID;
	m.attributes ~= Attribute(ATTR_USERNAME, cast(ubyte[]) "evtj:h6vY".dup);
	m.attributes ~= Attribute(ATTR_PRIORITY, cast(ubyte[])[0x6e, 0x00, 0x01, 0xff]);

	auto back = Message.decode(m.encode);
	back.typ.should.equal(BINDING_SUCCESS_RESPONSE);
	back.transactionId[].should.equal(RFC5769_TXID[]);
	back.attributes.length.should.equal(2);
	back.get(ATTR_USERNAME).should.equal(cast(ubyte[]) "evtj:h6vY");
	back.get(ATTR_PRIORITY).should.equal(cast(ubyte[])[0x6e, 0x00, 0x01, 0xff]);
	back.contains(ATTR_USE_CANDIDATE).should.equal(false);
}

@("stun FINGERPRINT is CRC-32/ISO-HDLC XOR 0x5354554e (rust rtc-stun vector)")
unittest
{
	// Mirrors rtc-stun's fingerprint_uses_crc_32_iso_hdlc: type 0, zero txid,
	// a SOFTWARE "software" attribute, then FINGERPRINT.
	Message m;
	m.attributes ~= Attribute(0x8022, cast(ubyte[]) "software".dup); // SOFTWARE
	m.addFingerprint();
	auto enc = m.encode;

	// The FINGERPRINT value is the last 4 bytes.
	enc[$ - 4 .. $].should.equal(cast(ubyte[])[0xe4, 0x4c, 0x33, 0xd9]);
	// Everything up to (excluding) the FINGERPRINT TLV matches the rust raw.
	enc[0 .. $ - 8].should.equal(cast(ubyte[])[
		0x00, 0x00, 0x00, 0x14, 0x21, 0x12, 0xA4, 0x42,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x80, 0x22, 0x00, 0x08, 's', 'o', 'f', 't', 'w', 'a', 'r', 'e']);

	m.checkFingerprint().should.equal(true);
}

@("isStunMessage recognises the magic cookie")
unittest
{
	Message m;
	m.typ = BINDING_REQUEST;
	m.transactionId = RFC5769_TXID;
	isStunMessage(m.encode).should.equal(true);

	// Wrong cookie / too short → not STUN.
	auto bad = m.encode.dup;
	bad[4] = 0x00;
	isStunMessage(bad).should.equal(false);
	isStunMessage(cast(ubyte[])[1, 2, 3]).should.equal(false);
}

@("decode rejects a bad magic cookie and a short header")
unittest
{
	auto bad = new ubyte[20];
	Message.decode(bad).should.throwException!Exception; // cookie is zero
	Message.decode(cast(ubyte[])[0, 1, 0, 0]).should.throwException!Exception; // short
}
