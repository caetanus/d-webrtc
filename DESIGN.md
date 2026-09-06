# webrtc (D) v3 — design

**Status:** started 2026-09-05, from zero. This is the third attempt and the
first honest one. `master` was a laundry of webrtc-rs's `rtc`. `v2` was sold as
a rewrite but carried thirteen of the old engine's modules byte-for-byte and
bolted endings onto the laundered SCTP/DTLS/DCEP/connection — the rust smell in
v2 is that carried code. v3 keeps nothing from either. Every module is written
from the RFC and, where a lifecycle question comes up, from Go (pion), never
from webrtc-rs. Nothing is `git`-copied from `master` or `v2`.

## Why the first two failed, so v3 does not repeat it

- **Laundering carries the wire and the happy path; it drops the lifecycle.**
  Both prior engines came up between two copies of themselves and stalled or
  stayed silent off the happy path. So endings are designed before happy paths
  here, not added after.
- **Self-round-trip is not a vector.** v2's SCTP/DCEP codecs were tested only
  against their own encoders. v3 pins every codec to a foreign source: an RFC
  sample, or bytes captured from webrtc-rs / a browser. A test that only agrees
  with itself does not count.
- **"Carry what the tests prove" became "keep the rust."** The tests are a
  behaviour contract, not a licence to keep a rust-shaped implementation. In v3
  the implementation is written fresh; a test carries only if it is a real
  vector or a real behaviour, and it is re-pointed at the new code.

## Laws

1. **Sans-io, and therefore no fibers.** Every layer is `handleInbound(bytes,
   now)`, `handleTimeout(now)`, `gatherOutbound(now)`, plus typed queries. It
   never blocks, sleeps, opens a socket, or calls the clock — `now` is a `long`
   ms the caller passes. **The engine spawns nothing**, so `waitAll` /
   `FiberGroup` / any concurrency primitive have no place in it by construction;
   the consumer (libp2p-dlang) owns the one fiber per session.
2. **Every state machine names its end** before its happy path: `Closed`,
   `Aborted(cause)`, `Failed(cause)` are states with transitions in, not flags.
   Feeding an ended layer is a no-op that says so; asking it for output after
   the end yields the final flight then nothing.
3. **Bounded before allocated.** Every length off the wire is checked against
   what we granted before a byte is copied.
4. **Errors are thrown, not returned.** A malformed message throws; callers do
   not inspect a status. No `Option`/`Result`-shaped returns standing in for an
   exception, no sentinel, no `Nullable` where a throw fits. `Nullable` is only
   for a value that is legitimately absent (no message ready yet), never for an
   error.
5. **Crypto is not ours.** libsodium for SHA/HMAC/random, OpenSSL through deimos
   for DTLS 1.2, the ECDSA P-256 cert and its fingerprint. We own the BIO pump
   and the fingerprint *comparison* — v2 exposed the peer fingerprint and never
   compared it; v3 pins it.

## Layers, bottom-up

```
 connection   assemble the four; demux STUN/ciphertext; pin the peer fingerprint; sequence close
 datachannel  DCEP (RFC 8832): open/ack, negotiated (id 0, no handshake), close = stream reset
 sctp         RFC 4960 assoc + RFC 6525 reset: handshake, DATA/SACK, reassembly, RTO/T1/T2/T3,
              flow control, SHUTDOWN, ABORT, HEARTBEAT, tag validation, Failed
 dtls         DTLS 1.2 over OpenSSL BIO pairs: handshake, app data, close_notify, timeout
 ice          RFC 8445 agent: host candidates, checks, nomination, keepalive, failure; srflx-ready
 stun         RFC 5389/8489 message + attrs, MESSAGE-INTEGRITY, FINGERPRINT, XOR-MAPPED-ADDRESS
```

Endings each layer must implement and test (the v2 gaps, named so they are not
skipped again): SCTP T1-init / T1-cookie / T2-shutdown serviced and a `Failed`
state; SCTP inbound verification-tag check (RFC 4960 §8.5); SCTP HEARTBEAT and
path failure; SCTP 256 KiB max-message and per-stream reassembly bound; ICE
keepalive / consent / restart; DTLS peer-initiated close observed; DataChannels
send refused on a closed/absent channel.

## Build order

Each step: module written fresh, foreign vectors + endings tested, gate green,
one commit. The acceptance test is real and comes first in intent: rust-libp2p's
webrtc-direct transport, both directions, driven from libp2p-dlang's `interop/`
(already built; it reaches ICE and stalls at DTLS today). Every layer is judged
against it as soon as the stack can run.

0. STUN — RFC 5769's four samples, integrity checked against the RFC's own
   precomputed HMAC (not just self-round-trip), fingerprint, XOR-MAPPED-ADDRESS.
1. ICE — lite responder + controlling checker; nomination; retransmit; failure.
2. DTLS — BIO pump; handshake; close_notify observed both ways; fingerprint
   comparison; against `openssl s_client -dtls1_2` as a foreign peer.
3. SCTP — codecs pinned to captured bytes; association with the full timer set,
   tag validation, recovery under loss, SHUTDOWN/ABORT/HEARTBEAT, RE-CONFIG.
4. datachannel — DCEP, negotiated channel, close via stream reset.
5. connection — assembled; fingerprint pinned; sequenced close; then the
   webrtc-direct interop against rust, both directions. That is the milestone.

## Out of scope

Media (RTP/RTCP/SRTP), TURN/relay candidates, ICE-TCP, mDNS candidates, PR-SCTP
beyond accepting the parameter. Browser adds srflx candidates and nothing else.
