# webrtc (D)

A WebRTC **data-channel** transport for D — the engine libp2p's `webrtc-direct`
needs (ICE → DTLS → SCTP → DCEP). It is a faithful, AI-generated **laundry** of
[webrtc-rs's sans-io rewrite `rtc`](https://github.com/webrtc-rs/rtc): pure state
machines, no async runtime baked in, so it plugs into any I/O loop (vibe-core in
libp2p-dlang) without a competing reactor.

Crypto uses **libsodium** throughout (X25519, ChaCha20-Poly1305, SHA-256,
Ed25519), the same choice as the rest of the libp2p-dlang stack. The two
primitives libsodium doesn't provide — ECDSA P-256 and X.509 — are taken from a C
library (OpenSSL/deimos) only if hand-porting them proves large; with Ed25519
certs the two-node case needs neither.

This is a standalone dub package that libp2p-dlang consumes as a dependency.

## Layout (mirrors the `rtc-*` crates)

| module | laundered from | role |
|--------|----------------|------|
| `webrtc.stun`        | rtc-stun        | STUN (RFC 5389/5769) |
| `webrtc.sctp`        | rtc-sctp        | SCTP association / streams |
| `webrtc.ice`         | rtc-ice         | ICE agent (ice-lite server) |
| `webrtc.dtls`        | rtc-dtls        | DTLS 1.2 handshake + record |
| `webrtc.datachannel` | rtc-datachannel | DCEP (RFC 8832) |

Ground truth: `~/lab/webrtc-rtc`. Every rust unit test → a D parity test.

## Test

    dub test        # unit-threaded + fluent-asserts
