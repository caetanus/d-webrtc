# webrtc (D)

A WebRTC **data-channel** engine for D — the transport stack libp2p's
`webrtc-direct` needs: **ICE → DTLS → SCTP → DCEP**, assembled into a single
`PeerConnection`.

It is a faithful, AI-generated **laundry** of
[webrtc-rs's sans-io rewrite `rtc`](https://github.com/webrtc-rs/rtc): pure state
machines, **no async runtime baked in**. You feed it inbound UDP datagrams and
drain outbound ones; it never touches a socket or a clock. That means it drops
into any I/O loop (vibe-core, in libp2p-dlang) without a competing reactor.

Everything below UDP and above the data channel is handled internally, so a
caller deals only in datagrams and messages:

```
DataChannels (DCEP)      application messages
SCTP association         reliable, multiplexed streams — runs *inside* DTLS
DTLS 1.2                 encryption + certificate-fingerprint pinning
ICE agent                connectivity over UDP host candidates (STUN)
UDP                      the caller's socket
```

## Crypto

Per the project rule *libsodium → Deimos(OpenSSL) → hand-port*:

- **libsodium** for the primitives it provides (SHA-256, HMAC building blocks,
  randomness) used by STUN and SCTP.
- **OpenSSL via `deimos.openssl`** for DTLS 1.2, the self-signed **ECDSA P-256**
  certificate, and its X.509/SHA-256 fingerprint (the `a=fingerprint` / libp2p
  `/certhash`). DTLS is *not* laundered from `rtc-dtls` — where a Deimos binding
  exists, we use it.

## Layout

| module | source | role |
|--------|--------|------|
| `webrtc.stun`        | laundry of rtc-stun        | STUN message + attributes (RFC 5389/5769) |
| `webrtc.sctp`        | laundry of rtc-sctp        | SCTP association, streams, queues, timers (RFC 4960) |
| `webrtc.ice`         | laundry of rtc-ice         | ICE agent — connectivity checks + USE-CANDIDATE nomination |
| `webrtc.dtls`        | OpenSSL via deimos.openssl | DTLS 1.2 transport + ECDSA P-256 certificate |
| `webrtc.datachannel` | laundry of rtc-datachannel | DCEP data channels (RFC 8832) |
| `webrtc.connection`  | —                          | `PeerConnection`: the four layers assembled |

Only the **webrtc-direct** path is ported. TURN, mDNS, srflx/relay candidates,
ICE-TCP, media (RTP/RTCP/SRTP), ICE role-conflict switching and keepalive are
deliberately dropped.

## Usage sketch

```d
import webrtc.connection;

// Roles follow libp2p webrtc-direct: dialer = ICE-controlling / DTLS-client /
// SCTP-client; listener is the mirror.
auto pc = new PeerConnection(Perspective.dialer, localIceCreds, tieBreaker,
    Certificate.generate());
pc.addLocalCandidate(host("1.2.3.4", 40000));
pc.setRemoteIce(remoteIceCreds, host("5.6.7.8", 50000));

// Sans-io: pump datagrams from/to your UDP socket.
foreach (dg; pc.gatherOutbound(nowMs)) socket.sendTo(dg.data, dg.dst);
pc.handleDatagram(received, from, to, nowMs);

// Once pc.isReady(), open and use a data channel.
auto sid = pc.channels.open(DataChannelConfig("chat", "proto"));
pc.channels.send(sid, cast(ubyte[]) "hello".dup, /*isString*/ true);
```

`peerFingerprint()` exposes the peer's certhash for multiaddr verification.

## Status

The engine is **complete and verified end to end** — over an in-memory datagram
pump, two `PeerConnection`s bring up ICE + DTLS + SCTP, pin certificate
fingerprints, and carry data-channel messages both ways across the whole stack.

Deferred (loss-recovery only — the loss-free path is complete): SCTP
fast-retransmit, T3-rtx timer-driven retransmission, PR-SCTP forward-TSN, stream
reset/reconfig, and shutdown.

## Test

    dub run -c ut     # unit-threaded + fluent-asserts (68 tests)

Ground truth for the laundry: the `rtc-*` crates at
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc). Every ported piece has a D
parity test against its rust counterpart.

## License

MIT — see [LICENSE](LICENSE).
