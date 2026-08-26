# QUIC and encrypted-traffic research: a reference map

Grew out of paccel's own QUIC work (structural long-header parsing, Initial-packet
decrypt, keylog-based Handshake/1-RTT decrypt, connection-ID/packet-number tracking,
JA3/JA4/JA3S/HASSH fingerprinting). This is a survey of the QUIC spec surface and the
adjacent encrypted-traffic-analysis research space, organized so it's useful as a
standing reference rather than a one-off note.

## 1. Core QUIC RFCs (the transport)

| RFC | Title | Why it matters for traffic research |
|---|---|---|
| [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999) | Version-Independent Properties of QUIC | Defines the only fields an observer can read without knowing the version: header form, DCID/SCID. Everything else is version-gated. |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport | The core transport. Packet number encoding (§17.1, Appendix A), frame types (§19), connection migration (§9), spin bit (§17.4), varint encoding (§16). |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to Secure QUIC | The crypto layer paccel's `quic-decrypt` feature implements: Initial secrets from DCID (§5.2), header protection (§5.4), packet protection (§5.3), key phases (§6). |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control | Not directly observable from a single capture, but explains RTT/loss-driven timing an observer sees externally. |
| [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) | Unreliable Datagram Extension for QUIC | Datagram frames (type 0x30/0x31) — used by MASQUE, WebTransport, some VPN-over-QUIC designs. |
| [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287) | Greasing the QUIC Bit | Defines the fixed-bit-flip greasing paccel already treats permissively (`is_v1_or_v2_family` / version-agnostic parsing). Directly relevant to anti-fingerprinting. |
| [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368) | Compatible Version Negotiation for QUIC | How a client can offer v1 while advertising alternates without a round trip — an evasion-relevant negotiation surface, not yet parsed by paccel. |
| [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) | QUIC Version 2 | Different salts (paccel's `V2_SALT`), different long-header type bits, renamed HKDF labels ("quicv2 key" etc.) — a second version family to track. |

## 2. Application mappings on top of QUIC

| RFC / draft | Title | Relevance |
|---|---|---|
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) | HTTP/3 | The dominant real-world QUIC payload. Blocked in paccel on STREAM-frame reassembly (not yet built). |
| [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) | QPACK | HTTP/3's header compression — the HPACK-equivalent gap, same class of problem as paccel's current no-HPACK HTTP/2 support. |
| [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) | HTTP Datagrams and the Capsule Protocol | Underpins MASQUE. |
| [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298) | Proxying UDP in HTTP (MASQUE) | UDP-over-HTTP/3 tunneling — directly relevant to VPN-over-QUIC traffic (e.g. iCloud Private Relay) and to censorship-circumvention tooling. Distinguishing "QUIC carrying MASQUE" from "QUIC carrying ordinary HTTP/3" from the outside is an open fingerprinting question. |
| [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220) | Bootstrapping WebTransport with HTTP/3 | Another QUIC-datagram consumer with its own traffic shape. |
| [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) §3.1 (Alt-Svc/Alt-Used) | — | How clients discover an HTTP/3 endpoint from HTTP/1-2 — the pre-QUIC signal that predicts a coming QUIC flow. |

## 3. Privacy/observability-relevant sub-specs

These are the parts of the spec that were *deliberately designed* around what an
on-path observer can and cannot learn — the most directly relevant reading for
encrypted-traffic research, since they document the threat model QUIC's authors had
in mind.

- **RFC 9001 §5.2 (Initial secrets)** — deliberately *not* secret. Derived from the
  client's own DCID via a public salt, specifically so Initial ClientHello (SNI/ALPN)
  stays inspectable on-path, same as a plaintext TLS ClientHello over TCP. This is
  the whole basis for paccel's `quic-decrypt` feature being able to do real decrypt
  without any external key material — see [RFC 9001 §9.5](https://www.rfc-editor.org/rfc/rfc9001#section-9.5)
  for the spec's own reasoning about why this doesn't weaken confidentiality.
- **RFC 9000 §17.4 (Spin Bit)** — an intentional, optional, unauthenticated 1-bit RTT
  signal, explicitly designed to leak *only* RTT and nothing else, with a required
  random-disable-for-some-connections mode specifically to prevent it being turned
  into a tracking/fingerprinting vector. Directly relevant prior art for "what's the
  right way to expose one bit of telemetry without it becoming a side channel."
- **RFC 9000 §9 (Connection Migration) / §5.1 (Connection IDs)** — multiple
  active CIDs per connection, NEW_CONNECTION_ID/RETIRE_CONNECTION_ID frames, and
  the requirement that CIDs be unlinkable to each other. This is the mechanism that
  defeats naive 4-tuple-based flow tracking across NAT rebinding/migration — an
  observer needs the CID issuance sequence (which paccel's `QuicConnectionTracker`
  partially models) to keep tracking a migrating connection.
- **RFC 9000 §19.1 (PADDING frame) / §14.1 (Initial datagram size)** — the mandatory
  1200-byte minimum Initial size exists specifically to prevent UDP amplification,
  but as a side effect also destroys most of the low-hanging packet-length side
  channel that plain-TCP-TLS ClientHello sizing has.
- **[QUIC-LB (draft-ietf-quic-load-balancers)](https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/)** —
  not yet an RFC, but the closest thing to a spec for how real deployments encode
  routing information *inside* the otherwise-opaque server-chosen CID. Relevant if
  you're trying to infer backend topology from CID structure in the wild (Cloudflare,
  Google, etc. all use CID-encoded routing).

## 4. Fingerprinting / classification research surface

What's actually observable about a QUIC flow without decryption, roughly in order of
how much of the connection you need to see:

| Signal | Source | What paccel exposes |
|---|---|---|
| Version, long-header type, DCID/SCID length+bytes | Every long-header packet | `parse_quic_long_header` (A1) — fully structural, no crypto needed |
| Initial ClientHello: SNI, ALPN, cipher suites, extension order | Decrypted Initial (publicly derivable) | `decrypt_initial_client_hello` (A2) |
| JA3/JA4-style TLS fingerprint of the QUIC ClientHello | Same decrypted ClientHello | `fingerprint::ja3_string`/`ja4_string`, `Ja4Transport::Quic` |
| Retry token presence/shape, integrity tag | Retry packets | `QuicLongHeader.retry_token`/`retry_integrity_tag` |
| Packet-number growth rate, largest-PN-seen | Requires per-connection state across packets | `QuicConnectionTracker::reconstruct_packet_number` (A4), RFC 9000 Appendix A |
| Connection-ID issuance/rotation pattern | NEW_CONNECTION_ID frames (needs STREAM/frame parsing beyond A1) | Not yet — frame-level parsing beyond CRYPTO/ACK/PADDING isn't built |
| Spin bit sequence | Short-header packets, needs authoritative DCID-length knowledge | Short-header is currently only a weak heuristic (`UdpAppHint::QuicShort`, ~25% false-positive without tracker state) |
| Packet size/timing distribution | Any packets, no decrypt needed | Out of scope for a parser — this is where classical traffic-analysis tooling (nDPI, Zeek's QUIC analyzer, ML classifiers over inter-arrival/size sequences) lives |
| Handshake/1-RTT plaintext (full ClientCert, ALPN confirm, etc.) | Requires `SSLKEYLOGFILE` — cannot be derived | `decrypt_packet_with_secret` + `QuicKeyLog` (A3), same model as Wireshark |

Prior art worth knowing about specifically for QUIC/HTTP-3 fingerprinting:

- **JA3/JA4 for QUIC** — same TLS ClientHello fingerprinting techniques as TCP+TLS,
  just extracted from the decrypted Initial CRYPTO stream instead of a plaintext TCP
  segment. FoxIO's JA4 spec has a dedicated `q` transport-type prefix for exactly
  this (paccel's `Ja4Transport::Quic`).
- **QUIC fingerprinting beyond TLS** — since QUIC exposes transport parameters
  (RFC 9000 §18) inside the *encrypted* CRYPTO stream (a `quic_transport_parameters`
  TLS extension, ID 0x39/57), a full fingerprint also covers things like initial
  max data, ack-delay-exponent, active-connection-id-limit — implementation-specific
  defaults that vary by QUIC stack (quiche vs. quic-go vs. msquic vs. ngtcp2) even
  when TLS-layer fields match. Not yet something paccel parses (would need full
  Initial-payload TLS extension walking beyond SNI/ALPN/cipher suites).
- **uTLS / QUIC equivalents** — libraries that deliberately randomize/mimic another
  implementation's ClientHello shape to evade fingerprint-based blocking (the same
  arms race TCP+TLS has had for years, now replaying on QUIC). Directly motivates why
  a single static JA3/JA4 value is a weak long-term classifier on its own.
- **Website fingerprinting over QUIC/HTTP-3** — a body of academic work (post-2020)
  showing that even fully encrypted QUIC traffic leaks enough via packet-size/timing
  sequences to re-identify visited pages with attacks originally designed for Tor;
  HTTP/3's multiplexing behaves differently from HTTP/2 enough to change (usually
  reduce, sometimes not) classifier accuracy depending on the study.
- **Censorship-circumvention angle** — QUIC's UDP-only transport and (until GREASE
  RFC 9287) fixed-bit made it an easy DPI target for outright blocking in several
  national censorship regimes; the greasing RFC and version-negotiation ambiguity are
  direct responses to that arms race, not just protocol hygiene.

## 5. Related crypto/format specs paccel already touches

| RFC | Title | Where it shows up |
|---|---|---|
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | TLS 1.3 | HKDF-Expand-Label (`hkdf_expand_label`), the ClientHello/ServerHello structure `tls.rs` parses, the 4 keylog labels `QuicKeyLog` consumes. |
| [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) | GREASE | The `0x?A?A` pattern paccel's `decode_packet_number`/fingerprint code filters out of cipher suites, extensions, and QUIC versions. |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HKDF | The Extract/Expand primitive underlying every QUIC key derivation. |
| NSS Key Log Format (no RFC — [Mozilla wiki](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)) | `SSLKEYLOGFILE` | The de facto standard `QuicKeyLog::parse` implements — same format Wireshark/curl/browsers already write, not QUIC-specific despite being essential for QUIC Handshake/1-RTT visibility. |
| [RFC 9345](https://www.rfc-editor.org/rfc/rfc9345) | qlog: Structured Logging for QUIC | Not implemented anywhere in paccel, but the standard structured-event-log format QUIC implementations (quiche, ngtcp2, quic-go, msquic, Chromium) can emit for exactly this kind of research — often a better ground-truth source than reconstructing state from the wire alone, since it includes internal state a passive observer can't recover (real RTT estimates, loss detection decisions, congestion window). |

## 6. Ground-truth tooling for this kind of research

- **tshark/Wireshark's QUIC dissector** — used throughout paccel's own development as
  an independent oracle (never as a source of committed binary test data — see the
  README's fixture-provenance notes). Supports `-o tls.keylog_file:` for the same
  `SSLKEYLOGFILE` format `QuicKeyLog` consumes.
- **Real QUIC stack implementations**, useful both as traffic generators and as
  fingerprint-diversity sources: [quiche](https://github.com/cloudflare/quiche)
  (Cloudflare, Rust), [ngtcp2](https://github.com/ngtcp2/ngtcp2) (C, what curl's
  `--http3` links against — used earlier in this project's own HTTP/2 fixture work),
  [quic-go](https://github.com/quic-go/quic-go) (Go), [msquic](https://github.com/microsoft/msquic)
  (Microsoft, C).
- **Public QUIC/HTTP-3 test vectors** — the Wireshark project's own test-suite
  captures (`quic-with-secrets.pcapng` and siblings) are the standard reference
  corpus most QUIC-parsing tooling gets validated against; paccel intentionally
  stopped redistributing these (see `CHANGELOG.md`/README) but they remain the right
  place to *pull fresh test vectors from* for future development, one capture at a
  time, cross-checked rather than bulk-imported.
- **RFC 9001 Appendix A** — the only officially blessed static test vector (Initial
  secrets, header protection, full protected/unprotected packet bytes) for QUIC v1
  Initial crypto. paccel's own `decrypts_rfc9001_appendix_a2_client_initial` test
  is built directly from it.

## 7. Open gaps (from this project, as a research-priority list)

Ordered roughly by "most useful next thing to build for encrypted-traffic-analysis
work specifically," not by general protocol-completeness:

1. **QUIC STREAM-frame parsing** — blocks HTTP/3, blocks connection-ID
   issuance/rotation tracking beyond the Initial exchange, blocks transport-parameter
   extraction. The single highest-leverage gap for this research area.
2. **Transport parameters extension (0x39) parsing inside the decrypted Initial
   CRYPTO stream** — cheap once STREAM parsing exists, high fingerprinting value
   (implementation-identifying defaults independent of the TLS layer).
3. **Coalesced-packet splitting** — a single UDP datagram legitimately carries
   multiple QUIC packets (e.g. Initial + Handshake back-to-back); not splitting them
   means paccel currently only sees the first.
4. **Version Negotiation packet parsing** — the list of alternate versions a server
   offers is itself a fingerprintable/classifiable signal, currently unparsed.
5. **Spin-bit statefulness** — once `QuicConnectionTracker` has authoritative
   short-header DCID-length knowledge, extracting the spin bit sequence per
   connection becomes possible; currently short-header classification is too weak
   (~25% false-positive) to build on.
