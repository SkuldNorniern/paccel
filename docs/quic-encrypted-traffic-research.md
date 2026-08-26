# QUIC and encrypted-traffic research: a reference map

Grew out of paccel's own QUIC work (structural long-header parsing, Initial-packet
decrypt, keylog-based Handshake/1-RTT decrypt, connection-ID/packet-number tracking,
JA3/JA4/JA3S/HASSH fingerprinting). This is a survey of the QUIC spec surface and the
adjacent encrypted-traffic-analysis research space, organized so it's useful as a
standing reference rather than a one-off note. Part I is the protocol spec itself,
down to the byte level where it matters for observation/fingerprinting. Part II is
applied technique: identifying streaming/video traffic and identifying malicious
traffic, both without breaking encryption.

All byte-level constants in Part I were verified against RFC/IANA text directly
before being written down here (RFC-fetch, not from memory), except where flagged
otherwise inline.

---

# Part I — the protocol, in detail

## 1. Core QUIC RFCs (the transport)

| RFC | Title | Why it matters for traffic research |
|---|---|---|
| [RFC 8999](https://www.rfc-editor.org/rfc/rfc8999) | Version-Independent Properties of QUIC | Defines the only fields an observer can read without knowing the version: header form, DCID/SCID. Everything else is version-gated. |
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC: A UDP-Based Multiplexed and Secure Transport | The core transport. Packet number encoding (§17.1, Appendix A), frame types (§19), connection migration (§9), spin bit (§17.4), varint encoding (§16). |
| [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) | Using TLS to Secure QUIC | The crypto layer paccel's `quic-decrypt` feature implements: Initial secrets from DCID (§5.2), header protection (§5.4), packet protection (§5.3), key phases (§6), Retry integrity (§5.8). |
| [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) | QUIC Loss Detection and Congestion Control | Not directly observable from a single capture, but explains RTT/loss-driven timing an observer sees externally. |
| [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) | Unreliable Datagram Extension for QUIC | Datagram frames (type 0x30/0x31) — used by MASQUE, WebTransport, some VPN-over-QUIC designs. |
| [RFC 9287](https://www.rfc-editor.org/rfc/rfc9287) | Greasing the QUIC Bit | Defines the fixed-bit-flip greasing paccel already treats permissively (`is_v1_or_v2_family` / version-agnostic parsing). Directly relevant to anti-fingerprinting. |
| [RFC 9368](https://www.rfc-editor.org/rfc/rfc9368) | Compatible Version Negotiation for QUIC | How a client can offer v1 while advertising alternates without a round trip — an evasion-relevant negotiation surface, not yet parsed by paccel. Also defines the `version_information` transport parameter, ID `0x11` (see §2.4). |
| [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) | QUIC Version 2 | Different salts (paccel's `V2_SALT`), different long-header type bits, renamed HKDF labels ("quicv2 key" etc.), different Retry integrity constants (§2.5) — a second version family to track. |

## 2. Wire format, byte by byte

This section exists so the higher-level material in Parts I/II can point at exact
bits/bytes instead of hand-waving. Everything here is what an observer needs to
parse a packet structurally, before any decryption.

### 2.1 Variable-length integers (RFC 9000 §16)

Every length/offset/ID field in QUIC (except a few fixed-size ones like connection
IDs) uses this encoding. The two most-significant bits of the *first* byte give the
total encoded length; the remaining 6 bits of that byte plus all subsequent bytes
are the value, big-endian:

| First-byte top 2 bits | Total length | Usable value bits | Max value |
|---|---|---|---|
| `00` | 1 byte | 6 | 63 |
| `01` | 2 bytes | 14 | 16,383 |
| `10` | 4 bytes | 30 | 1,073,741,823 |
| `11` | 8 bytes | 62 | 4,611,686,018,427,387,903 |

paccel's `decode_varint` in `src/layer/application/quic/mod.rs` implements exactly
this table.

### 2.2 Long header first byte (RFC 9000 §17.2)

Used for Initial, 0-RTT, Handshake, and Retry packets — sent only before/during the
handshake, always carries the full Version + DCID + SCID.

```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|1|1|T T|X X X X|
+-+-+-+-+-+-+-+-+
 |  |
 |  +-- Fixed Bit (0x40) — MUST be 1 in RFC 9000-conformant traffic;
 |      RFC 9287 permits greasing this to 0 in a fraction of packets
 |      specifically to stop DPI middleboxes ossifying on it always being 1.
 +----- Header Form (0x80) — 1 = long header.
```

`TT` (bits masked by `0x30`) is the **Long Packet Type**, and its meaning is
version-dependent — this is a real, easy-to-get-wrong trap: RFC 9000's own `TT`
values (`00`=Initial, `01`=0-RTT, `10`=Handshake, `11`=Retry) apply to QUIC v1;
QUIC v2 (RFC 9369 §3.2) deliberately **remaps** these same 2 bits to a different
assignment specifically to prevent a version-negotiation downgrade attack that a
fixed mapping would enable. paccel's `is_v1_or_v2_family`/`quic_packet_type`
functions already branch on version for exactly this reason — always resolve
packet type through the version, never assume `TT`'s meaning is version-independent.

`XXXX` (the low 4 bits, `0x0f`) differ by packet type:
- Initial / 0-RTT / Handshake: `Reserved(2 bits)` + `Packet Number Length(2 bits)`,
  where the PN-length field encodes `(actual PN byte count) - 1`, so `00`→1 byte,
  `11`→4 bytes. These 4 bits are **header-protected** (RFC 9001 §5.4.1) — an
  observer cannot read the true reserved/PN-length bits without removing header
  protection first (protected values are masked with `mask[0] & 0x0f`).
- Retry: `Unused(4 bits)` — no packet number field exists on a Retry packet at all.

After the first byte: `Version (4 bytes)`, `DCID Length (1 byte)` + `DCID`,
`SCID Length (1 byte)` + `SCID` — all of this is **not** header-protected and
readable by any observer regardless of version knowledge (RFC 8999's
version-independent invariants). Everything after SCID (Token for Initial, Length,
Packet Number, and the encrypted payload) is type- and version-specific.

### 2.3 Short header first byte (RFC 9000 §17.3.1)

Used for every 1-RTT packet after the handshake completes — no Version/DCID-length/
SCID fields, since by this point both endpoints already know each other's CIDs from
the handshake's NEW_CONNECTION_ID exchange.

```
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|0|1|S|R R|K|P P|
+-+-+-+-+-+-+-+-+
 | | |   | |
 | | |   | +----- Packet Number Length (0x03, 2 bits) — header-protected.
 | | |   +------- Key Phase (0x04) — header-protected; toggles on each 1-RTT
 | | |            key update (RFC 9001 §6). Observable once header protection
 | | |            is removed, but requires knowing 1-RTT keys to remove it at
 | | |            all — Key Phase is not observable passively without decrypt.
 | | +----------- Reserved (0x18, 2 bits) — header-protected.
 | +------------- Spin Bit (0x20) — NOT header-protected, deliberately
 |                 observable by design (RFC 9000 §17.4). See §3 below.
 +---------------- Fixed Bit (0x40) — same greasing caveat as long header.
Header Form (0x80) = 0 for short header.
```

The DCID immediately follows the first byte, with **no length prefix** — a receiver
only knows how many bytes to read because it chose that CID's length itself when it
issued it via NEW_CONNECTION_ID during the handshake. **This is the reason a purely
passive short-header observer cannot reliably parse 1-RTT packets at all** without
having seen that connection's handshake: DCID length is out-of-band state, not a
wire-visible field. It's also exactly why paccel's short-header classification is
presently just a heuristic (`app[0] & 0xc0 == 0x40`, checking Header-Form=0/Fixed-
Bit=1 with no further validation) and why `QuicConnectionTracker` exists — to learn
each direction's DCID length from the Initial/Handshake exchange and make later
short-header parsing authoritative instead of guessed.

### 2.4 Transport parameters (RFC 9000 §18.2, extended by later RFCs)

Sent inside the TLS `quic_transport_parameters` extension (extension ID 57 /
`0x39`, [RFC 9001 §8.2](https://www.rfc-editor.org/rfc/rfc9001#section-8.2)) as
part of the ClientHello/EncryptedExtensions — i.e. present in the *plaintext*
Initial CRYPTO stream for the client's copy, decryptable the same way paccel
already decrypts SNI/ALPN from Initial. Each parameter is a varint ID, followed by
a varint length, followed by that many bytes of value — a simple TLV list, easy to
walk generically. Full registry (source: IANA QUIC parameters registry, mirroring
RFC 9000 §18.2 plus later RFCs):

| ID | Name | Defined in |
|---|---|---|
| `0x00` | `original_destination_connection_id` | RFC 9000 |
| `0x01` | `max_idle_timeout` | RFC 9000 |
| `0x02` | `stateless_reset_token` | RFC 9000 |
| `0x03` | `max_udp_payload_size` | RFC 9000 |
| `0x04` | `initial_max_data` | RFC 9000 |
| `0x05` | `initial_max_stream_data_bidi_local` | RFC 9000 |
| `0x06` | `initial_max_stream_data_bidi_remote` | RFC 9000 |
| `0x07` | `initial_max_stream_data_uni` | RFC 9000 |
| `0x08` | `initial_max_streams_bidi` | RFC 9000 |
| `0x09` | `initial_max_streams_uni` | RFC 9000 |
| `0x0a` | `ack_delay_exponent` | RFC 9000 |
| `0x0b` | `max_ack_delay` | RFC 9000 |
| `0x0c` | `disable_active_migration` | RFC 9000 |
| `0x0d` | `preferred_address` | RFC 9000 |
| `0x0e` | `active_connection_id_limit` | RFC 9000 |
| `0x0f` | `initial_source_connection_id` | RFC 9000 |
| `0x10` | `retry_source_connection_id` | RFC 9000 |
| `0x11` | `version_information` | RFC 9368 |
| `0x20` | `max_datagram_frame_size` | RFC 9221 |

(Note: `0x11`, not `0x20`, is `version_information` — `0x20` is a different,
unrelated parameter from the DATAGRAM extension. Easy to misattribute; worth
double-checking against source if implementing this table in code.)

**Why this table matters for fingerprinting**: every real QUIC stack ships with its
own defaults for the numeric parameters (`initial_max_data`,
`active_connection_id_limit`, `ack_delay_exponent`, etc.) that vary by
implementation and sometimes by version, independent of anything at the TLS layer.
Two clients with byte-identical JA3/JA4 (same TLS library) can still be
distinguished by transport-parameter values if they're using different QUIC stacks
on top of that TLS library — a strictly finer-grained fingerprint dimension than
JA3/JA4 alone, currently unexploited by paccel (see Part I §7, gap list).

### 2.5 Retry Integrity Tag (RFC 9001 §5.8 / RFC 9369 §3.3.3)

A Retry packet has no packet-number field and isn't AEAD-protected the normal way;
instead its authenticity is checked with a **fixed, publicly-known** AEAD key and
nonce (the same for every QUIC connection using a given version — this is
intentionally not a secret, since a Retry's job is DoS mitigation via a stateless
cookie, not confidentiality). Verified directly against RFC text:

| | QUIC v1 (RFC 9001 §5.8) | QUIC v2 (RFC 9369 §3.3.3) |
|---|---|---|
| Key | `be0c690b9f66575a1d766b54e368c84` | `8fb4b01b56ac48e260fbcbcead7ccc92` |
| Nonce | `461599d35d632bf2239825bb` | `d86969bc2d7c6d9990efb04a` |

AES-128-GCM over an empty plaintext, with AAD = the original client-chosen DCID
(length-prefixed) followed by the entire Retry packet header (everything up to but
not including the 16-byte tag itself) — produces the 16-byte tag that's appended to
every Retry packet. Since the key/nonce are public, **anyone can compute and verify
this tag** — it authenticates "this Retry really came from a server that saw the
original Initial," not secrecy. paccel currently extracts `retry_token` and
`retry_integrity_tag` structurally (A1) but doesn't verify the tag; doing so would
let a passive observer distinguish a genuine Retry from a spoofed/injected one, a
useful anti-tampering check for anyone building defensive tooling on top of this.

### 2.6 Frame type registry (RFC 9000 §19, extended)

Frames live inside the decrypted payload of any packet type that carries them
(Initial/0-RTT/Handshake/1-RTT — never Retry or Version Negotiation, neither of
which have a payload in this sense). One or more frames are packed back-to-back to
fill a packet. Source: IANA QUIC frame-types registry (RFC 9000's own §19 text
repeatedly failed to fetch cleanly during verification for this doc — flagging
that as a tooling note, not a spec ambiguity; the IANA registry is the same data,
just easier to fetch reliably).

| ID | Frame | Notes |
|---|---|---|
| `0x00` | PADDING | Zero-length, no content — bulk filler, e.g. to reach the 1200-byte Initial minimum. |
| `0x01` | PING | Elicits an ACK; no content. |
| `0x02`–`0x03` | ACK / ACK_ECN | The ECN variant carries 3 extra ECN counts. |
| `0x04` | RESET_STREAM | Abrupt stream termination. |
| `0x05` | STOP_SENDING | Request peer stop sending on a stream. |
| `0x06` | CRYPTO | Carries the TLS handshake byte stream — what paccel's `extract_crypto_stream` reassembles. |
| `0x07` | NEW_TOKEN | Server issues a future-Initial token to skip Retry. |
| `0x08`–`0x0f` | STREAM | Low 3 bits are flags: `0x04`=OFF (explicit offset present), `0x02`=LEN (explicit length present), `0x01`=FIN (final frame of the stream) — standard/stable QUIC knowledge, not independently RFC-text-fetched in this verification pass; worth a second confirmation before treating as authoritative in code. |
| `0x10` | MAX_DATA | Connection-level flow control update. |
| `0x11` | MAX_STREAM_DATA | Per-stream flow control update. |
| `0x12`–`0x13` | MAX_STREAMS (bidi / uni) | Stream-count limit update. |
| `0x14` | DATA_BLOCKED | Sender-side flow-control-blocked signal. |
| `0x15` | STREAM_DATA_BLOCKED | Per-stream version of the above. |
| `0x16`–`0x17` | STREAMS_BLOCKED (bidi / uni) | Stream-count-limited signal. |
| `0x18` | NEW_CONNECTION_ID | Issues a new CID + stateless reset token — the mechanism behind connection-migration unlinkability (§3). |
| `0x19` | RETIRE_CONNECTION_ID | Retires a previously issued CID. |
| `0x1a` | PATH_CHALLENGE | Path validation (migration, NAT rebinding). |
| `0x1b` | PATH_RESPONSE | Response to PATH_CHALLENGE. |
| `0x1c`–`0x1d` | CONNECTION_CLOSE (QUIC-layer / application-layer) | Carries a close reason — the application-layer variant can leak protocol-specific error strings. |
| `0x1e` | HANDSHAKE_DONE | Server-to-client only; confirms handshake completion. |
| `0x1f` | IMMEDIATE_ACK | draft-ietf-quic-ack-frequency — not yet an RFC. |
| `0x30`–`0x31` | DATAGRAM | RFC 9221 — unreliable, unordered app data; what MASQUE/WebTransport build on. |
| `0x3e`–`0x3f` | PATH_ACK | draft-ietf-quic-multipath — not yet an RFC. |
| `0xaf` | ACK_FREQUENCY | Same ack-frequency draft as `0x1f`. |

paccel's `extract_crypto_stream` currently walks only PADDING/PING/ACK/CRYPTO —
sufficient for Initial-packet ClientHello extraction, but the single biggest
structural gap for everything past that (STREAM for HTTP/3 and connection-ID
tracking, NEW_CONNECTION_ID for the unlinkability-defeating tracking mentioned
in §3, CONNECTION_CLOSE for error-reason leakage).

---

# Part II — applied encrypted-traffic analysis

## 3. Privacy/observability-relevant sub-specs

The parts of the spec that were *deliberately designed* around what an on-path
observer can and cannot learn — the most directly relevant reading for
encrypted-traffic research, since they document the threat model QUIC's authors
had in mind, which in turn tells you what's a legitimate observable signal versus
what would be exploiting an implementation bug.

- **RFC 9001 §5.2 (Initial secrets)** — deliberately *not* secret. Derived from the
  client's own DCID via a public salt, specifically so Initial ClientHello (SNI/ALPN)
  stays inspectable on-path, same as a plaintext TLS ClientHello over TCP. This is
  the whole basis for paccel's `quic-decrypt` feature being able to do real decrypt
  without any external key material — see [RFC 9001 §9.5](https://www.rfc-editor.org/rfc/rfc9001#section-9.5)
  for the spec's own reasoning about why this doesn't weaken confidentiality.
- **RFC 9000 §17.4 (Spin Bit)** — an intentional, optional, unauthenticated 1-bit RTT
  signal (bit `0x20` in the short-header first byte, §2.3), explicitly designed to
  leak *only* RTT and nothing else, with a required random-disable-for-some-
  connections mode specifically to prevent it being turned into a tracking/
  fingerprinting vector. Directly relevant prior art for "what's the right way to
  expose one bit of telemetry without it becoming a side channel."
- **RFC 9000 §9 (Connection Migration) / §5.1 (Connection IDs)** — multiple
  active CIDs per connection, NEW_CONNECTION_ID/RETIRE_CONNECTION_ID frames (§2.6),
  and the requirement that CIDs be unlinkable to each other. This is the mechanism
  that defeats naive 4-tuple-based flow tracking across NAT rebinding/migration — an
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
| Transport parameters (§2.4) — implementation-identifying defaults | Same decrypted Initial CRYPTO stream, `quic_transport_parameters` TLS extension `0x39` | Not yet parsed |
| Retry token presence/shape, integrity tag | Retry packets | `QuicLongHeader.retry_token`/`retry_integrity_tag` (tag not verified, see §2.5) |
| Packet-number growth rate, largest-PN-seen | Requires per-connection state across packets | `QuicConnectionTracker::reconstruct_packet_number` (A4), RFC 9000 Appendix A |
| Connection-ID issuance/rotation pattern | NEW_CONNECTION_ID frames (needs frame parsing beyond A1/§2.6) | Not yet — frame-level parsing beyond CRYPTO/ACK/PADDING isn't built |
| Spin bit sequence | Short-header packets, needs authoritative DCID-length knowledge (§2.3) | Short-header is currently only a weak heuristic (`UdpAppHint::QuicShort`, ~25% false-positive without tracker state) |
| Packet size/timing distribution | Any packets, no decrypt needed | Out of scope for a parser — this is where classical traffic-analysis tooling (nDPI, Zeek's QUIC analyzer, ML classifiers over inter-arrival/size sequences) lives |
| ECH presence (extension `0xfe0d`) | ClientHello extension list | Not yet parsed — see §8.4 |
| Handshake/1-RTT plaintext (full ClientCert, ALPN confirm, etc.) | Requires `SSLKEYLOGFILE` — cannot be derived | `decrypt_packet_with_secret` + `QuicKeyLog` (A3), same model as Wireshark |

Prior art worth knowing about specifically for QUIC/HTTP-3 fingerprinting:

- **JA3/JA4 for QUIC** — same TLS ClientHello fingerprinting techniques as TCP+TLS,
  just extracted from the decrypted Initial CRYPTO stream instead of a plaintext TCP
  segment. FoxIO's JA4 spec has a dedicated `q` transport-type prefix for exactly
  this (paccel's `Ja4Transport::Quic`).
- **QUIC fingerprinting beyond TLS** — transport parameters (§2.4) are a fingerprint
  dimension independent of the TLS layer: two clients using the same TLS library
  (identical JA3/JA4) but different QUIC stacks on top of it (e.g. both link
  BoringSSL, one via Chromium's own QUIC, one via a from-scratch reimplementation)
  still diverge on `initial_max_data`/`active_connection_id_limit`/
  `ack_delay_exponent` defaults. Not yet parsed by paccel.
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
| NSS Key Log Format (no RFC — [Mozilla docs](https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html)) | `SSLKEYLOGFILE` | The de facto standard `QuicKeyLog::parse` implements — same format Wireshark/curl/browsers already write, not QUIC-specific despite being essential for QUIC Handshake/1-RTT visibility. |
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

## 7. Applied: identifying streaming/video services (YouTube-class traffic) in encrypted QUIC

YouTube, and most large video platforms, moved their delivery path onto QUIC/HTTP-3
years ago (Google was QUIC's original deployer, well before RFC 9000). None of the
techniques below need to break TLS 1.3 — they classify the *shape* of the traffic,
which is exactly what stays observable by design (see §3 above on what the spec
deliberately leaves exposed).

### 7.1 What's visible without any decryption

- **SNI in the Initial ClientHello** (paccel: `decrypt_initial_client_hello` →
  `TlsClientHello.server_name`). Historically the single strongest signal —
  `*.googlevideo.com`, `youtube.com`, `ytimg.com` etc. This is the first thing to
  check and, absent ECH (§7.4), usually sufficient on its own for coarse
  "is this YouTube" classification.
- **Destination IP / ASN / CDN ownership.** Google serves video from its own ASNs
  (`AS15169` and related), often from edge caches embedded inside ISP networks
  (Google Global Cache). IP/ASN-based classification is coarse (identifies "Google,"
  not specifically "YouTube video playback" vs. "Google Search") but cheap and
  doesn't require any packet inspection beyond the IP header.
- **DNS preceding the flow.** A `youtube.com`/`googlevideo.com` DNS query
  immediately before a QUIC flow to the resolved IP is strong corroborating
  evidence — but only if DNS itself is observable (plaintext UDP/53 or unencrypted
  enough to inspect; DoH/DoQ pushes this signal out of reach, see §7.4).
- **ALPN.** `h3` vs. `h3-29`/draft ALPNs can hint at client stack maturity, rarely
  service-identifying on its own.
- **JA3/JA4 of the ClientHello** (paccel: `fingerprint::ja3_hash`/`ja4_string` with
  `Ja4Transport::Quic`). Identifies the *client's* TLS/QUIC stack (Chrome's BoringSSL
  QUIC stack has a distinctive, version-stable fingerprint), which narrows "what kind
  of client is this" but does not by itself identify *which service* — useful as a
  supporting feature, not standalone.

### 7.2 What's visible without SNI/decryption at all — pure traffic-shape signals

This is the research area that matters most once SNI is unavailable (VPN, ECH, or
just choosing to work SNI-independent for robustness). It relies entirely on
metadata QUIC cannot hide by design: packet sizes, inter-arrival timing, and flow
volume/duration, observed per-connection (identifiable via the 4-tuple + CID even
across NAT rebinding, using the same CID-tracking logic paccel's
`QuicConnectionTracker` implements).

- **Adaptive bitrate (ABR) burst pattern.** YouTube (like most DASH/HLS-style
  players) downloads video in discrete chunks, not a continuous stream — buffer,
  fetch a segment as fast as the link allows, idle, repeat. This produces a
  characteristic **burst-idle-burst** envelope in the packet-size-over-time series
  that's quite distinct from bulk file transfer (continuous) or web browsing
  (many small short bursts) or a VoIP/gaming flow (small packets, tight periodic
  timing). This single feature is the backbone of most published QUIC/HTTP-3
  video-vs-other classifiers.
- **Segment size ≈ resolution/bitrate proxy.** The byte volume of each ABR chunk
  correlates with the video's current encoding bitrate, which correlates with
  resolution — several published attacks reconstruct *approximate resolution
  changes over time* (not exact video identity) purely from chunk-size sequences,
  even over a VPN tunnel that hides the inner IP/SNI entirely.
- **Downstream/upstream asymmetry.** Video playback is heavily downstream-dominated
  (small ACK/request traffic upstream, large segment traffic downstream) — trivial
  to compute, useful as an early coarse filter before more expensive sequence-based
  classification.
- **Flow duration + periodicity.** Long-lived (minutes), continues even through idle
  buffer periods (distinguishing it from a one-shot large download that finishes and
  closes).
- **Number of concurrent streams inside one QUIC connection.** HTTP/3 multiplexes
  video segment requests, manifest fetches, and thumbnail/analytics beacons over one
  connection's STREAM frames (§2.6, type `0x08`-`0x0f`) — the count/pattern of
  concurrently open stream IDs is a further discriminating feature once STREAM-frame
  parsing exists (paccel gap, §9 item 1).

### 7.3 Classifier design notes

- **Feature representation.** Two dominant families in the literature: (a) hand-
  engineered statistical features (burst count, mean/variance of chunk size, up/down
  byte ratio, flow duration) fed to classical ML (random forest, gradient boosting);
  (b) raw packet-size+direction+inter-arrival-time sequences (first N packets, or a
  fixed time window) fed to a sequence model (1D-CNN, LSTM/GRU, or Transformer).
  Sequence models generally outperform hand-engineered features for fine-grained
  "which service" classification but need more labeled data and are more sensitive
  to link conditions (packet loss/reordering change the observed sequence even
  though the underlying content didn't change).
- **QUIC vs. TCP+TLS changes the feature space, not the paradigm.** QUIC's own
  packetization (1 QUIC packet per UDP datagram typically, PMTU-sized, ~1200-1500
  bytes) removes some of the TCP-segmentation noise older classifiers relied on, but
  the ABR burst pattern itself is unchanged — most TCP-QUIC video-classification
  literature is a direct port of the same features, occasionally re-tuned.
  Coalesced packets (multiple QUIC packets per UDP datagram — paccel gap, §9 item 3)
  are the one QUIC-specific wrinkle: naive "1 packet = 1 datagram" assumptions in a
  classifier's feature extraction will under-count on coalesced datagrams. The
  Length field (§2.2) is the actual on-wire framing signal, so a proper feature
  extractor walks it explicitly rather than assuming datagram-length == packet-length.
- **Ground truth for training.** Requires either (a) a browser/headless client
  driven to a known set of URLs with `SSLKEYLOGFILE` capturing, so labels are exact
  and features can be validated against decrypted content; or (b) SNI-labeled real
  traffic (works only where ECH isn't in play). paccel's `quic-decrypt`+`fingerprint`
  features are directly useful for building (a): decrypt Initial for SNI-based
  auto-labeling, extract JA3/JA4 as an auxiliary feature, cross-check against
  `SSLKEYLOGFILE`-decrypted Handshake for full validation.
- **Evaluation pitfall: closed-world vs. open-world.** A classifier trained/tested
  only on "is this YouTube or not, among 5 known services" scores unrealistically
  well; real deployments see arbitrary unknown traffic. Open-world evaluation
  (include a large "unknown/other" class, measure false-positive rate against it)
  is the standard rigor bar in this literature and is frequently skipped in weaker
  papers — worth checking for explicitly when reading published results.

### 7.4 The blind spots this all runs into

- **Encrypted Client Hello (ECH)** — an active IETF-standardized TLS 1.3 extension
  (extension type `0xfe0d`) that encrypts the *entire* inner ClientHello (real SNI
  included) inside an outer, publicly-visible ClientHello carrying only a decoy/
  "public name" SNI. Where deployed (Cloudflare, and increasingly Chrome-with-QUIC
  against ECH-supporting origins), this removes SNI as a signal entirely — pure
  traffic-shape classification (§7.2) becomes the only remaining approach.
  Structurally detecting *that* ECH is in use (the presence of extension `0xfe0d`,
  even without decrypting it) is itself a useful, currently-unimplemented paccel
  feature — it flags "SNI-based classification will not work on this flow" so a
  pipeline can fall back to shape-only classification automatically.
- **Encrypted DNS (DoH/DoQ, RFC 9250).** Removes the plaintext-DNS corroborating
  signal from §7.1. DoQ specifically is QUIC-carried DNS on port 853 — structurally
  distinguishable from HTTP/3 QUIC by ALPN (`doq`) if ALPN is visible, otherwise
  needs its own shape-based classifier (DNS query/response is a very different
  traffic shape from HTTP/3: tiny, non-bursty, one round trip per resolution).
- **CDN co-location.** Once traffic is IP/ASN-classified only as far as "some CDN
  edge," multiple unrelated services fronted by the same CDN (Cloudflare, Fastly,
  Google's own edge) become indistinguishable by IP alone — motivates why
  traffic-shape and JA3/JA4 features matter even when IP-based classification is
  available, not just as an ECH fallback.

## 8. Applied: identifying malicious traffic (C2, malware) in encrypted channels

The threat model differs from §7 in an important way: an adversary *controls* the
client-side QUIC/TLS stack and has every incentive to blend in, whereas a video
player has no reason to disguise itself. That changes which signals are load-bearing.

### 8.1 Client-fingerprint anomaly detection (JA3/JA4/HASSH-class)

This is the single most productive technique against unsophisticated malware, and
directly what paccel's `fingerprint` feature targets.

- **Non-browser TLS/QUIC stacks stand out.** Legitimate browser traffic clusters
  tightly around a small number of JA3/JA4 values (Chrome's BoringSSL QUIC stack,
  Firefox's NSS stack, Safari's stack — each version-stable for months at a time).
  Malware frequently links a generic TLS library (OpenSSL default config, a raw
  `rustls`/Python `ssl` client, or a bespoke minimal QUIC implementation) with none
  of the browser-specific extension ordering, GREASE injection (RFC 8701 — its
  *absence* is itself a strong tell, see below), or cipher-suite breadth real
  browsers carry. A JA4 value that's rare/unseen across a large legitimate-traffic
  baseline, especially paired with a destination that has no other reason to be
  contacted, is a well-established weak-but-cheap detector.
- **GREASE absence as a signal.** RFC 8701 GREASE values are injected by every
  major browser specifically to prevent ossification; most non-browser TLS/QUIC
  stacks (including most malware C2 frameworks, since GREASE requires deliberate
  implementation effort with zero functional benefit to the attacker) omit it
  entirely. A `is_grease_u16`-style check (paccel already has one internally for
  fingerprint computation) applied *as a detection feature itself* — "does this
  ClientHello contain any GREASE values" — is a cheap binary signal worth surfacing
  directly, not just consuming internally to normalize JA3/JA4.
- **JA3S / server-side fingerprinting.** C2 infrastructure is often minimal/
  self-hosted rather than a real CDN-fronted service — the *server's* TLS stack
  (JA3S, paccel: `fingerprint::ja3s_hash`) frequently reveals a bare Python/Go/Rust
  TLS server rather than nginx/Cloudflare/a major CDN's stack. Combining client-side
  JA4 anomaly with server-side JA3S anomaly on the *same connection* is stronger
  than either alone — legitimate traffic to an anomalous server is much rarer than
  either signal individually.
- **JA4S/JA4X (not yet in paccel, see §9).** JA4S extends the same idea to the
  ServerHello with FoxIO's newer format; JA4X specifically fingerprints X.509
  certificate structure (issuer/subject RDN sequence shape, extension presence) —
  directly useful for catching self-signed or minimally-templated certs common in
  C2 infrastructure, but only reachable via Handshake decrypt (keylog-gated for
  QUIC, same as paccel's `quic-decrypt` Handshake path) since TLS 1.3 (and by
  extension QUIC) encrypts the Certificate message — unlike legacy TLS 1.2 over
  TCP, where a passive observer gets the cert for free. This is a genuine QUIC-
  specific *regression* in cert-based C2 detection capability versus older
  cleartext-cert TLS 1.2, worth calling out explicitly: **if your prior detection
  pipeline relied on passively-visible certificates, QUIC (and TLS 1.3 generally)
  removes that signal unless you have keylog access.**

### 8.2 Beaconing / C2-check-in pattern detection

Independent of any fingerprint — this works even against traffic that fingerprints
as a perfectly normal browser (increasingly common as attackers adopt legitimate
HTTP libraries or literally drive headless Chrome for C2 channels).

- **Interval regularity.** C2 beacons check in on a schedule (fixed interval,
  fixed interval + jitter, or exponential backoff after failure) — this produces
  low-variance inter-connection timing that's statistically distinguishable from
  human-driven browsing (bursty, irregular, correlated with active-hours/timezone)
  even when every individual connection looks benign. Classic detection: bucket
  connection-start timestamps per destination, compute coefficient of variation of
  the inter-arrival times, flag low-CV destinations for review. Works identically
  whether the transport is TCP+TLS or QUIC — it's a connection-level, not
  packet-level, signal, so it survives everything ECH/DoH hide.
- **Payload-size regularity.** Legitimate interactive traffic (browsing, video) has
  highly variable request/response sizes; a beacon polling "any tasking?" over and
  over produces near-identical request AND response sizes across check-ins — a
  second independent low-variance signal, ideally combined with timing regularity
  rather than used alone (some legitimate polling/heartbeat traffic, e.g. app
  telemetry, also has this shape).
- **Destination reputation / rarity.** Newly-registered domains, domains with no
  DNS history, IPs with no reverse DNS, ASNs with poor reputation (bulletproof
  hosting) — orthogonal to anything QUIC-specific, standard threat-intel enrichment
  applied to whatever destination identity *is* observable (SNI if present, else
  IP/ASN per §7.1/§7.4).
- **0-RTT / session-resumption abuse as a secondary signal.** QUIC's 0-RTT (RFC
  9001 §4.6-4.7) lets a returning client skip a round trip using a resumed PSK —
  legitimate for reducing latency on repeat visits to the same service, but replay-
  vulnerable by the spec's own admission (0-RTT data isn't protected against replay
  the way 1-RTT is) and disproportionately used by automated/scripted clients
  reconnecting on a fixed schedule versus human browsing's more varied connection
  pattern — another weak corroborating signal, not a standalone detector.

### 8.3 Protocol-conformance / implementation-anomaly detection

Distinct from fingerprint-*identity* anomaly (§8.1) — this looks for spec-violation
or unusual-but-technically-legal structural choices, which tends to catch more
sophisticated/custom C2 tooling that a naive JA3/JA4 blocklist misses because it
never bothered to mimic a browser fingerprint closely enough to blend into a
blocklist's known-bad set, or conversely mimics one *too* precisely (static/replayed
fingerprint, no natural version drift over time the way real browser rollouts show).

- **Structurally invalid or unusual field combinations paccel can flag today**
  (the crate's own permissive/strict parse-mode split, and its `ParseWarning`
  system, exist precisely to surface this class of thing without hard-failing a
  parse): version numbers outside the known v1/v2 family combined with real traffic
  volume (custom/private QUIC forks), DCID/SCID lengths at the extreme edges of
  what's legal (RFC 9000 §17.2 caps DCID at 20 bytes for known versions), Retry
  tokens with implausible structure or an integrity tag that fails verification
  against the public constants in §2.5, transport-parameter combinations RFC 9000
  disallows (e.g. `active_connection_id_limit` below the spec's mandated minimum
  of 2 — once transport-parameter parsing exists, per §9 item 2).
- **Cipher-suite/extension list entropy.** A real browser's cipher-suite and
  extension list, while individually recognizable, still spans a
  reasonably-sized space across major browsers/versions; a custom minimal C2 QUIC
  stack often hardcodes exactly one cipher suite (frequently just
  `TLS_AES_128_GCM_SHA256`, RFC 9001's own mandatory-to-implement minimum) and a
  handful of extensions — genuinely minimal, not merely different-looking. Low
  cardinality/low entropy in these lists, especially combined with GREASE absence
  (§8.1), is a stronger joint signal than either alone.
- **Timing/version drift as an anti-static-fingerprint check.** Because real
  browsers roll out TLS/QUIC stack changes on a predictable release cadence,
  a JA3/JA4 value that stays *exactly* byte-identical for a suspiciously long
  window (many months, spanning multiple real browser releases) while claiming to
  be that browser is itself suspicious — this needs a historical fingerprint
  database (e.g. tracking JA4 values over time per claimed User-Agent/ALPN) rather
  than anything derivable from a single capture.

### 8.4 What decrypt access changes

Everything in §8.1-8.3 is passive/metadata-only. If `SSLKEYLOGFILE` access exists
(a controlled endpoint, a sandboxed malware-analysis VM, or lawful-intercept-style
managed infrastructure with the necessary authorization) — the same
`decrypt_packet_with_secret`/`QuicKeyLog` path from paccel's own QUIC work opens up:

- Full Certificate inspection (self-signed, mismatched CN/SAN, implausibly-short
  validity window, known-malicious cert reuse across otherwise-unrelated
  infrastructure — classic indicators, just gated behind decrypt access for QUIC/
  TLS 1.3 in a way they weren't for TLS 1.2).
- HTTP/3 request/response content once STREAM-frame parsing + QPACK decode exist
  (both currently paccel gaps, §9) — full payload-based signature/YARA-style
  matching becomes possible, same as it already is for decrypted HTTP/2 or
  plaintext HTTP/1.x.
- Ground truth for *training* the passive/metadata detectors in §8.1-8.3: decrypt
  a labeled malware-traffic corpus once, extract the metadata-only features from
  the same flows, and you have a supervised training set without needing the
  malware sample to keep beaconing indefinitely.

## 9. Open gaps (from this project, as a research-priority list)

Ordered roughly by "most useful next thing to build for encrypted-traffic-analysis
work specifically," not by general protocol-completeness:

1. **QUIC STREAM-frame parsing** (§2.6) — blocks HTTP/3, blocks connection-ID
   issuance/rotation tracking beyond the Initial exchange, blocks transport-parameter
   extraction. The single highest-leverage gap for this research area.
2. **Transport parameters extension (`0x39`) parsing inside the decrypted Initial
   CRYPTO stream** (§2.4) — cheap once STREAM parsing exists, high fingerprinting
   value (implementation-identifying defaults independent of the TLS layer).
3. **Coalesced-packet splitting** — a single UDP datagram legitimately carries
   multiple QUIC packets (e.g. Initial + Handshake back-to-back); not splitting them
   means paccel currently only sees the first.
4. **Version Negotiation packet parsing** — the list of alternate versions a server
   offers is itself a fingerprintable/classifiable signal, currently unparsed.
5. **Spin-bit statefulness** — once `QuicConnectionTracker` has authoritative
   short-header DCID-length knowledge (§2.3), extracting the spin bit sequence per
   connection becomes possible; currently short-header classification is too weak
   (~25% false-positive) to build on.
6. **ECH detection (`0xfe0d` extension presence)** — a cheap structural check
   (does not require decrypting the ECH payload) that flags when SNI-based
   classification (§7.1, §8) will silently fail, so a pipeline can fall back to
   shape-only analysis automatically instead of misclassifying on a decoy SNI.
7. **Retry integrity tag verification** (§2.5) — the key/nonce are public
   constants; verifying rather than merely extracting the tag lets a defensive
   pipeline distinguish genuine server Retries from spoofed/injected ones.
8. **JA4S/JA4X** — server-side and certificate fingerprinting, the natural next
   step after JA3S for the C2-detection use case in §8.1, gated behind Handshake
   decrypt the same way full Certificate access already is.
