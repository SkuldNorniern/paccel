# Paccel

Paccel is an in-progress Rust packet parsing engine focused on practical protocol visibility, correctness, and performance.

The goal is to become a strong parsing alternative for Fluere workloads (not a full Wireshark clone).

Requires Rust 1.88+ (edition 2024, let chains).

## Install

```bash
cargo add paccel
```

Or in `Cargo.toml`:

```toml
paccel = "0.1"
# optional features:
paccel = { version = "0.1", features = ["fingerprint"] }
paccel = { version = "0.1", features = ["quic-decrypt"] }
```

`0.x` releases are explicitly unstable — the public API can change between minor versions before `1.0`. See [Status](#status) below before depending on any specific piece.

## Current status

- parser engine scaffolding is in place (`engine/*`)
- packet model is split into owned + view modules (`packet/*`)
- built-in parsing, capture iteration, opt-in reassembly, and stream tracking are available
- low-level borrowed packet wrappers exist for manual parsing flows:
  - `packet::EthernetPacket`, `packet::SllPacket`, `packet::Sll2Packet`, `packet::Ipv4Packet`, `packet::Ipv6Packet`, `packet::TcpPacket`, `packet::UdpPacket`, `packet::ArpPacket`, `packet::DnsPacket`, `packet::IcmpPacket`, `packet::Icmpv6Packet`, `packet::DhcpPacket`, `packet::GrePacket`, `packet::VxlanPacket`, `packet::VlanTagView`

## Supported protocols

| Layer / capability | Support |
|---|---|
| Link | Ethernet II; VLAN 802.1Q; QinQ 802.1ad; Linux SLL/SLL2; 802.11 with radiotap; ARP; PPPoE with PPP-in-PPPoE; MPLS; LLDP; STP; CDP; LACP |
| Network | IPv4 with options; IPv6 with extension headers; ICMP with echo; ICMPv6 with NDP; IGMP; OSPF; PIM; EIGRP; VRRP |
| Transport | TCP with options; UDP; SCTP; GRE; AH; ESP; L2TP |
| Tunnel (recursive inner decode) | GRE; VXLAN; GENEVE; MPLS; IP-in-IP |
| Application (full parse) | DNS (records + EDNS), mDNS, DHCP, DHCPv6, NTP, TLS ClientHello (SNI/ALPN/raw extension order) and ServerHello, HTTP/1.x, HTTP/2 (frame header: type/length/flags/stream ID, no HPACK), QUIC (version-aware long-header packet types v1/v2, Token/Length/PN-offset, Retry token + integrity tag, Version Negotiation lists, opt-in coalesced-packet splitting), SSH banner and `SSH_MSG_KEXINIT` algorithm lists, BGP, CoAP, DNP3, FTP, HSRP, IKE/ISAKMP (v1/v2), IMAP, Kerberos (UDP/TCP), LDAP, Modbus/TCP, MQTT, NNTP, ONC-RPC (NFS classification), PCP, RADIUS, RIP, RTCP, RTP, SIP, SMB1/CIFS, SMB2, SMTP, SNMP, SSDP, STUN, Syslog, TFTP, Telnet (IAC negotiation) — plus OSPF, PIM, EIGRP, VRRP, CDP, LACP (see Link/Network rows) |
| Application (port/heuristic classification only) | WireGuard, OpenVPN, L2TP, QUIC short header (1-RTT), LLMNR, NBNS, NAT-PMP |
| Fingerprinting (`fingerprint` feature) | JA3 / JA4 (TLS ClientHello), JA3S (TLS ServerHello), HASSH / HASSHServer (SSH KEXINIT) |
| QUIC decrypt (`quic-decrypt` feature) | Initial packets: full decrypt from publicly-derivable keys (recovers the ClientHello - SNI/ALPN). Handshake/1-RTT: decrypt via an externally-supplied `SSLKEYLOGFILE`-format secret (`QuicKeyLog`), same model Wireshark/curl/browsers use - these levels need a live TLS 1.3 ECDHE exchange, not derivable from a passive capture alone. Opt-in `QuicConnectionTracker` for connection-ID/packet-number state across a flow, including CID-indexed lookup across tuple changes. |
| Capture formats | pcap and pcapng (linktype-aware: Ethernet, SLL, SLL2, NULL, RAW/IPv4/IPv6, FDDI/SNAP, and 802.11) |
| Reassembly | IPv4/IPv6 fragments; TCP streams (opt-in) |
| Streaming | Multi-segment HTTP/TLS through `SessionTracker` |

The parser is designed to handle malformed input without panicking; it is fuzz-, property-, and differential-tested.

## Status

`0.x` — API can still change before `1.0`.

- Link/network/transport/tunnel parsing, pcap/pcapng capture iteration, IPv4/IPv6 fragment reassembly: stable.
- Port/heuristic-only protocols (WireGuard, OpenVPN, L2TP, QUIC short header, LLMNR, NBNS, NAT-PMP): no structural confirmation, port number and/or a suggestive byte pattern only. QUIC short-header classification has a roughly 1-in-4 false-positive rate on arbitrary UDP payloads without connection state; `QuicConnectionTracker` state makes it authoritative, plumbing is on the caller.
- `quic-decrypt` and `fingerprint` features: off by default, RFC/reference-vector verified, not yet seen real-world traffic diversity.
- HTTP/2: frame-header only (type/length/flags/stream ID), no HPACK, no `ParsedPacket` wiring.
- QUIC: STREAM frames parseable (`iter_quic_frames`) and reassemblable (`QuicStreamReassembler`), standalone, not wired into `ParsedPacket`. HTTP/3 not built (needs QPACK on top of this). Handshake/1-RTT decrypt needs an externally-supplied `SSLKEYLOGFILE` secret — not derivable from a passive capture, by design of TLS 1.3.
- TCP stream reassembly / `SessionTracker`: opt-in, bounded FIFO eviction, explicit overlap policy (`TcpOverlapPolicy::Reject`/`FirstWins`/`LastWins`, default `Reject`), `RST` tears down the flow, a `SYN` on an already-established direction resets it (tuple-reuse safe).
- `ParseError`/`ParseErrorKind`/`Layer`: the emerging richer error model (layer/protocol/offset/kind), additive alongside `LayerError` - most parsers still return `LayerError`, convertible via `ParseError::from_layer_error`.
- `ProbeResult<T>`: distinguishes not-this-protocol/incomplete/malformed, which `Option<T>`/`.ok()` collapse into the same `None`. One real caller so far (`dnp3::probe_dnp3`, wired into `BuiltinPacketParser`'s DNP3 classification) - most protocol probes still return `Option<T>` directly.
- Not supported: HTTP/3, GTP, Diameter, JA4S/JA4X/JA4H/JA4SSH.
- tshark differential and pcap-vs-scapy parity coverage still small/expanding.
- Hot path still uses some intermediate allocations.

## Quick usage

```rust
use paccel::engine::BuiltinPacketParser;

fn parse_frame(frame: &[u8]) {
    match BuiltinPacketParser::parse(frame) {
        Ok(parsed) => {
            if let Some(ipv4) = parsed.ipv4 {
                println!("ipv4 {} -> {}", ipv4.source, ipv4.destination);
            }
            if let Some(dns) = parsed.dns {
                println!("dns txid={}", dns.header.transaction_id);
            }
            if !parsed.udp_hints.is_empty() {
                let hint_names: Vec<_> = parsed.udp_hints.iter().map(|h| h.as_str()).collect();
                println!("udp app hints: {:?}", hint_names);
            }
            for warning in parsed.warnings {
                println!(
                    "warning [{}:{}@{}]: {}",
                    warning.protocol.as_str(),
                    warning.subcode.as_str(),
                    warning.offset,
                    warning.message
                );
            }
        }
        Err(err) => {
            println!("parse error: {}", err);
        }
    }
}
```

You can also call `BuiltinPacketParser::parse_with_config(...)` to tune parse limits (for example IPv6 extension depth).

For pcap/pcapng workflows, use `paccel::engine::parse_capture_frames(...)` and feed each frame into `BuiltinPacketParser`.
For allocation-sensitive iteration, use `paccel::engine::iter_capture_frames(...)` to stream frames without collecting first.

The core `BuiltinPacketParser` is intentionally stateless by design (similar to libpnet/scapy usage patterns).
Flow/state tracking should be composed on the integration side (for example inside Fluere).

## Cargo features

The crate is zero-dependency by default. Two optional features pull in [RustCrypto](https://github.com/RustCrypto) crates (all Apache-2.0/MIT):

- **`quic-decrypt`** (`aes-gcm`, `aes`, `hkdf`, `sha2`): `paccel::layer::application::quic::decrypt_initial_client_hello`/`decrypt_initial_packet` recover a QUIC Initial packet's plaintext, including the ClientHello, using only keys derivable from the packet's own Destination Connection ID (RFC 9001 sec 5.2 - this is the same on-path visibility any DPI tool or Wireshark itself has, not a break of QUIC's security model). For Handshake/1-RTT, `decrypt_packet_with_secret` takes a secret from `paccel::layer::application::quic::QuicKeyLog`, which parses the standard `SSLKEYLOGFILE` text format (`<Label> <ClientHelloRandomHex> <SecretHex>` per line, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`/`SERVER_HANDSHAKE_TRAFFIC_SECRET`/`CLIENT_TRAFFIC_SECRET_0`/`SERVER_TRAFFIC_SECRET_0`) - the same file curl, browsers, and Wireshark itself already know how to produce via the `SSLKEYLOGFILE` environment variable. There is no way around needing this file for Handshake/1-RTT: those levels are protected by a live ECDHE exchange, not something derivable from a capture alone.
- **`fingerprint`** (`md-5`, `sha2`): `paccel::fingerprint` provides `ja3_string`/`ja3_hash`/`ja4_string` (from a `TlsClientHello`), `ja3s_string`/`ja3s_hash` (from a `TlsServerHello`), and `hassh`/`hassh_server` (from an `SshKexInit`). All verified against official reference vectors or tshark's own native field computation, not hand-derived.

## libpnet compatibility snapshot

| Capability | libpnet | paccel |
|---|---|---|
| Low-level packet views (Ethernet/IP/TCP/UDP/ARP/DNS/ICMP) | yes | yes |
| Linux cooked capture (SLL/SLL2) | yes | yes |
| Typed protocol/ethertype name helpers | yes | yes |
| One-shot structured parse output with warnings | limited | yes |
| Application-layer protocol parsing (40+ protocols, see table above) | no (link/network/transport only) | yes |
| Tunnel metadata in one parse pass (MPLS/VXLAN/GENEVE/AH/ESP/WireGuard) | partial | yes |
| Strict/permissive parser mode | no | yes |
| Built-in raw send/receive transport stack | yes | no (out of scope) |
| Core mutable packet-builder API | yes | no (deferred/non-goal in core) |

## Explicit core non-goals (current scope)

- No built-in flow table in the stateless core parser; reassembly and stream tracking are opt-in components.
- No raw datalink/transport send/receive runtime in core parser.
- No macro-heavy mutable packet construction API in core crate.

## Test fixture provenance

**None of this affects the published crate.** `tests/pcaps/` and `fuzz/` are excluded from the packaged crate (see `exclude` in `Cargo.toml`) — `cargo package --list` confirms zero binary fixtures ship. Everything under `src/` is original, written from RFCs/specs and verified against `tshark`'s output, not derived from Wireshark's own (GPLv2) source code.

`tests/pcaps/happy-path/*` are small hand-built captures (tens to hundreds of bytes each); no external source. Most protocol test data lives inline in `tests/pcap_integration.rs` as paccel-authored synthetic frames, each built and verified directly against that protocol's own parser source (`tshark` is used only as an independent oracle to cross-check output, never as a source of committed binary data).

`tests/pcaps/protocol-gaps/*` holds one self-generated capture:

| Fixture | Source |
|---|---|
| `http2_get_hello.pcap` | Self-generated on loopback: `curl --http2-prior-knowledge` against a local Python [`h2`](https://github.com/python-hyper/h2) library server, captured with `tcpdump`; not third-party data |

SSDP/NAT-PMP/PCP classification is tested against in-code synthetic frames (`tests/pcap_integration.rs`) rather than a captured pcap — an earlier fixture built from a local home-network capture was removed and purged from git history since it embedded real device MAC/IP addresses.

## License

Apache-2.0 (see `LICENSE`).
