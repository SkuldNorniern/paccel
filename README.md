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
paccel = "0.2"
# optional features:
paccel = { version = "0.2", features = ["fingerprint"] }
paccel = { version = "0.2", features = ["quic-decrypt"] }
```

`0.x` can break the public API between minor versions before `1.0`. Check [Status](#status) before depending on any one piece.

## Current status

The engine (`engine/*`) does built-in parsing, capture iteration, opt-in reassembly, and stream tracking. The packet model (`packet/*`) splits into owned types and borrowed views for manual parsing:

`packet::EthernetPacket`, `packet::SllPacket`, `packet::Sll2Packet`, `packet::Ipv4Packet`, `packet::Ipv6Packet`, `packet::TcpPacket`, `packet::UdpPacket`, `packet::ArpPacket`, `packet::DnsPacket`, `packet::IcmpPacket`, `packet::Icmpv6Packet`, `packet::DhcpPacket`, `packet::GrePacket`, `packet::VxlanPacket`, `packet::VlanTagView`.

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

Still `0.x`, API can move before `1.0`.

**Solid:** link/network/transport/tunnel parsing, pcap/pcapng capture iteration, IPv4/IPv6 fragment reassembly.

**Heuristic only:** WireGuard, OpenVPN, L2TP, QUIC short header, LLMNR, NBNS, NAT-PMP — port number and a loose byte pattern, no structural check. QUIC short-header guessing has roughly a 1-in-4 false-positive rate on random UDP without connection state; feed it a `QuicConnectionTracker` and it becomes authoritative, though wiring that up is on you.

**QUIC:** long header, short header, Version Negotiation, coalesced-packet splitting, a generic frame parser (`iter_quic_frames`), and STREAM reassembly (`QuicStreamReassembler`) all exist. None of it is wired into `ParsedPacket` yet, so you call it directly. HTTP/3 isn't built — it needs QPACK on top of this. Handshake/1-RTT decrypt needs an `SSLKEYLOGFILE` secret; TLS 1.3 gives no other way to get those keys from a passive capture.

**TCP reassembly / `SessionTracker`:** opt-in, bounded FIFO eviction, real overlap handling (`TcpOverlapPolicy::Reject`/`FirstWins`/`LastWins`, default `Reject`). `RST` tears the flow down; a `SYN` on an already-open direction restarts it instead of getting silently appended to the old stream. `TcpStreamReassembler`/`QuicStreamReassembler`/`SessionTracker`/`IpFragmentReassembler` also cap total buffered bytes across every flow/stream/probe/datagram combined (`with_max_total_buffered_bytes`/`with_max_total_probe_bytes`/`with_max_total_bytes`, 64 MiB default), not just per-entry.

**New, not fully wired in yet:** `ParseError`/`ParseErrorKind`/`Layer` add offset/protocol context that `LayerError` doesn't carry, but most parsers still return plain `LayerError`. `ProbeResult<T>` separates "not this protocol" from "truncated" from "malformed" (DNP3's probe uses it; the rest still return `Option<T>`). `ParsedPacket::application()` is one accessor over the ~40 `Option<T>` application fields — the fields themselves aren't going anywhere.

`ParseWarning` dropped its redundant `subcode` field — `code`/`subcode` were exact duplicates (`ParseWarningCode::VxlanInner` / `ParseWarningSubcode::VxlanInner`, one per variant). `code.as_str()` now gives the stable string name directly.

**Not there yet:** HTTP/2 has no HPACK. No HTTP/3, GTP, or Diameter. Fingerprinting stops at JA3/JA4/JA3S/HASSH — no JA4S/JA4X/JA4H/JA4SSH. tshark differential and pcap-vs-scapy coverage is still growing. The hot path still allocates more than it needs to.

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
                    warning.code.as_str(),
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

Zero-dependency by default. Two optional features pull in [RustCrypto](https://github.com/RustCrypto) crates (Apache-2.0/MIT):

- **`quic-decrypt`** (`aes-gcm`, `aes`, `hkdf`, `sha2`) — `decrypt_initial_client_hello`/`decrypt_initial_packet` in `paccel::layer::application::quic` recover a QUIC Initial packet's plaintext (including the ClientHello) from keys derived off the packet's own Destination Connection ID, per RFC 9001 sec 5.2. Any on-path observer can do this; it's not a break of QUIC. Handshake/1-RTT is different — `decrypt_packet_with_secret` needs a secret from `QuicKeyLog`, which reads the standard `SSLKEYLOGFILE` format (the same file curl/browsers/Wireshark already write via that env var). No way around that: those keys come from a live ECDHE exchange, not from the capture itself.
- **`fingerprint`** (`md-5`, `sha2`) — `paccel::fingerprint` gives you `ja3_string`/`ja3_hash`/`ja4_string` off a `TlsClientHello`, `ja3s_string`/`ja3s_hash` off a `TlsServerHello`, and `hassh`/`hassh_server` off an `SshKexInit`. Checked against official reference vectors and tshark's own field output.

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

## Core non-goals (current scope)

- No built-in flow table in the stateless core parser; reassembly and stream tracking are opt-in components.
- No raw datalink/transport send/receive runtime in core parser.
- No macro-heavy mutable packet construction API in core crate.

## Test fixture provenance

None of this ships in the crate — `tests/pcaps/` and `fuzz/` are excluded (`exclude` in `Cargo.toml`; `cargo package --list` confirms it). `src/` itself is original, written from RFCs and checked against `tshark`'s output, not derived from Wireshark's GPLv2 source.

`tests/pcaps/happy-path/*` are small hand-built captures, tens to hundreds of bytes, no external source. Most protocol test data lives inline in `tests/pcap_integration.rs` as synthetic frames built directly against each protocol's spec — tshark is only used to cross-check output, never as a source of committed bytes.

`tests/pcaps/protocol-gaps/*` holds one self-generated capture:

| Fixture | Source |
|---|---|
| `http2_get_hello.pcap` | Self-generated on loopback: `curl --http2-prior-knowledge` against a local Python [`h2`](https://github.com/python-hyper/h2) library server, captured with `tcpdump`; not third-party data |

SSDP/NAT-PMP/PCP classification is tested against in-code synthetic frames (`tests/pcap_integration.rs`) rather than a captured pcap — an earlier fixture built from a local home-network capture was removed and purged from git history since it embedded real device MAC/IP addresses.

## License

Apache-2.0 (see `LICENSE`).
