# Paccel

Rust packet parser. Reads a frame and gives you the layers, without a capture runtime or a flow table under it.

Built for Fluere workloads. Not a Wireshark clone.

Requires Rust 1.88+ (edition 2024, let chains).

## Install

```bash
cargo add paccel
```

Or in `Cargo.toml`:

```toml
paccel = "0.3"
# optional features:
paccel = { version = "0.3", features = ["fingerprint"] }
paccel = { version = "0.3", features = ["quic-decrypt"] }
```

`0.x` can break the public API between minor versions before `1.0`.

## Layout

`engine/*` does built-in parsing, capture iteration, opt-in reassembly and stream tracking. `packet/*` splits into owned types and borrowed views for manual parsing:

`packet::EthernetPacket`, `packet::SllPacket`, `packet::Sll2Packet`, `packet::Ipv4Packet`, `packet::Ipv6Packet`, `packet::TcpPacket`, `packet::UdpPacket`, `packet::ArpPacket`, `packet::DnsPacket`, `packet::IcmpPacket`, `packet::Icmpv6Packet`, `packet::DhcpPacket`, `packet::GrePacket`, `packet::VxlanPacket`, `packet::VlanTagView`.

## Supported protocols

| Layer / capability | Support |
|---|---|
| Link | Ethernet II; VLAN 802.1Q; QinQ 802.1ad; Linux SLL/SLL2; 802.11 with radiotap; ARP; PPPoE with PPP-in-PPPoE; MPLS; LLDP; STP; CDP; LACP |
| Network | IPv4 with options; IPv6 with extension headers; ICMP with echo; ICMPv6 with NDP; IGMP; OSPF; PIM; EIGRP; VRRP. An ICMP error decodes the datagram it quotes into `icmp_quoted`, which names the flow the error is about |
| Transport | TCP with options; UDP; SCTP; GRE; AH; ESP; L2TP |
| Tunnel (recursive inner decode) | GRE; VXLAN; GENEVE; MPLS; IP-in-IP |
| Application (full parse) | DNS (records + EDNS), mDNS, DHCP, DHCPv6, NTP, TLS ClientHello (SNI/ALPN/raw extension order) and ServerHello, HTTP/1.x, HTTP/2 (typed frame iterator: bodies decoded per frame type, no HPACK), QUIC (version-aware long-header packet types v1/v2, Token/Length/PN-offset, Retry token + integrity tag, Version Negotiation lists, opt-in coalesced-packet splitting), SSH banner and `SSH_MSG_KEXINIT` algorithm lists, BGP, CoAP, DNP3, FTP, HSRP, IKE/ISAKMP (v1/v2), IMAP, Kerberos (UDP/TCP), LDAP, Modbus/TCP, MQTT, NNTP, ONC-RPC (NFS classification), PCP, RADIUS, RIP, RTCP, RTP, SIP, SMB1/CIFS, SMB2, SMTP, SNMP, SSDP, STUN, Syslog, TFTP, Telnet (IAC negotiation). Also OSPF, PIM, EIGRP, VRRP, CDP, LACP (see Link/Network rows) |
| Application (port/heuristic classification only) | WireGuard, OpenVPN, L2TP, QUIC short header (1-RTT), LLMNR, NBNS, NAT-PMP. Port and a loose byte pattern, no structural check. `QuicConnectionTracker::classify_short_header` gives `Confidence::Structural` or `::Stateful` instead once it knows the connection |
| Fingerprinting (`fingerprint` feature) | JA3 / JA4 (TLS ClientHello), JA3S (TLS ServerHello), HASSH / HASSHServer (SSH KEXINIT) |
| QUIC decrypt (`quic-decrypt` feature) | Initial packets: full decrypt from publicly-derivable keys (recovers the ClientHello - SNI/ALPN). Handshake/1-RTT: decrypt via an externally-supplied `SSLKEYLOGFILE`-format secret (`QuicKeyLog`), same model Wireshark/curl/browsers use - these levels need a live TLS 1.3 ECDHE exchange, not derivable from a passive capture alone. Opt-in `QuicConnectionTracker` keys that state on the connection rather than the address pair, so packet numbers and connection IDs survive a client migration. Tracks the NEW_CONNECTION_ID/RETIRE_CONNECTION_ID lifecycle with a separate sequence space per endpoint, and packet numbers per RFC 9000 sec 12.3 space (Initial/Handshake/Application). `QuicStreamReassembler::offer_for_connection` keys stream bytes on the connection too, so a stream carries across a move. |
| Capture formats | pcap and pcapng (linktype-aware: Ethernet, SLL, SLL2, NULL, RAW/IPv4/IPv6, FDDI/SNAP, and 802.11) |
| Reassembly | IPv4/IPv6 fragments; TCP and QUIC streams (opt-in). Overlap policy is `Reject`, `FirstWins` or `LastWins`, default `Reject`. `RST` tears a flow down, and a `SYN` on an open direction restarts it rather than appending to the old stream. A direction closes at its FIN and refuses the bytes after it. Every reassembler caps total buffered bytes across all flows, not just per flow (64 MiB default) |
| Streaming | Multi-segment HTTP, TLS, BGP, SMB1/2, LDAP, DNS-over-TCP and MQTT through `SessionTracker`. Probes are tried strongest signature first, and one that has only read a length field cannot claim a stream from one that matched a signature. A direction that runs out of budget while undecided is retired rather than left buffering |

Malformed input does not panic. Fuzzed, property-tested, and diffed against tshark and scapy.

State is bounded and ages out. Every index has a cap, per connection as well as in total, and `expire_before` on a caller-supplied clock drops what has gone quiet. Nothing reads a clock internally, so a pcap replay ages state the same way a live capture does.

## Quick usage

```rust
use paccel::engine::BuiltinPacketParser;

fn parse_frame(frame: &[u8]) {
    match BuiltinPacketParser::parse(frame) {
        Ok(parsed) => {
            if let Some(ipv4) = parsed.ipv4.as_ref() {
                println!("ipv4 {} -> {}", ipv4.source, ipv4.destination);
            }
            if let Some(dns) = parsed.dns() {
                println!("dns txid={}", dns.header.transaction_id);
            }
            if !parsed.udp_hints.is_empty() {
                let hint_names: Vec<_> = parsed.udp_hints.iter().map(|h| h.as_str()).collect();
                println!("udp app hints: {:?}", hint_names);
            }
            for warning in &parsed.warnings {
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

The error says which layer stopped the parse and why. See `ParseError`, `ParseErrorKind` and `Layer`.

Call `BuiltinPacketParser::parse_with_config(...)` to tune parse limits, for example IPv6 extension depth. `ParseMode::Permissive` is the default and keeps what survived a short capture, with a `ParseWarning` saying what went missing. `ParseMode::Strict` refuses the frame instead.

For pcap/pcapng workflows, use `paccel::engine::parse_capture_frames(...)` and feed each frame into `BuiltinPacketParser`.
For allocation-sensitive iteration, use `paccel::engine::iter_capture_frames(...)` to stream frames without collecting first.

`BuiltinPacketParser` is stateless. Flow and state tracking compose on top, for example inside Fluere.

## Stateful usage

The stateful pieces take the capture's own clock, so a replay ages state the same way a live capture does.

```rust
use paccel::engine::{CaptureTimestamp, SessionTracker, iter_capture_frames};

fn classify(capture: &[u8]) {
    let mut tracker = SessionTracker::new();
    let mut last = 0u64;

    for frame in iter_capture_frames(capture).expect("a capture header") {
        let Ok(frame) = frame else { continue };
        // A Simple Packet Block has no timestamp; keep the last one we saw.
        let now = frame
            .timestamp
            .and_then(CaptureTimestamp::to_timestamp_ns)
            .unwrap_or(last);
        last = now;

        if let Some(event) = tracker.offer_frame_at(frame.data, now) {
            println!("{}:{} -> {:?}", event.src, event.src_port, event.l7);
        }

        // Drop anything quiet for five minutes.
        tracker.expire_before(now.saturating_sub(300_000_000_000));
    }

    let stats = tracker.stats();
    println!("{} probes holding {} bytes", stats.active_probes, stats.probe_bytes);
}
```

`QuicConnectionTracker` works the same way, and hands `QuicStreamReassembler::offer_for_connection` a connection and direction that stay put when a client changes address.

## Cargo features

Zero-dependency by default. Two optional features pull in [RustCrypto](https://github.com/RustCrypto) crates (Apache-2.0/MIT):

- **`quic-decrypt`** (`aes-gcm`, `aes`, `hkdf`, `sha2`). `decrypt_initial_client_hello`/`decrypt_initial_packet` in `paccel::layer::application::quic` recover a QUIC Initial packet's plaintext (including the ClientHello) from keys derived off the packet's own Destination Connection ID, per RFC 9001 sec 5.2. Any on-path observer can do this; it's not a break of QUIC. Handshake/1-RTT is different. `decrypt_packet_with_secret` needs a secret from `QuicKeyLog`, which reads the standard `SSLKEYLOGFILE` format (the same file curl/browsers/Wireshark already write via that env var). No way around that: those keys come from a live ECDHE exchange, not from the capture itself.
- **`fingerprint`** (`md-5`, `sha2`). `paccel::fingerprint` gives you `ja3_string`/`ja3_hash`/`ja4_string` off a `TlsClientHello`, `ja3s_string`/`ja3s_hash` off a `TlsServerHello`, and `hassh`/`hassh_server` off an `SshKexInit`. Checked against official reference vectors and tshark's own field output.

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

## Core non-goals

- No built-in flow table in the stateless core parser; reassembly and stream tracking are opt-in components.
- No raw datalink/transport send/receive runtime in core parser.
- No macro-heavy mutable packet construction API in core crate.

## Test fixture provenance

None of this ships in the crate. `tests/pcaps/` and `fuzz/` are excluded (`exclude` in `Cargo.toml`; `cargo package --list` confirms it). `src/` itself is original, written from RFCs and checked against `tshark`'s output, not derived from Wireshark's GPLv2 source.

`tests/pcaps/happy-path/*` are small hand-built captures, tens to hundreds of bytes, no external source. Most protocol test data lives inline in `tests/pcap_integration.rs` as synthetic frames built directly against each protocol's spec. tshark is only used to cross-check output, never as a source of committed bytes.

`tests/pcaps/protocol-gaps/*` holds one self-generated capture:

| Fixture | Source |
|---|---|
| `http2_get_hello.pcap` | Self-generated on loopback: `curl --http2-prior-knowledge` against a local Python [`h2`](https://github.com/python-hyper/h2) library server, captured with `tcpdump`; not third-party data |

SSDP/NAT-PMP/PCP classification is tested against in-code synthetic frames (`tests/pcap_integration.rs`) rather than a captured pcap. An earlier fixture built from a local home-network capture was removed and purged from git history since it embedded real device MAC/IP addresses.

## License

Apache-2.0 (see `LICENSE`).
