# Paccel

Paccel is an in-progress Rust packet parsing engine focused on practical protocol visibility, correctness, and performance.

The goal is to become a strong parsing alternative for Fluere workloads (not a full Wireshark clone).

Requires Rust 1.88+ (edition 2024, let chains).

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
| Application (full parse) | DNS (records + EDNS), mDNS, DHCP, DHCPv6, NTP, TLS ClientHello (SNI/ALPN/raw extension order) and ServerHello, HTTP/1.x, HTTP/2 (frame header: type/length/flags/stream ID, no HPACK), QUIC (version-aware long-header packet types v1/v2, Token/Length/PN-offset, Retry token + integrity tag), SSH banner and `SSH_MSG_KEXINIT` algorithm lists, BGP, CoAP, DNP3, FTP, HSRP, IKE/ISAKMP (v1/v2), IMAP, Kerberos (UDP/TCP), LDAP, Modbus/TCP, MQTT, NNTP, ONC-RPC (NFS classification), PCP, RADIUS, RIP, RTCP, RTP, SIP, SMB1/CIFS, SMB2, SMTP, SNMP, SSDP, STUN, Syslog, TFTP, Telnet (IAC negotiation) — plus OSPF, PIM, EIGRP, VRRP, CDP, LACP (see Link/Network rows) |
| Application (port/heuristic classification only) | WireGuard, OpenVPN, L2TP, QUIC short header (1-RTT), LLMNR, NBNS, NAT-PMP |
| Fingerprinting (`fingerprint` feature) | JA3 / JA4 (TLS ClientHello), JA3S (TLS ServerHello), HASSH / HASSHServer (SSH KEXINIT) |
| QUIC decrypt (`quic-decrypt` feature) | Initial packets: full decrypt from publicly-derivable keys (recovers the ClientHello - SNI/ALPN). Handshake/1-RTT: decrypt via an externally-supplied `SSLKEYLOGFILE`-format secret (`QuicKeyLog`), same model Wireshark/curl/browsers use - these levels need a live TLS 1.3 ECDHE exchange, not derivable from a passive capture alone. Opt-in `QuicConnectionTracker` for connection-ID/packet-number state across a flow. |
| Capture formats | pcap and pcapng (linktype-aware: Ethernet, SLL, SLL2, NULL, RAW/IPv4/IPv6, FDDI/SNAP, and 802.11) |
| Reassembly | IPv4/IPv6 fragments; TCP streams (opt-in) |
| Streaming | Multi-segment HTTP/TLS through `SessionTracker` |

The parser never panics on malformed input; it is fuzz-, property-, and differential-tested.

## What it is not yet

- tshark corpus scaffolding exists; parity automation is in place, but tshark-based differential coverage is still being expanded
- baseline pcap-vs-scapy parity test exists, but coverage is still small
- still uses intermediate allocations in parts of hot path
- QUIC: no Version Negotiation list parsing, no coalesced-packet splitting, no STREAM frame parsing (so HTTP/3 is not reachable yet). Handshake/1-RTT decrypt needs an externally-supplied keylog secret (see the `quic-decrypt` feature above) - there is no way to derive those keys from a passive capture alone, by design of TLS 1.3. Short-header/1-RTT classification without `QuicConnectionTracker` state remains a low-confidence heuristic (any UDP payload's top two bits have a 1-in-4 chance of matching).
- HTTP/2 is frame-header classification only (type/length/flags/stream ID) - no HPACK header decompression, so individual header fields inside HEADERS/CONTINUATION frames are not decoded
- no GTP or Diameter support yet (no ground-truth test data available)
- fingerprinting only covers ClientHello/ServerHello/KEXINIT-based JA3/JA4/JA3S/HASSH; no JA4S/JA4X/JA4H/JA4SSH variants yet

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

- **`quic-decrypt`** (`aes-gcm`, `aes`, `hkdf`, `sha2`): `paccel::layer::application::quic::decrypt_initial_client_hello`/`decrypt_initial_packet` recover a QUIC Initial packet's plaintext, including the ClientHello, using only keys derivable from the packet's own Destination Connection ID (RFC 9001 §5.2 - this is the same on-path visibility any DPI tool or Wireshark itself has, not a break of QUIC's security model). For Handshake/1-RTT, `decrypt_packet_with_secret` takes a secret from `paccel::layer::application::quic::QuicKeyLog`, which parses the standard `SSLKEYLOGFILE` text format (`<Label> <ClientHelloRandomHex> <SecretHex>` per line, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`/`SERVER_HANDSHAKE_TRAFFIC_SECRET`/`CLIENT_TRAFFIC_SECRET_0`/`SERVER_TRAFFIC_SECRET_0`) - the same file curl, browsers, and Wireshark itself already know how to produce via the `SSLKEYLOGFILE` environment variable. There is no way around needing this file for Handshake/1-RTT: those levels are protected by a live ECDHE exchange, not something derivable from a capture alone.
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

**None of this affects the published crate.** `tests/pcaps/` and `fuzz/` are excluded from the packaged crate (see `exclude` in `Cargo.toml`) — `cargo package --list` confirms zero binary fixtures ship. Everything under `src/` is original, written from RFCs/specs and verified against `tshark`'s output, not derived from Wireshark's own (GPLv2) source code. Apache-2.0 in `LICENSE` covers the crate as published; the third-party test data below exists only in this git repository, for local test use, under its own license.

`tests/pcaps/happy-path/*` are small hand-built captures (tens to hundreds of bytes each); no external source.

`tests/pcaps/protocol-gaps/*` are a mix of hand-built captures and real-world captures pulled from public sources for ground-truth testing (byte layouts cross-checked against `tshark`'s own dissectors before writing each parser). Origin of each real capture:

| Fixture | Source |
|---|---|
| `cdp_device_id.pcap` | Hand-built with [scapy](https://scapy.net/) (`scapy.contrib.cdp`); no external capture |
| `eigrp_hello.cap` | [Wireshark SampleCaptures: `[redacted]`]([redacted]) |
| `ftp_session.cap` | [Wireshark SampleCaptures: `[redacted]`]([redacted]) (trimmed to `tcp.port==21`, reformatted from NetMon to pcapng) |
| `hsrp_hello.pcap` | [Wireshark SampleCaptures: `hsrp.pcap`]([redacted]) |
| `http2_get_hello.pcap` | Self-generated on loopback: `curl --http2-prior-knowledge` against a local Python [`h2`](https://github.com/python-hyper/h2) library server, captured with `tcpdump`; not third-party/GPL data |
| `ikev2_sa_init.pcap` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `imap_banner.cap` | [Wireshark SampleCaptures: `imap.cap`]([redacted]) |
| `lacp.pcap` | [Wireshark SampleCaptures: `[redacted]`]([redacted]) |
| `nfs_getattr.pcap` | [Wireshark test suite: `nfs.pcap`]([redacted]) |
| `ospf_hello.cap` | [Wireshark SampleCaptures: `ospf.cap`]([redacted]) |
| `pim_hello_register.cap` | [Wireshark SampleCaptures: `[redacted]`]([redacted]) |
| `quic_fragmented_handshake.pcapng` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `quic_multistream.pcapng` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `quic_retry.pcapng` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `quic_tls_upgrade.pcapng` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `rip_v1.pcap` | [Wireshark SampleCaptures: `RIP_v1`]([redacted]) |
| `rtcp_sr_rr.pcap` | [Wireshark SampleCaptures: `[redacted]`]([redacted]) (`tls-1.3/sip.pcap` inside the archive) |
| `smb1_negotiate.cap` | [Wireshark SampleCaptures: `[redacted]`]([redacted]) (2 frames extracted) |
| `smb2_negotiate.pcapng` | [The Ultimate PCAP by Johannes Weber]([redacted]) (2 frames extracted) |
| `smtp_session.pcap` | [Wireshark SampleCaptures: `smtp.pcap`]([redacted]) |
| `ssh_banner.pcapng` | [Wireshark SampleCaptures: `[redacted]`]([redacted]) |
| `syslog_messages.pcapng` | [The Ultimate PCAP by Johannes Weber]([redacted]) (2 frames extracted) |
| `telnet_iac.pcap` | [Wireshark SampleCaptures: `[redacted]`]([redacted]) |
| `tls12_sni.pcapng` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `tls13_handshake.pcap` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `vrrp_advertisement.pcapng` | [The Ultimate PCAP by Johannes Weber]([redacted]) (1 frame extracted) |
| `wireguard_ping_tcp.pcap` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `wireguard_psk.pcap` | [Wireshark test suite: `[redacted]`]([redacted]) |
| `bgp_shutdown.pcap`, `coap_cbor.pcap`, `dhcpv6.pcap`, `dnp3_read.pcap`, `kerberos.pcapng`, `ldap_search.pcap`, `modbus.pcap`, `mqtt.pcap`, `nntp.pcap`, `openvpn_tcp_tls-auth.pcapng`, `openvpn_udp_tls-auth.pcapng`, `radius_localhost.pcapng`, `sip-rtp-g711.pcap`, `snmp_usm.pcap`, `tftp_rrq.pcap` | Added in an earlier session; exact source not recorded |

[redacted]

SSDP/NAT-PMP/PCP classification is tested against in-code synthetic frames (`tests/pcap_integration.rs`) rather than a captured pcap — an earlier fixture built from a local home-network capture was removed and purged from git history since it embedded real device MAC/IP addresses.

## License

Apache-2.0 (see `LICENSE`).
