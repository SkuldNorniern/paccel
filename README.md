# Paccel

Paccel is an in-progress Rust packet parsing engine focused on practical protocol visibility, correctness, and performance.

The goal is to become a strong parsing alternative for Fluere workloads (not a full Wireshark clone).

## Current status

- parser engine scaffolding is in place (`engine/*`)
- packet model is split into owned + view modules (`packet/*`)
- built-in parsing path exists for:
  - Ethernet II
  - VLAN/QinQ
  - ARP
  - IPv4
  - IPv6 + basic extension header walk
  - TCP
  - UDP
  - DNS over UDP/53 and mDNS over UDP/5353 (heuristic-gated)
  - UDP app hints for DHCP/NTP/mDNS/DNS
- low-level borrowed packet wrappers exist for manual parsing flows:
  - `packet::EthernetPacket`, `packet::Ipv4Packet`, `packet::Ipv6Packet`, `packet::TcpPacket`, `packet::UdpPacket`, `packet::ArpPacket`, `packet::DnsPacket`, `packet::IcmpPacket`, `packet::Icmpv6Packet`

## What it is not yet

- no fragment reassembly engine yet
- no TCP stream reassembly yet
- tshark corpus scaffolding exists, but automated parity checks are not implemented yet
- baseline pcap-vs-scapy parity test exists, but coverage is still small
- still uses intermediate allocations in parts of hot path

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
                println!("udp app hints: {:?}", parsed.udp_hints);
            }
            for warning in parsed.warnings {
                println!("warning [{:?}]: {}", warning.code, warning.message);
            }
        }
        Err(err) => {
            println!("parse error: {}", err);
        }
    }
}
```

You can also call `BuiltinPacketParser::parse_with_config(...)` to tune parse limits (for example IPv6 extension depth).

For pcap workflows, use `paccel::engine::parse_pcap_frames(...)` and feed each frame into `BuiltinPacketParser`.

The core `BuiltinPacketParser` is intentionally stateless by design (similar to libpnet/scapy usage patterns).
Flow/state tracking should be composed on the integration side (for example inside Fluere).

## Development notes

- Main plan and roadmap: `paccel/plan.md`
- Current architecture notes: `paccel/docs/current-architecture.md`
- Run tests from crate root:
  - `cargo test`
- Generate tshark snapshots for corpus files:
  - `tests/scripts/generate_tshark_snapshots.sh`
- Capture a fresh pcap with tcpdump (requires permissions):
  - `tests/scripts/capture_with_tcpdump.sh tests/pcaps/happy-path/tcpdump_capture.pcap any 200`
- Generate scapy snapshot for a pcap fixture:
  - `tests/scripts/generate_scapy_snapshot.py tests/pcaps/happy-path/tcpdump_dns_udp.pcap tests/snapshots/scapy/tcpdump_dns_udp.expected.json`
- Regenerate scapy snapshot and run parity test:
  - `tests/scripts/compare_pcap_with_scapy.sh`

Included fixture:

- `tests/pcaps/happy-path/tcpdump_dns_udp.pcap` copied from tcpdump test corpus (`tests/dns_udp.pcap`).

## License

MIT (see `paccel/LICENSE`).
