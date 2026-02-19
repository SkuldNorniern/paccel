# Paccel

Paccel is an in-progress Rust packet parsing engine focused on practical protocol visibility, correctness, and performance.

The goal is to become a strong parsing alternative for Fluere workloads (not a full Wireshark clone).

## Current status

- parser engine scaffolding is in place (`engine/*`)
- packet model is split into owned + view modules (`packet/*`)
- built-in parsing path exists for:
  - Ethernet II, SLL/SLL2 at parse entry
  - VLAN/QinQ
  - ARP
  - IPv4 (truncation and fragment warnings)
  - IPv6 + basic extension header walk
  - TCP (with options: MSS, window scale), UDP
  - ICMP (1), ICMPv6 (58), IGMP (2); minimal headers
  - GRE (protocol 47); minimal header, protocol type
  - MPLS (ethertypes 0x8847/0x8848); minimal label stack metadata
  - GENEVE (UDP 6081); minimal header metadata
  - AH (protocol 51) and ESP (protocol 50); minimal SPI/sequence metadata
  - WireGuard over UDP (default ports 51820/51821); message-type classification (init/response/cookie/data)
  - PPPoE (ethertypes 0x8863/0x8864); minimal header
  - DNS over UDP/53 and mDNS over UDP/5353 (heuristic-gated)
  - UDP app hints for DHCP/NTP/mDNS/DNS
- low-level borrowed packet wrappers exist for manual parsing flows:
  - `packet::EthernetPacket`, `packet::SllPacket`, `packet::Sll2Packet`, `packet::Ipv4Packet`, `packet::Ipv6Packet`, `packet::TcpPacket`, `packet::UdpPacket`, `packet::ArpPacket`, `packet::DnsPacket`, `packet::IcmpPacket`, `packet::Icmpv6Packet`, `packet::DhcpPacket`, `packet::GrePacket`, `packet::VxlanPacket`, `packet::VlanTagView`

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

## libpnet compatibility snapshot

| Capability | libpnet | paccel |
|---|---|---|
| Low-level packet views (Ethernet/IP/TCP/UDP/ARP/DNS/ICMP) | yes | yes |
| Linux cooked capture (SLL/SLL2) | yes | yes |
| Typed protocol/ethertype name helpers | yes | yes |
| One-shot structured parse output with warnings | limited | yes |
| Tunnel metadata in one parse pass (MPLS/VXLAN/GENEVE/AH/ESP/WireGuard) | partial | yes |
| Strict/permissive parser mode | no | yes |
| Built-in raw send/receive transport stack | yes | no (out of scope) |
| Core mutable packet-builder API | yes | no (deferred/non-goal in core) |

## Explicit core non-goals (current scope)

- No built-in flow table, reassembly engine, or stream tracker in core parser.
- No raw datalink/transport send/receive runtime in core parser.
- No macro-heavy mutable packet construction API in core crate.

## Development notes

- Main plan and roadmap: `paccel/plan.md`
- Current architecture notes: `paccel/docs/current-architecture.md`
- Fluere `pcap` adapter notes: `paccel/docs/fluere-pcap-adapter.md`
- Parser perf baseline notes: `paccel/docs/perf-baseline.md`
- Run tests from crate root:
  - `cargo test`
- Run parser benchmarks:
  - `cargo bench --bench builtin_parser_baseline`
- Run parser benchmark regression guard:
  - `python3 tests/scripts/check_benchmark_guard.py`
- Refresh benchmark baseline doc from current run:
  - `python3 tests/scripts/update_perf_baseline.py`
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
- `tests/pcaps/happy-path/tcpdump_ntp.pcap` copied from tcpdump test corpus (`tests/ntp.pcap`).
- `tests/pcaps/happy-path/tcpdump_icmpv6.pcap` copied from tcpdump test corpus (`tests/icmpv6.pcap`).

## License

MIT (see `paccel/LICENSE`).
