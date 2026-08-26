# Changelog

## 0.1.0 — unreleased

Initial public release.

### Core

- Zero-dependency-by-default stateless packet parser (`BuiltinPacketParser`).
- Link: Ethernet II, VLAN/QinQ, Linux SLL/SLL2, 802.11 + radiotap, ARP, PPPoE, MPLS, LLDP, STP, CDP, LACP.
- Network: IPv4 (with options), IPv6 (with extension headers), ICMP, ICMPv6/NDP, IGMP, OSPF, PIM, EIGRP, VRRP.
- Transport: TCP (with options), UDP, SCTP, GRE, AH, ESP, L2TP.
- Tunnels (recursive inner decode): GRE, VXLAN, GENEVE, MPLS, IP-in-IP.
- 40+ application-layer protocols — see README's protocol table.
- pcap and pcapng capture parsing, linktype-aware (Ethernet, SLL, SLL2, NULL, RAW, FDDI/SNAP, 802.11).
- Strict/permissive parse modes; designed to handle malformed input without panicking (fuzz-, property-, malformed-input-, and differential-tested).

### Opt-in stateful components

- IPv4/IPv6 fragment reassembly with hard flow-count bounds (FIFO eviction) and overlap-drops-the-datagram semantics.
- TCP stream reassembly and `SessionTracker` (multi-segment HTTP/TLS), same bounded-flow-count model. **Experimental**: partially-overlapping out-of-order TCP segments have no explicit reject policy yet.
- `QuicConnectionTracker`: connection-ID/packet-number state across a QUIC flow.

### Experimental features (feature-gated)

- `quic-decrypt`: QUIC Initial-packet decrypt from publicly-derivable keys; Handshake/1-RTT decrypt via an externally-supplied `SSLKEYLOGFILE` secret.
- `fingerprint`: JA3/JA4 (TLS ClientHello), JA3S (TLS ServerHello), HASSH/HASSHServer (SSH KEXINIT).

### Known limitations

- HTTP/2 is frame-header-only (no HPACK), standalone module, not wired into `BuiltinPacketParser` yet.
- No HTTP/3, GTP, or Diameter support.
- QUIC: no Version Negotiation list parsing, no coalesced-packet splitting, no STREAM frame parsing.
- No JA4S/JA4X/JA4H/JA4SSH fingerprint variants yet.

See README's "Capability maturity" section for the full per-component breakdown.
