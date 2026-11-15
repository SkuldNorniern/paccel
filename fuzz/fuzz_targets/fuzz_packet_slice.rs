#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use paccel::engine::{BuiltinPacketParser, TransportSegment};
use paccel::packet::PacketSlice;

/// `PacketSlice` reads the outermost L2-L4 stack in place; the full parser
/// reads the same bytes and recurses further. Where both name the outermost
/// addresses or ports, they have to name the same ones - a disagreement means
/// one of the two walked the frame wrong.
fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let linktype = u16::from_le_bytes([data[0], data[1]]);
    let frame = &data[2..];

    let slice = PacketSlice::with_linktype(frame, Some(linktype));
    let Ok(parsed) = BuiltinPacketParser::parse_with_linktype(frame, linktype) else {
        return;
    };
    let Some(slice) = slice else { return };

    let parsed_addresses = match (parsed.ipv4.as_ref(), parsed.ipv6.as_ref()) {
        (Some(ipv4), _) => Some((IpAddr::V4(ipv4.source), IpAddr::V4(ipv4.destination))),
        (None, Some(ipv6)) => Some((IpAddr::V6(ipv6.source), IpAddr::V6(ipv6.destination))),
        (None, None) => None,
    };
    if let (Some(from_slice), Some(from_parse)) = (slice.addresses(), parsed_addresses) {
        assert_eq!(from_slice, from_parse, "addresses disagree");
    }

    let parsed_ports = match parsed.transport.as_ref() {
        Some(TransportSegment::Tcp(tcp)) => Some((tcp.source_port, tcp.destination_port)),
        Some(TransportSegment::Udp(udp)) => Some((udp.source_port, udp.destination_port)),
        _ => None,
    };
    if let (Some(from_slice), Some(from_parse)) = (slice.ports(), parsed_ports) {
        assert_eq!(from_slice, from_parse, "ports disagree");
    }

    // An offset the slice reports has to sit inside the frame it was read from.
    if let Some(at) = slice.network_offset() {
        assert!(at <= frame.len(), "network offset past the frame");
    }
    if let Some(at) = slice.transport_offset() {
        assert!(at <= frame.len(), "transport offset past the frame");
    }
});
