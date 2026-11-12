#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::engine::{BuiltinPacketParser, ParsedPacket};

/// Every network header the parse found has to be findable again in the frame.
///
/// A caller that rewrites addresses in place trusts these offsets, so an
/// offset that runs past the buffer, or names bytes other than the ones the
/// parse reported, is a bug whatever the input was.
fn offsets_locate_the_addresses(frame: &[u8], packet: &ParsedPacket, parent: usize) {
    let base = parent + packet.frame_offset;
    if let Some(at) = packet.network_offset {
        let at = base + at;
        if let Some(ipv4) = packet.ipv4.as_ref() {
            assert_eq!(frame[at + 12..at + 16], ipv4.source.octets());
            assert_eq!(frame[at + 16..at + 20], ipv4.destination.octets());
        }
        if let Some(ipv6) = packet.ipv6.as_ref() {
            assert_eq!(frame[at + 8..at + 24], ipv6.source.octets());
            assert_eq!(frame[at + 24..at + 40], ipv6.destination.octets());
        }
        if let Some(arp) = packet.arp.as_ref() {
            assert_eq!(frame[at + 14..at + 18], arp.sender_protocol_addr.octets());
            assert_eq!(frame[at + 24..at + 28], arp.target_protocol_addr.octets());
        }
    } else {
        assert!(packet.ipv4.is_none() && packet.ipv6.is_none() && packet.arp.is_none());
    }

    if let Some(inner) = packet.inner.as_deref() {
        offsets_locate_the_addresses(frame, inner, base);
    }
    if let Some(quoted) = packet.icmp_quoted.as_deref() {
        offsets_locate_the_addresses(frame, quoted, base);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let linktype = u16::from_le_bytes([data[0], data[1]]);
    let frame = &data[2..];
    if let Ok(parsed) = BuiltinPacketParser::parse_with_linktype(frame, linktype) {
        offsets_locate_the_addresses(frame, &parsed, 0);
    }
});
