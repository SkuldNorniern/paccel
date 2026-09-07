#![allow(clippy::panic)]

use paccel::engine::{
    BuiltinPacketParser, ParseConfig, ParseMode, ParseWarningCode, TransportSegment,
    iter_capture_frames, parse_capture_frames,
};
use paccel::layer::application::dns::parse_dns_message;

fn pcap_header() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&0i32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&65_535u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes
}

fn pcapng_section() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0a0d_0d0au32.to_be_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    bytes.extend_from_slice(&28u32.to_le_bytes());
    bytes
}

fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes.extend_from_slice(&ethertype.to_be_bytes());
    bytes
}

fn ipv4_header(ihl: u8, total_length: u16, protocol: u8) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[0] = 0x40 | ihl;
    bytes[2..4].copy_from_slice(&total_length.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes
}

fn ipv6_header(payload_length: u16, next_header: u8) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&payload_length.to_be_bytes());
    bytes[6] = next_header;
    bytes[7] = 64;
    bytes
}

fn strict_config() -> ParseConfig {
    ParseConfig {
        mode: ParseMode::Strict,
        ..ParseConfig::default()
    }
}

fn assert_capture_error(bytes: &[u8]) {
    assert!(parse_capture_frames(bytes).is_err());

    match iter_capture_frames(bytes) {
        Err(_) => {}
        Ok(mut frames) => assert!(frames.any(|frame| frame.is_err())),
    }
}

fn assert_packet_error(bytes: &[u8]) {
    assert!(BuiltinPacketParser::parse(bytes).is_err());
    assert!(BuiltinPacketParser::parse_with_config(bytes, strict_config()).is_err());
}

fn assert_packet_warning(bytes: &[u8]) {
    let parsed =
        BuiltinPacketParser::parse(bytes).expect("permissive parse should return warnings");
    assert!(!parsed.warnings.is_empty());
}

// Capture layer

#[test]
fn pcap_truncated_mid_record_header_is_rejected() {
    let mut bytes = pcap_header();
    bytes.extend_from_slice(&[0; 9]);
    assert_capture_error(&bytes);
}

#[test]
fn pcap_giant_included_length_is_rejected() {
    let mut bytes = pcap_header();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_capture_error(&bytes);
}

#[test]
fn pcap_magic_with_truncated_global_header_is_rejected() {
    let mut bytes = pcap_header();
    bytes.truncate(23);
    assert_capture_error(&bytes);
}

#[test]
fn pcapng_section_block_smaller_than_minimum_is_rejected() {
    let mut bytes = pcapng_section();
    bytes[4..8].copy_from_slice(&8u32.to_le_bytes());
    assert_capture_error(&bytes);
}

#[test]
fn pcapng_enhanced_packet_cap_len_outside_block_is_rejected() {
    let mut bytes = pcapng_section();
    bytes.extend_from_slice(&6u32.to_le_bytes());
    bytes.extend_from_slice(&32u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&64u32.to_le_bytes());
    bytes.extend_from_slice(&64u32.to_le_bytes());
    bytes.extend_from_slice(&32u32.to_le_bytes());
    assert_capture_error(&bytes);
}

#[test]
fn pcapng_unaligned_block_length_is_rejected() {
    let mut bytes = pcapng_section();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&14u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 6]);
    assert_capture_error(&bytes);
}

#[test]
fn pcapng_mismatched_trailer_length_is_rejected() {
    let mut bytes = pcapng_section();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&20u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&16u32.to_le_bytes());
    assert_capture_error(&bytes);
}

#[test]
fn empty_and_tiny_captures_are_rejected() {
    assert_capture_error(&[]);
    for len in 1..=3 {
        assert_capture_error(&vec![0; len]);
    }
}

#[test]
fn all_zero_capture_is_rejected() {
    assert_capture_error(&[0; 64]);
}

// Packet layer

#[test]
fn truncated_ethernet_headers_are_rejected() {
    for len in 0..14 {
        assert_packet_error(&vec![0; len]);
    }
}

#[test]
fn ipv4_max_ihl_with_short_header_is_rejected_only_in_strict_mode() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(15, 60, 6));

    let parsed = BuiltinPacketParser::parse(&bytes).expect("permissive keeps what it read");
    let ipv4 = parsed.ipv4.as_ref().expect("the addresses are still valid");
    assert!(ipv4.options_truncated, "the options did not survive");
    assert!(ipv4.options.is_none(), "and none are invented");
    assert!(BuiltinPacketParser::parse_with_config(&bytes, strict_config()).is_err());
}

#[test]
fn ipv4_total_length_beyond_capture_warns_or_errors() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(5, u16::MAX, 255));

    assert_packet_warning(&bytes);
    assert!(BuiltinPacketParser::parse_with_config(&bytes, strict_config()).is_err());
}

#[test]
fn udp_length_beyond_capture_is_rejected_only_in_strict_mode() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(5, 28, 17)); // 20 IP + 8 UDP header, no payload
    let mut udp = vec![0; 8];
    udp[4..6].copy_from_slice(&20u16.to_be_bytes()); // declares 20, only 8 present
    bytes.extend_from_slice(&udp);

    assert!(
        BuiltinPacketParser::parse(&bytes).is_ok(),
        "permissive mode should clamp, not error"
    );
    assert!(BuiltinPacketParser::parse_with_config(&bytes, strict_config()).is_err());
}

#[test]
fn tcp_max_data_offset_with_short_header_is_rejected_only_in_strict_mode() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(5, 40, 6));
    let mut tcp = vec![0; 20];
    tcp[12] = 0xf0;
    bytes.extend_from_slice(&tcp);

    let parsed = BuiltinPacketParser::parse(&bytes).expect("permissive keeps what it read");
    assert!(parsed.ipv4.is_some(), "the addresses are still valid");

    // All twenty fixed bytes arrived; only the option list the data offset
    // named is missing. Nothing has to be invented to report the sequence
    // number, flags and window, so they are reported - the same way a
    // truncated IPv4 option list still yields its addresses.
    let Some(TransportSegment::Tcp(tcp)) = &parsed.transport else {
        panic!("expected the fixed header, got {:?}", parsed.transport);
    };
    assert!(tcp.options_truncated, "and the shortfall is recorded");
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| w.code == ParseWarningCode::TcpOptionsTruncated),
        "with a warning saying so"
    );
    assert!(BuiltinPacketParser::parse_with_config(&bytes, strict_config()).is_err());
}

/// The distinction the case above turns on: when the fixed fields themselves
/// did not arrive, there is nothing to report and the ports are all that is
/// kept. Reporting a header here would mean inventing the missing fields.
#[test]
fn a_tcp_header_cut_inside_its_fixed_fields_is_still_absent() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(5, 32, 6));
    let mut tcp = vec![0; 12];
    tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
    bytes.extend_from_slice(&tcp);

    let parsed = BuiltinPacketParser::parse(&bytes).expect("permissive keeps what it read");
    assert!(
        parsed.transport.is_none(),
        "twelve bytes are not a tcp header"
    );
    assert_eq!(
        parsed.ports(),
        Some((1234, 80)),
        "the ports did survive, and are what a flow is keyed on"
    );
}

#[test]
fn ipv6_payload_length_beyond_capture_warns_or_errors() {
    let mut bytes = ethernet(0x86dd);
    bytes.extend_from_slice(&ipv6_header(u16::MAX, 59));

    assert_packet_warning(&bytes);
    assert!(BuiltinPacketParser::parse_with_config(&bytes, strict_config()).is_err());
}

#[test]
fn ipv6_extension_chain_stops_at_depth_limit() {
    const ROUTING_HEADERS: u16 = 32;

    let mut bytes = ethernet(0x86dd);
    bytes.extend_from_slice(&ipv6_header(ROUTING_HEADERS * 8, 43));
    for _ in 0..ROUTING_HEADERS {
        bytes.extend_from_slice(&[43, 0, 0, 0, 0, 0, 0, 0]);
    }

    assert_packet_warning(&bytes);
    let strict = BuiltinPacketParser::parse_with_config(&bytes, strict_config())
        .expect("strict parse should also stop at the extension depth limit");
    assert!(!strict.warnings.is_empty());
}

#[test]
fn deeply_nested_vlan_stack_truncated_after_tag_is_rejected() {
    let mut bytes = ethernet(0x8100);
    for _ in 0..100 {
        bytes.extend_from_slice(&[0, 0, 0x81, 0x00]);
    }
    assert_packet_error(&bytes);
}

#[test]
fn unterminated_mpls_stack_stops_at_depth_limit() {
    let mut bytes = ethernet(0x8847);
    for _ in 0..100 {
        bytes.extend_from_slice(&[0, 0, 0, 64]);
    }

    assert_packet_warning(&bytes);
    let strict = BuiltinPacketParser::parse_with_config(&bytes, strict_config())
        .expect("strict parse should also stop at the MPLS depth limit");
    assert!(!strict.warnings.is_empty());
}

// DNS layer

#[test]
fn dns_max_question_count_with_header_only_is_rejected() {
    let mut bytes = vec![0; 12];
    bytes[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(parse_dns_message(&bytes).is_err());
}

#[test]
fn dns_forward_compression_pointer_is_rejected() {
    let mut bytes = vec![0; 12];
    bytes[5] = 1;
    bytes.extend_from_slice(&[0xc0, 0x0e, 0, 1, 0, 1]);
    assert!(parse_dns_message(&bytes).is_err());
}

#[test]
fn dns_compression_pointer_that_re_reads_itself_is_rejected() {
    let mut bytes = vec![0; 10];
    bytes.extend_from_slice(&[0xc0, 0x0a]);
    bytes[5] = 1;
    bytes.extend_from_slice(&[0xc0, 0x0a, 0, 1, 0, 1]);
    assert!(parse_dns_message(&bytes).is_err());
}

#[test]
fn dns_label_spanning_past_buffer_is_rejected() {
    let mut bytes = vec![0; 12];
    bytes[5] = 1;
    bytes.extend_from_slice(&[63, b'a', b'b', b'c']);
    assert!(parse_dns_message(&bytes).is_err());
}

/// RFC 1701 sec 4.1: with the routing bit set a variable-length source-route
/// list follows the fixed fields, so the payload is not at `header_len`.
/// Decoding from there reads routing data as an inner packet, which is how
/// tshark and scapy both decline it. RFC 2784 sec 2.3.1 deprecates routing and
/// tells receivers to discard.
#[test]
fn gre_with_the_routing_bit_set_decodes_no_inner_packet() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(5, 44, 47));
    // Routing present, protocol IPv4, then what would look like an inner packet.
    bytes.extend_from_slice(&[0x40, 0x00, 0x08, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&ipv4_header(5, 20, 6));

    let parsed = BuiltinPacketParser::parse(&bytes).expect("the outer packet is fine");
    let gre = parsed.gre.expect("the gre header itself parses");
    assert!(gre.routing_present);
    assert!(
        parsed.inner.is_none(),
        "a payload that cannot be located must not be decoded from a guess"
    );
}

/// A frame with a complete link header and nothing behind it still has usable
/// addresses and VLAN tags. Discarding the whole frame loses the only thing it
/// carried.
#[test]
fn a_frame_that_is_only_a_link_header_keeps_it() {
    let bytes = ethernet(0x0800);

    let parsed = BuiltinPacketParser::parse(&bytes).expect("permissive keeps the link header");
    assert!(parsed.ethernet.is_some(), "the addresses are still valid");
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| w.code == ParseWarningCode::LinkPayloadTruncated),
        "and it says why there is nothing more"
    );
    assert!(BuiltinPacketParser::parse_with_config(&bytes, strict_config()).is_err());
}

/// A network header too short to parse used to throw the frame away, taking
/// the VLAN tag and MAC addresses with it.
#[test]
fn a_vlan_tag_survives_a_network_header_that_does_not() {
    let mut bytes = vec![0x00; 12];
    bytes.extend_from_slice(&[0x81, 0x00]);
    bytes.extend_from_slice(&[0x00, 0x64]);
    bytes.extend_from_slice(&[0x08, 0x00]);
    bytes.extend_from_slice(&[0x45, 0x00, 0x00]);

    let parsed = BuiltinPacketParser::parse(&bytes).expect("permissive keeps what it read");
    let ethernet = parsed.ethernet.expect("the link header");
    assert_eq!(
        ethernet.vlan_tags.first().map(|tag| tag & 0x0fff),
        Some(100),
        "the vlan tag parsed and must not be discarded with the ip header"
    );
    assert!(
        parsed.ipv4.is_none(),
        "nothing is invented for the part that failed"
    );
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| w.code == ParseWarningCode::NetworkHeaderUnreadable),
        "and it says the network header could not be read"
    );
    assert!(BuiltinPacketParser::parse_with_config(&bytes, strict_config()).is_err());
}
