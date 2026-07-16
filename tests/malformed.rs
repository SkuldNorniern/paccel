#![allow(clippy::panic)]

use paccel::engine::{
    BuiltinPacketParser, ParseConfig, ParseMode, iter_capture_frames, parse_capture_frames,
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
fn ipv4_max_ihl_with_short_header_is_rejected() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(15, 60, 6));
    assert_packet_error(&bytes);
}

#[test]
fn ipv4_total_length_beyond_capture_warns_or_errors() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(5, u16::MAX, 255));

    assert_packet_warning(&bytes);
    assert!(BuiltinPacketParser::parse_with_config(&bytes, strict_config()).is_err());
}

#[test]
fn tcp_max_data_offset_with_short_header_is_rejected() {
    let mut bytes = ethernet(0x0800);
    bytes.extend_from_slice(&ipv4_header(5, 40, 6));
    let mut tcp = vec![0; 20];
    tcp[12] = 0xf0;
    bytes.extend_from_slice(&tcp);
    assert_packet_error(&bytes);
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
