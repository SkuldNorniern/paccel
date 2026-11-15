//! Public methods that nothing else in the tree calls.
//!
//! Each of these is reachable by a user of the crate and was, until this file,
//! never executed - so an off-by-one in the offsets or a wrong argument in a
//! clock-taking variant would have shipped unseen.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use paccel::engine::{
    BuiltinPacketParser, IpFragmentReassembler, QuicStreamReassembler, TcpStreamReassembler,
    TransportSegment,
};
use paccel::layer::network::ipv4::Ipv4Header;
use paccel::packet::{ArpPacket, DhcpPacket, DnsPacket, PacketSlice, TransportSlice};

/// Ethernet + IPv4 + UDP, built by hand so every field below has a known value.
fn udp_frame() -> Vec<u8> {
    let mut frame = vec![
        // Ethernet: dst, src, ethertype IPv4
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
    ];
    frame.extend([
        // IPv4: ihl 5, total length 32, ttl 64, protocol UDP, 10.0.0.1 -> 10.0.0.2
        0x45, 0x00, 0x00, 0x20, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10, 0,
        0, 2,
    ]);
    // UDP: 1234 -> 53, length 12, no checksum
    frame.extend([0x04, 0xd2, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00]);
    frame.extend([0xde, 0xad, 0xbe, 0xef]);
    frame
}

#[test]
fn the_slice_hands_back_the_transport_it_read() {
    let frame = udp_frame();
    let slice = PacketSlice::new(&frame).expect("an ethernet frame");
    match slice.transport().expect("a udp header") {
        TransportSlice::Udp(udp) => {
            assert_eq!(udp.source_port(), 1234);
            assert_eq!(udp.destination_port(), 53);
        }
        other => unreachable!("expected udp, got {other:?}"),
    }
}

#[test]
fn a_parse_names_the_protocol_at_every_layer() {
    let frame = udp_frame();
    let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
    assert_eq!(parsed.link_protocol_name(), Some("ipv4"));
    assert_eq!(parsed.network_protocol_name(), Some("ipv4"));
    assert_eq!(parsed.transport_protocol_name(), Some("udp"));
    assert_eq!(parsed.warning_code_names().count(), parsed.warnings.len());
    assert_eq!(parsed.tunnel_protocol_names().count(), 0);
    assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
}

/// The bytes a DHCP and an ARP packet carry at fixed offsets, per RFC 2131 and
/// RFC 826. A reader that slipped by one would find the neighbouring field.
#[test]
fn the_fixed_offset_readers_find_their_fields() {
    let mut dhcp = vec![0u8; 240];
    dhcp[0] = 1; // op: request
    dhcp[3] = 7; // hops
    dhcp[8..10].copy_from_slice(&600u16.to_be_bytes()); // secs
    dhcp[12..16].copy_from_slice(&[192, 168, 1, 10]); // ciaddr
    dhcp[20..24].copy_from_slice(&[192, 168, 1, 1]); // siaddr
    dhcp[24..28].copy_from_slice(&[192, 168, 1, 254]); // giaddr
    dhcp[236..240].copy_from_slice(&[99, 130, 83, 99]); // RFC 2132 magic cookie
    let dhcp = DhcpPacket::new(&dhcp).expect("a bootp-sized packet");
    assert_eq!(dhcp.hops(), 7);
    assert_eq!(dhcp.secs(), 600);
    assert_eq!(dhcp.ciaddr(), Ipv4Addr::new(192, 168, 1, 10));
    assert_eq!(dhcp.siaddr(), Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(dhcp.giaddr(), Ipv4Addr::new(192, 168, 1, 254));

    let mut arp = vec![0u8; 28];
    arp[4] = 6; // hardware length, Ethernet
    arp[5] = 4; // protocol length, IPv4
    arp[8..14].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    arp[18..24].copy_from_slice(&[0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]);
    let arp = ArpPacket::new(&arp).expect("an arp-sized packet");
    assert_eq!(
        arp.sender_hardware_addr(),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
    );
    assert_eq!(
        arp.target_hardware_addr(),
        [0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc]
    );

    let mut dns = vec![0u8; 12];
    dns[8..10].copy_from_slice(&3u16.to_be_bytes());
    let dns = DnsPacket::new(&dns).expect("a dns header");
    assert_eq!(dns.authority_count(), 3);
}

/// The dated variants are the ones `expire_before` can act on. Undated flows
/// are left alone, so a clock that never reached the flow would show up as a
/// flow that refuses to expire.
#[test]
fn a_dated_flow_expires_and_an_undated_one_does_not() {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    let mut tcp = TcpStreamReassembler::new();
    let out = tcp.offer_detailed_at(src, 1000, dst, 80, 1, true, false, false, b"", 100);
    assert!(out.data.is_empty(), "a bare SYN carries no payload");
    tcp.offer_detailed_at(src, 1000, dst, 80, 2, false, false, false, b"abcd", 100);
    assert_eq!(tcp.expire_before(50), 0, "not yet past the flow's date");
    assert_eq!(tcp.expire_before(200), 1, "the dated flow ages out");

    let mut quic = QuicStreamReassembler::new();
    let out = quic.offer_detailed_at(src, 1000, dst, 443, 0, 0, false, b"hello", 100);
    assert_eq!(out.data, b"hello");
    assert_eq!(quic.expire_before(50), 0);
    assert_eq!(quic.expire_before(200), 1);
}

/// A fragment set whose remainder never arrives is what dating is for.
#[test]
fn a_dated_fragment_set_ages_out() {
    let header = Ipv4Header {
        version: 4,
        ihl: 5,
        dscp: 0,
        ecn: 0,
        total_length: 28,
        identification: 0x1234,
        flags: 1, // more fragments
        fragment_offset: 0,
        ttl: 64,
        protocol: 17,
        checksum: 0,
        source: Ipv4Addr::new(10, 0, 0, 1),
        destination: Ipv4Addr::new(10, 0, 0, 2),
        options: None,
        options_truncated: false,
    };

    let mut fragments = IpFragmentReassembler::new();
    assert_eq!(fragments.offer_ipv4_at(&header, b"abcdefgh", 100), None);
    assert!(fragments.total_bytes() > 0, "the first fragment is held");
    assert_eq!(fragments.expire_before(50), 0);
    assert_eq!(
        fragments.expire_before(200),
        1,
        "the half datagram ages out"
    );
    assert_eq!(fragments.total_bytes(), 0);
}

/// IPv6 fragments could not be dated at all until `offer_ipv6_at`, so a half
/// arrived datagram only ever left through the byte cap, never the clock.
#[test]
fn a_dated_ipv6_fragment_set_ages_out() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    let mut fragments = IpFragmentReassembler::new();
    assert_eq!(
        fragments.offer_ipv6_at(src, dst, 0x99, 0, true, 17, b"abcdefgh", 100),
        None,
        "the tail has not arrived"
    );
    assert!(fragments.total_bytes() > 0, "the first fragment is held");
    assert_eq!(fragments.expire_before(50), 0, "not yet past its date");
    assert_eq!(
        fragments.expire_before(200),
        1,
        "the half datagram ages out"
    );
    assert_eq!(fragments.total_bytes(), 0);

    // The undated form still refuses to age, which is what leaves it to the cap.
    let mut undated = IpFragmentReassembler::new();
    undated.offer_ipv6(src, dst, 0x99, 0, true, 17, b"abcdefgh");
    assert_eq!(undated.expire_before(u64::MAX), 0);
}

#[test]
fn an_ipv6_address_still_keys_a_quic_stream() {
    let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
    let mut quic = QuicStreamReassembler::new();
    let out = quic.offer_detailed_at(src, 1000, dst, 443, 7, 0, true, b"done", 10);
    assert_eq!(out.data, b"done");
}

/// A connection-keyed stream could not be dated either, so a migrated QUIC
/// connection's buffered bytes only ever left through the stream cap.
#[test]
fn a_dated_connection_keyed_stream_ages_out() {
    use paccel::engine::QuicConnectionTracker;

    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let server_cid = [9, 9, 9, 9];

    let mut tracker = QuicConnectionTracker::new();
    tracker.observe_long_header(client, 5_000, server, 443, &[1, 1, 1, 1]);
    tracker.observe_long_header(server, 443, client, 5_000, &server_cid);
    let (id, direction) = tracker
        .connection_and_direction(client, 5_000, server, 443, &server_cid)
        .expect("the connection is known");

    let mut reassembler = QuicStreamReassembler::new();
    // Offset 4 with nothing before it waits behind the gap, so it stays held.
    let held = reassembler.offer_for_connection_at(id, direction, 0, 4, false, b"tail", 100);
    assert!(held.data.is_empty(), "the head has not arrived");
    assert_eq!(reassembler.expire_before(50), 0, "not yet past its date");
    assert_eq!(
        reassembler.expire_before(200),
        1,
        "the dated stream ages out"
    );
}

/// An ARP packet re-emitted from its parsed form has to come back byte for
/// byte, or a rewritten capture would carry a different packet.
#[test]
fn a_parsed_arp_packet_round_trips_to_bytes() {
    use paccel::layer::datalink::arp::{ArpOperation, ArpPacket as ParsedArp};

    let packet = ParsedArp {
        hardware_type: 1,
        protocol_type: 0x0800,
        hardware_len: 6,
        protocol_len: 4,
        operation: ArpOperation::Request,
        sender_hardware_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        sender_protocol_addr: Ipv4Addr::new(10, 0, 0, 1),
        target_hardware_addr: [0; 6],
        target_protocol_addr: Ipv4Addr::new(10, 0, 0, 2),
    };

    let bytes = packet.to_bytes();
    assert_eq!(bytes.len(), 28);
    let read = ArpPacket::new(&bytes).expect("the bytes it just wrote");
    assert_eq!(read.operation(), 1);
    assert_eq!(read.sender_hardware_addr(), packet.sender_hardware_addr);
    assert_eq!(read.sender_protocol_addr(), packet.sender_protocol_addr);
    assert_eq!(read.target_protocol_addr(), packet.target_protocol_addr);
}

/// Each NDP option reader answers only for its own type, so a reader that
/// dropped the type check would hand back another option's bytes.
#[test]
fn an_ndp_option_answers_only_for_its_own_type() {
    use paccel::layer::network::icmpv6::NdpOption;

    let target = NdpOption {
        option_type: 2,
        data: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    };
    assert_eq!(target.target_link_addr(), Some(target.data.as_slice()));
    assert_eq!(target.prefix_information(), None);
    assert_eq!(target.source_link_addr(), None);

    let prefix = NdpOption {
        option_type: 3,
        data: vec![64, 0xc0],
    };
    assert_eq!(prefix.prefix_information(), Some(prefix.data.as_slice()));
    assert_eq!(prefix.target_link_addr(), None);
}
