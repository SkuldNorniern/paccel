use super::*;

fn build_ethernet_ipv4_udp_frame(src_port: u16, dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + udp_payload.len()) as u16;
    let ip_total_len = (20 + udp_len as usize) as u16;

    let mut frame = Vec::with_capacity(14 + ip_total_len as usize);
    frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
    frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&ip_total_len.to_be_bytes());
    frame.extend_from_slice(&0x1234u16.to_be_bytes());
    frame.extend_from_slice(&0x4000u16.to_be_bytes());
    frame.push(64);
    frame.push(17);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[192, 168, 1, 1]);
    frame.extend_from_slice(&[224, 0, 0, 251]);

    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(udp_payload);

    frame
}

#[test]
fn parses_ethernet_ipv4_tcp_minimal() {
    let frame = vec![
        0, 1, 2, 3, 4, 5, // dst mac
        6, 7, 8, 9, 10, 11, // src mac
        0x08, 0x00, // ethertype ipv4
        0x45, 0x00, 0x00, 0x28, // ipv4 v4 ihl5 total len 40
        0x12, 0x34, 0x40, 0x00, // id/flags
        64, 6, 0x00, 0x00, // ttl/proto/checksum(dummy)
        192, 168, 1, 1, // src ip
        192, 168, 1, 2, // dst ip
        0x00, 0x50, 0x01, 0xbb, // tcp sport/dport
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x02, // ack
        0x50, 0x10, 0x10, 0x00, // data offset/flags/window
        0x00, 0x00, 0x00, 0x00, // checksum/urg
    ];

    let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
    assert!(parsed.ethernet.is_some());
    assert!(parsed.ipv4.is_some());
    assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));
}

#[test]
fn parses_ethernet_vlan_ipv4_udp_dns() {
    let frame = vec![
        0, 1, 2, 3, 4, 5, // dst mac
        6, 7, 8, 9, 10, 11, // src mac
        0x81, 0x00, // vlan ethertype
        0x00, 0x64, // vlan tci
        0x08, 0x00, // inner ethertype ipv4
        0x45, 0x00, 0x00, 0x3d, // ipv4 total len 61
        0x12, 0x34, 0x40, 0x00, // id/flags
        64, 17, 0x00, 0x00, // ttl/proto/checksum(dummy)
        192, 168, 1, 1, // src ip
        8, 8, 8, 8, // dst ip
        0x30, 0x39, 0x00, 0x35, // udp sport/dport=53
        0x00, 0x29, 0x00, 0x00, // udp len/checksum
        0x12, 0x34, 0x01, 0x00, // dns id/flags
        0x00, 0x01, 0x00, 0x00, // qd/an
        0x00, 0x00, 0x00, 0x00, // ns/ar
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
    assert!(parsed.ethernet.is_some());
    assert!(parsed.ipv4.is_some());
    assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    assert!(parsed.dns.is_some());
    assert!(parsed.udp_hints.contains(&UdpAppHint::Dns));
}

#[test]
fn skips_l4_on_ipv6_non_initial_fragment() {
    let frame = vec![
        0, 1, 2, 3, 4, 5, // dst mac
        6, 7, 8, 9, 10, 11, // src mac
        0x86, 0xdd, // ethertype ipv6
        0x60, 0x00, 0x00, 0x00, // version/tc/flow label
        0x00, 0x10, // payload len 16
        44, 64, // next header = fragment, hop limit
        // src
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // dst
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // fragment header (8 bytes)
        17, 0, // next header UDP, reserved
        0x00, 0x09, // frag offset non-zero (1<<3) + M flag
        0x12, 0x34, 0x56, 0x78, // identification
        // partial udp bytes (not enough)
        0x00, 0x35, 0x30, 0x39, 0x00, 0x10, 0x00, 0x00,
    ];

    let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
    assert!(parsed.ipv6.is_some());
    assert!(parsed.transport.is_none());
    assert_eq!(parsed.warnings.len(), 1);
    assert_eq!(
        parsed.warnings[0].code,
        ParseWarningCode::Ipv6NonInitialFragment
    );
}

#[test]
fn detects_dhcp_udp_probe() {
    let mut payload = vec![0u8; 240];
    payload[0] = 1;
    payload[236..240].copy_from_slice(&[99, 130, 83, 99]);

    let frame = build_ethernet_ipv4_udp_frame(68, 67, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
    assert!(parsed.udp_hints.contains(&UdpAppHint::Dhcp));
}

#[test]
fn detects_ntp_udp_probe() {
    let mut payload = vec![0u8; 48];
    payload[0] = 0x23; // LI=0, VN=4, Mode=3

    let frame = build_ethernet_ipv4_udp_frame(123, 123, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
    assert!(parsed.udp_hints.contains(&UdpAppHint::Ntp));
}

#[test]
fn detects_mdns_udp_probe() {
    let payload = vec![
        0x12, 0x34, 0x01, 0x00, // dns id/flags
        0x00, 0x01, 0x00, 0x00, // qd/an
        0x00, 0x00, 0x00, 0x00, // ns/ar
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let frame = build_ethernet_ipv4_udp_frame(5353, 5353, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
    assert!(parsed.udp_hints.contains(&UdpAppHint::Mdns));
    assert!(parsed.dns.is_some());
}
