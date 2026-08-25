#![allow(clippy::cognitive_complexity, clippy::panic)]

use std::net::{Ipv4Addr, Ipv6Addr};

use paccel::engine::{
    BgpMessageType, BuiltinPacketParser, CoapType, Dnp3AppFunctionCode, Dnp3FunctionCode,
    FtpMessage, ImapMessage, KerberosMessageType, LdapProtocolOp, MqttPacketType, NntpMessage,
    OpenVpnOpcode, RpcMessage, SipMessage, SmtpMessage, SnmpMessage, SnmpPduType, SsdpMessage,
    TelnetCommand, TftpMessage, TransportSegment, UdpAppHint, WireGuardMessageType,
    iter_capture_frames, parse_capture_frames, parse_pcap_frames,
};
#[cfg(feature = "fingerprint")]
use paccel::fingerprint;
use paccel::layer::application::quic::QuicPacketType;

fn build_ethernet_ipv4_udp_frame(
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> Vec<u8> {
    let udp_len = u16::try_from(8 + udp_payload.len()).expect("UDP payload should fit in a frame");
    let ip_total_len = 20u16
        .checked_add(udp_len)
        .expect("UDP datagram should fit in an IPv4 packet");

    let mut frame = Vec::with_capacity(14 + ip_total_len as usize);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());

    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&ip_total_len.to_be_bytes());
    frame.extend_from_slice(&0x1234u16.to_be_bytes());
    frame.extend_from_slice(&0x4000u16.to_be_bytes());
    frame.push(64);
    frame.push(17);
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&[192, 0, 2, 1]);
    frame.extend_from_slice(&dst_ip);

    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(udp_payload);

    frame
}

#[test]
fn ssdp_fixture_frame_one_is_msearch_request() {
    let payload = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n";
    let frame = build_ethernet_ipv4_udp_frame([239, 255, 255, 250], 44_222, 1900, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.ssdp,
        Some(SsdpMessage::Request {
            method: "M-SEARCH".to_string(),
            target: "*".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                ("HOST".to_string(), "239.255.255.250:1900".to_string()),
                ("ST".to_string(), "ssdp:all".to_string()),
                ("MAN".to_string(), "\"ssdp:discover\"".to_string()),
                ("MX".to_string(), "2".to_string()),
            ],
        })
    );
    assert!(parsed.udp_hints.contains(&UdpAppHint::Ssdp));
}

#[test]
fn nat_pmp_fixture_frame_two_is_external_address_request() {
    let payload = [0x00, 0x00];
    let frame = build_ethernet_ipv4_udp_frame([192, 0, 2, 2], 61_908, 5351, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let nat_pmp = parsed.nat_pmp.expect("NAT-PMP should be present");

    assert_eq!(nat_pmp.version, 0);
    assert_eq!(nat_pmp.opcode, 0);
    assert!(parsed.udp_hints.contains(&UdpAppHint::NatPmp));
}

#[test]
fn nat_pmp_fixture_frame_three_is_map_udp_request() {
    let payload = [
        0x00, 0x01, 0x00, 0x00, 0xa2, 0xa9, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x20,
    ];
    let frame = build_ethernet_ipv4_udp_frame([192, 0, 2, 2], 61_908, 5351, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let nat_pmp = parsed.nat_pmp.expect("NAT-PMP should be present");

    assert_eq!(nat_pmp.version, 0);
    assert_eq!(nat_pmp.opcode, 1);
    assert!(parsed.udp_hints.contains(&UdpAppHint::NatPmp));
}

#[test]
fn pcp_fixture_frame_four_is_announce_request() {
    let payload = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x02,
    ];
    let frame = build_ethernet_ipv4_udp_frame([192, 0, 2, 2], 61_909, 5351, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let pcp = parsed.pcp.expect("PCP should be present");

    assert_eq!(pcp.version, 2);
    assert!(!pcp.is_response);
    assert_eq!(pcp.opcode, 0);
    assert_eq!(pcp.lifetime, 0);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Pcp));
}

#[test]
fn dnp3_fixture_frame_four_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/dnp3_read.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(3)
        .expect("capture should contain frame 4")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let dnp3 = parsed.dnp3.as_ref().expect("DNP3 should be present");

    assert_eq!(dnp3.link_function, Dnp3FunctionCode::UnconfirmedUserData);
    assert_eq!(dnp3.destination, 3);
    assert_eq!(dnp3.source, 4);
    assert_eq!(
        dnp3.application.map(|application| application.function),
        Some(Dnp3AppFunctionCode::Read)
    );
}

#[test]
fn bgp_fixture_frame_one_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/bgp_shutdown.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let bgp = parsed.bgp.expect("BGP should be present");

    assert_eq!(bgp.message_type, BgpMessageType::Keepalive);
    assert_eq!(bgp.length, 19);
}

#[test]
fn bgp_fixture_frame_five_is_notification() {
    let bytes = include_bytes!("pcaps/protocol-gaps/bgp_shutdown.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(4)
        .expect("capture should contain frame 5")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let bgp = parsed.bgp.expect("BGP should be present");

    assert_eq!(bgp.message_type, BgpMessageType::Notification);
}

#[test]
fn ospf_fixture_frame_one_is_hello() {
    let bytes = include_bytes!("pcaps/protocol-gaps/ospf_hello.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let ospf = parsed.ospf.as_ref().expect("OSPF should be present");

    assert_eq!(ospf.version, 2);
    assert_eq!(ospf.message_type, 1);
    assert_eq!(ospf.packet_length, 44);
    assert_eq!(ospf.router_id, Ipv4Addr::new(192, 168, 170, 8));
    assert_eq!(ospf.area_id, Ipv4Addr::new(0, 0, 0, 1));
}

#[test]
fn lacp_fixture_frame_one_is_actor_state() {
    let bytes = include_bytes!("pcaps/protocol-gaps/lacp.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let ethernet = parsed
        .ethernet
        .as_ref()
        .expect("Ethernet should be present");
    let lacp = parsed.lacp.as_ref().expect("LACP should be present");

    assert_eq!(ethernet.destination, [0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]);
    assert_eq!(ethernet.ethertype, 0x8809);
    assert_eq!(lacp.subtype, 1);
    assert_eq!(lacp.version, 1);
    assert_eq!(lacp.actor_port, 18);
}

#[test]
fn cdp_fixture_frame_one_has_device_id_header() {
    let bytes = include_bytes!("pcaps/protocol-gaps/cdp_device_id.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let cdp = parsed.cdp.as_ref().expect("CDP should be present");

    assert_eq!(cdp.version, 1);
    assert_eq!(cdp.ttl, 180);
    assert_eq!(cdp.checksum, 0xc65e);
}

#[test]
fn hsrp_fixture_frame_one_is_hello() {
    let bytes = include_bytes!("pcaps/protocol-gaps/hsrp_hello.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let hsrp = parsed.hsrp.as_ref().expect("HSRP should be present");
    let udp = match parsed.transport.as_ref() {
        Some(TransportSegment::Udp(udp)) => udp,
        _ => panic!("UDP should be present"),
    };

    assert_eq!(udp.destination_port, 1985);
    assert_eq!(hsrp.version, 0);
    assert_eq!(hsrp.opcode, 0);
    assert_eq!(hsrp.state, 16);
    assert_eq!(hsrp.group, 10);
    assert_eq!(hsrp.priority, 90);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Hsrp));
}

#[test]
fn eigrp_fixture_frame_one_is_hello() {
    let bytes = include_bytes!("pcaps/protocol-gaps/eigrp_hello.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let ipv4 = parsed.ipv4.as_ref().expect("IPv4 should be present");
    let eigrp = parsed.eigrp.as_ref().expect("EIGRP should be present");

    assert_eq!(ipv4.destination, Ipv4Addr::new(224, 0, 0, 10));
    assert_eq!(ipv4.protocol, 88);
    assert_eq!(eigrp.version, 2);
    assert_eq!(eigrp.opcode, 5);
    assert_eq!(eigrp.as_number, 100);
}

#[test]
fn pim_fixture_frame_one_is_hello() {
    let bytes = include_bytes!("pcaps/protocol-gaps/pim_hello_register.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let pim = parsed.pim.as_ref().expect("PIM should be present");

    assert_eq!(pim.version, 2);
    assert_eq!(pim.message_type, 0);
}

#[test]
fn pim_fixture_frame_three_is_register() {
    let bytes = include_bytes!("pcaps/protocol-gaps/pim_hello_register.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(2)
        .expect("capture should contain frame 3")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let pim = parsed.pim.as_ref().expect("PIM should be present");

    assert_eq!(pim.version, 2);
    assert_eq!(pim.message_type, 1);
}

#[test]
fn vrrp_fixture_frame_one_is_advertisement() {
    let bytes = include_bytes!("pcaps/protocol-gaps/vrrp_advertisement.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let ethernet_end = frame
        .data
        .len()
        .checked_sub(4)
        .expect("mPacket frame should include its FCS");
    let ethernet = frame
        .data
        .get(8..ethernet_end)
        .expect("mPacket frame should include a preamble and Ethernet payload");
    let parsed =
        BuiltinPacketParser::parse_with_linktype(ethernet, 1).expect("packet should parse");
    let vrrp = parsed.vrrp.as_ref().expect("VRRP should be present");

    assert_eq!(vrrp.version, 2);
    assert_eq!(vrrp.packet_type, 1);
    assert_eq!(vrrp.virtual_router_id, 1);
    assert_eq!(vrrp.priority, 100);
    assert_eq!(vrrp.address_count, 1);
}

#[test]
fn rpc_fixture_frame_one_is_nfs_getattr_call() {
    let bytes = include_bytes!("pcaps/protocol-gaps/nfs_getattr.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");

    assert_eq!(
        parsed.rpc,
        Some(RpcMessage::Call {
            xid: 0x7b55_8aeb,
            rpc_version: 2,
            program: 100_003,
            program_version: 3,
            procedure: 1,
        })
    );
    assert!(parsed.udp_hints.contains(&UdpAppHint::Rpc));
}

#[test]
fn rpc_fixture_frame_two_is_reply() {
    let bytes = include_bytes!("pcaps/protocol-gaps/nfs_getattr.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");

    assert_eq!(parsed.rpc, Some(RpcMessage::Reply { xid: 0x7b55_8aeb }));
    assert!(parsed.udp_hints.contains(&UdpAppHint::Rpc));
}

#[test]
fn rip_fixture_frame_one_is_request() {
    let bytes = include_bytes!("pcaps/protocol-gaps/rip_v1.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let rip = parsed.rip.as_ref().expect("RIP should be present");

    assert_eq!(rip.command, 1);
    assert_eq!(rip.version, 1);
}

#[test]
fn rip_fixture_frame_two_is_response() {
    let bytes = include_bytes!("pcaps/protocol-gaps/rip_v1.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let rip = parsed.rip.as_ref().expect("RIP should be present");

    assert_eq!(rip.command, 2);
    assert_eq!(rip.version, 1);
}

#[test]
fn ikev2_fixture_frame_one_is_sa_init_initiator_request() {
    let bytes = include_bytes!("pcaps/protocol-gaps/ikev2_sa_init.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let isakmp = parsed.isakmp.as_ref().expect("ISAKMP should be present");

    assert_eq!(isakmp.initiator_spi, 0x5d48_bfee_b7d5_74da);
    assert_eq!(isakmp.next_payload, 0x21);
    assert_eq!(isakmp.major_version, 2);
    assert_eq!(isakmp.exchange_type, 0x22);
    assert!(isakmp.is_initiator);
    assert!(!isakmp.is_response);
    assert_eq!(isakmp.length, 232);
}

#[test]
fn quic_multistream_fixture_frame_one_has_expected_dcid() {
    let bytes = include_bytes!("pcaps/protocol-gaps/quic_multistream.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(quic.version, 0xff00_001d);
    assert_eq!(
        quic.dcid,
        vec![0x2e, 0xe7, 0xfa, 0xb7, 0x09, 0xec, 0x0e, 0x70]
    );
    assert!(!quic.is_initial);
    assert_eq!(quic.kind, QuicPacketType::Unknown);
}

#[test]
fn quic_retry_fixture_frame_one_is_v1_initial() {
    let bytes = include_bytes!("pcaps/protocol-gaps/quic_retry.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(quic.version, 1);
    assert_eq!(quic.kind, QuicPacketType::Initial);
    assert_eq!(
        quic.dcid,
        vec![0xb4, 0xe8, 0x3a, 0x41, 0xa2, 0x57, 0xc1, 0xe7]
    );
    assert_eq!(quic.token, Some(Vec::new()));
    assert_eq!(quic.length, Some(1232));
}

#[test]
fn quic_retry_fixture_frame_three_is_retry() {
    let bytes = include_bytes!("pcaps/protocol-gaps/quic_retry.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(2)
        .expect("capture should contain frame 3")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(quic.kind, QuicPacketType::Retry);
    assert_eq!(
        quic.scid,
        vec![
            0xc0, 0x6a, 0xaa, 0xc2, 0x07, 0xb0, 0xe0, 0x83, 0xec, 0x50, 0x61, 0x19, 0x62, 0x8d,
            0x3b, 0xf9, 0xb1, 0x79, 0x2d, 0x70
        ]
    );
    assert_eq!(
        quic.retry_token,
        Some(vec![
            0x99, 0x90, 0x63, 0x7f, 0xbc, 0xe6, 0x90, 0xa6, 0x09, 0x51, 0xe9, 0xf3, 0x4d, 0x27,
            0x8f, 0x33, 0xe0, 0xaf, 0x2e, 0x8f, 0xb7, 0x8b, 0xf2, 0xf3, 0x00, 0x94, 0x6c, 0x37,
            0xc9, 0x67, 0x70, 0x69, 0x7d, 0x9a, 0xf5, 0x15, 0x01, 0xde, 0xa1, 0x2a, 0x5f, 0x32,
            0x40, 0xc0, 0xb4, 0xff, 0xf3, 0x57, 0x8a, 0xc3, 0x6a, 0x9d, 0x78, 0x09, 0xc8, 0xe7,
            0xce, 0x3a, 0xc9, 0x08, 0xe6, 0x14, 0x95, 0x38, 0x05, 0x0f
        ])
    );
    assert_eq!(
        quic.retry_integrity_tag,
        Some([
            0xea, 0xf1, 0xe8, 0xc6, 0x29, 0x9e, 0xc8, 0x88, 0x1e, 0x1c, 0xb9, 0xf9, 0xaa, 0x6f,
            0xdc, 0x20
        ])
    );
}

#[test]
fn quic_fragmented_handshake_fixture_frame_two_is_retry_shaped() {
    let bytes = include_bytes!("pcaps/protocol-gaps/quic_fragmented_handshake.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(
        quic.dcid,
        vec![
            0x43, 0x94, 0x4e, 0xda, 0x18, 0xbe, 0xb7, 0xe5, 0x48, 0xb3, 0x8d, 0x37, 0x5b, 0xf3,
            0xc2, 0xa3, 0xbc
        ]
    );
    assert_eq!(
        quic.scid,
        vec![
            0x2e, 0x9a, 0x32, 0xed, 0x45, 0xc9, 0x06, 0x6a, 0xd4, 0xf9, 0xac, 0x32, 0xc1, 0xd2,
            0x3c, 0x19, 0xe4, 0x80
        ]
    );
}

#[test]
fn quic_tls_upgrade_fixture_frame_forty_seven_is_v1_initial() {
    let bytes = include_bytes!("pcaps/protocol-gaps/quic_tls_upgrade.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(46)
        .expect("capture should contain frame 47")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let ipv6 = parsed.ipv6.as_ref().expect("IPv6 should be present");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(
        ipv6.destination,
        "2606:4700:10::6816:826".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(quic.version, 1);
    assert_eq!(quic.kind, QuicPacketType::Initial);
    assert_eq!(
        quic.dcid,
        vec![0x20, 0x3f, 0x9e, 0x9f, 0x68, 0x69, 0x82, 0x74]
    );
    assert_eq!(quic.token, Some(Vec::new()));
    assert_eq!(quic.length, Some(1212));
}

#[test]
fn quic_tls_upgrade_fixture_frame_four_tls_sni() {
    let bytes = include_bytes!("pcaps/protocol-gaps/quic_tls_upgrade.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(3)
        .expect("capture should contain frame 4")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let tls = parsed.tls.as_ref().expect("TLS should be present");

    assert_eq!(tls.server_name, Some("cloudflare-quic.com".to_string()));
}

#[test]
fn tls13_handshake_fixture_frame_one_is_clienthello() {
    let bytes = include_bytes!("pcaps/protocol-gaps/tls13_handshake.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let tls = parsed.tls.as_ref().expect("TLS should be present");

    assert_eq!(tls.record_version, 0x0301);
}

#[test]
fn tls12_sni_fixture_frame_one_has_sni() {
    let bytes = include_bytes!("pcaps/protocol-gaps/tls12_sni.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let tls = parsed.tls.as_ref().expect("TLS should be present");

    assert_eq!(tls.server_name, Some("example.com".to_string()));
}

#[test]
fn tls12_sni_fixture_frame_two_is_server_hello() {
    let bytes = include_bytes!("pcaps/protocol-gaps/tls12_sni.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let server_hello = parsed
        .tls_server_hello
        .as_ref()
        .expect("ServerHello should be present");

    assert_eq!(server_hello.record_version, 0x0303);
    assert_eq!(server_hello.handshake_version, 0x0303);
    assert_eq!(server_hello.cipher_suite, 0xc02f);
    assert_eq!(server_hello.extension_types, vec![65281, 0, 11, 16, 23]);
}

#[cfg(feature = "fingerprint")]
#[test]
fn tls12_sni_fixture_frame_two_has_expected_ja3s() {
    let bytes = include_bytes!("pcaps/protocol-gaps/tls12_sni.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let server_hello = parsed
        .tls_server_hello
        .as_ref()
        .expect("ServerHello should be present");

    assert_eq!(
        fingerprint::ja3s_hash(server_hello),
        "5d79edf64e03689ff559a54e9d9487bc"
    );
}

#[test]
fn wireguard_psk_fixture_frame_one_is_handshake_initiation() {
    let bytes = include_bytes!("pcaps/protocol-gaps/wireguard_psk.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let wireguard = parsed
        .wireguard
        .as_ref()
        .expect("WireGuard should be present");

    assert_eq!(
        wireguard.message_type,
        WireGuardMessageType::HandshakeInitiation
    );
}

#[test]
fn wireguard_ping_tcp_fixture_frame_one_is_handshake_initiation() {
    let bytes = include_bytes!("pcaps/protocol-gaps/wireguard_ping_tcp.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let wireguard = parsed
        .wireguard
        .as_ref()
        .expect("WireGuard should be present");

    assert_eq!(
        wireguard.message_type,
        WireGuardMessageType::HandshakeInitiation
    );
}

#[test]
fn wireguard_ping_tcp_fixture_frame_three_is_transport_data() {
    let bytes = include_bytes!("pcaps/protocol-gaps/wireguard_ping_tcp.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(2)
        .expect("capture should contain frame 3")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let wireguard = parsed
        .wireguard
        .as_ref()
        .expect("WireGuard should be present");

    assert_eq!(wireguard.message_type, WireGuardMessageType::TransportData);
}

#[test]
fn coap_fixture_frame_one_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/coap_cbor.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let coap = parsed.coap.expect("CoAP should be present");

    assert_eq!(coap.version, 1);
    assert_eq!(coap.message_type, CoapType::Confirmable);
    assert_eq!(coap.code_class, 0);
    assert_eq!(coap.code_detail, 2);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Coap));
}

#[test]
fn ldap_fixture_frame_four_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/ldap_search.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(3)
        .expect("capture should contain frame 4")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let ldap = parsed.ldap.expect("LDAP should be present");

    assert_eq!(ldap.message_id, 1);
    assert_eq!(ldap.protocol_op, LdapProtocolOp::BindRequest);
}

#[test]
fn nntp_fixture_frame_four_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/nntp.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(3)
        .expect("capture should contain frame 4")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");

    assert!(matches!(
        parsed.nntp,
        Some(NntpMessage::Response { code: 200, .. })
    ));
}

#[test]
fn syslog_fixture_frame_one_has_expected_facility_severity() {
    let bytes = include_bytes!("pcaps/protocol-gaps/syslog_messages.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcapng should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let syslog = parsed.syslog.expect("Syslog should be present");

    assert_eq!(syslog.facility, 23);
    assert_eq!(syslog.severity, 5);
    assert!(matches!(
        parsed.transport,
        Some(TransportSegment::Udp(ref udp)) if udp.destination_port == 514
    ));
    assert!(parsed.udp_hints.contains(&UdpAppHint::Syslog));
}

#[test]
fn syslog_fixture_frame_two_has_expected_facility_severity() {
    let bytes = include_bytes!("pcaps/protocol-gaps/syslog_messages.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcapng should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let syslog = parsed.syslog.expect("Syslog should be present");

    assert_eq!(syslog.facility, 23);
    assert_eq!(syslog.severity, 6);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Syslog));
}

#[test]
fn imap_fixture_frame_four_is_greeting() {
    let bytes = include_bytes!("pcaps/protocol-gaps/imap_banner.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(3)
        .expect("capture should contain frame 4")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");

    assert_eq!(
        parsed.imap,
        Some(ImapMessage::Untagged {
            text: "OK Microsoft Exchange IMAP4rev1 server version 5.5.2650.23 (umr-mail02) ready"
                .to_string(),
        })
    );
}

#[test]
fn ftp_fixture_frame_six_is_banner_response() {
    let bytes = include_bytes!("pcaps/protocol-gaps/ftp_session.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(5)
        .expect("capture should contain frame 6")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let ftp = parsed.inner.as_deref().and_then(|inner| inner.ftp.as_ref());

    assert_eq!(
        ftp,
        Some(&FtpMessage::Response {
            code: 220,
            text: "6bone.informatik.uni-leipzig.de FTP server (NetBSD-ftpd 20041119) ready."
                .to_string(),
        })
    );
}

#[test]
fn ftp_fixture_frame_seven_is_user_command() {
    let bytes = include_bytes!("pcaps/protocol-gaps/ftp_session.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(6)
        .expect("capture should contain frame 7")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let ftp = parsed.inner.as_deref().and_then(|inner| inner.ftp.as_ref());

    assert_eq!(
        ftp,
        Some(&FtpMessage::Command {
            verb: "USER".to_string(),
            args: "anonymous".to_string(),
        })
    );
}

#[test]
fn smb1_fixture_frame_one_is_negotiate_request() {
    let bytes = include_bytes!("pcaps/protocol-gaps/smb1_negotiate.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let smb1 = parsed.smb1.as_ref().expect("SMB1 should be present");

    assert_eq!(smb1.command, 0x72);
    assert!(!smb1.is_response);
    assert_eq!(smb1.tid, 0);
    assert_eq!(smb1.pid, 0);
    assert_eq!(smb1.uid, 0);
    assert_eq!(smb1.mid, 1);
}

#[test]
fn smb1_fixture_frame_two_is_negotiate_response() {
    let bytes = include_bytes!("pcaps/protocol-gaps/smb1_negotiate.cap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let smb1 = parsed.smb1.as_ref().expect("SMB1 should be present");

    assert_eq!(smb1.command, 0x72);
    assert!(smb1.is_response);
    assert_eq!(smb1.tid, 0);
    assert_eq!(smb1.pid, 0);
    assert_eq!(smb1.uid, 0);
    assert_eq!(smb1.mid, 1);
}

#[test]
fn smb2_fixture_frame_one_is_negotiate_response() {
    let bytes = include_bytes!("pcaps/protocol-gaps/smb2_negotiate.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let smb2 = parsed.smb2.as_ref().expect("SMB2 should be present");

    assert_eq!(smb2.command, 0);
    assert!(smb2.is_response);
    assert_eq!(smb2.message_id, 0);
    assert_eq!(smb2.tree_id, 0);
    assert_eq!(smb2.session_id, 0);
}

#[test]
fn smb2_fixture_frame_two_is_negotiate_request() {
    let bytes = include_bytes!("pcaps/protocol-gaps/smb2_negotiate.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let smb2 = parsed.smb2.as_ref().expect("SMB2 should be present");

    assert_eq!(smb2.command, 0);
    assert!(!smb2.is_response);
    assert_eq!(smb2.message_id, 1);
    assert_eq!(smb2.tree_id, 0);
    assert_eq!(smb2.session_id, 0);
}

#[test]
fn smtp_fixture_frame_six_is_banner_response() {
    let bytes = include_bytes!("pcaps/protocol-gaps/smtp_session.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(5)
        .expect("capture should contain frame 6")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");

    assert_eq!(
        parsed.smtp,
        Some(SmtpMessage::Response {
            code: 220,
            text: "xc90.websitewelcome.com ESMTP Exim 4.69 #1 Mon, 05 Oct 2009 01:05:54 -0500 "
                .to_string(),
        })
    );
}

#[test]
fn smtp_fixture_frame_seven_is_ehlo_command() {
    let bytes = include_bytes!("pcaps/protocol-gaps/smtp_session.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(6)
        .expect("capture should contain frame 7")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");

    assert_eq!(
        parsed.smtp,
        Some(SmtpMessage::Command {
            verb: "EHLO".to_string(),
            args: "GP".to_string(),
        })
    );
}

#[test]
fn telnet_fixture_frame_four_is_do_suppress_go_ahead() {
    let bytes = include_bytes!("pcaps/protocol-gaps/telnet_iac.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(3)
        .expect("capture should contain frame 4")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");

    assert_eq!(
        parsed.telnet,
        Some(TelnetCommand {
            command: 0xfd,
            option: 0x03,
        })
    );
}

#[test]
fn mqtt_fixture_frame_one_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/mqtt.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let mqtt = parsed.mqtt.expect("MQTT should be present");

    assert_eq!(mqtt.packet_type, MqttPacketType::Connect);
    assert_eq!(mqtt.remaining_length, 37);
}

#[test]
fn modbus_fixture_frame_two_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/modbus.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let modbus = parsed.modbus.expect("Modbus should be present");

    assert_eq!(modbus.transaction_id, 0);
    assert_eq!(modbus.unit_id, 255);
    assert_eq!(modbus.function_code, 4);
    assert!(!modbus.is_exception);
}

#[test]
fn kerberos_udp_fixture_frame_one_is_as_req() {
    let bytes = include_bytes!("pcaps/protocol-gaps/kerberos.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let kerberos = parsed.kerberos.expect("Kerberos should be present");

    assert_eq!(kerberos.message_type, KerberosMessageType::AsReq);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Kerberos));
}

#[test]
fn kerberos_tcp_fixture_frame_five_is_tgs_req() {
    let bytes = include_bytes!("pcaps/protocol-gaps/kerberos.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(4)
        .expect("capture should contain frame 5")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let kerberos = parsed.kerberos.expect("Kerberos should be present");

    assert_eq!(kerberos.message_type, KerberosMessageType::TgsReq);
}

#[test]
fn sip_fixture_frame_one_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/sip-rtp-g711.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");

    assert!(matches!(
        parsed.sip,
        Some(SipMessage::Request { ref method, .. }) if method == "INVITE"
    ));
    assert!(parsed.udp_hints.contains(&UdpAppHint::Sip));
}

#[test]
fn rtp_fixture_frame_six_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/sip-rtp-g711.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(5)
        .expect("capture should contain frame 6")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let rtp = parsed.rtp.as_ref().expect("RTP should be present");

    assert_eq!(rtp.payload_type, 0);
    assert_eq!(rtp.sequence_number, 37_595);
    assert_eq!(rtp.timestamp, 160);
    assert_eq!(rtp.ssrc, 0x343d_a99b);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Rtp));
}

#[test]
fn rtcp_fixture_frame_228_is_sender_report() {
    let bytes = include_bytes!("pcaps/protocol-gaps/rtcp_sr_rr.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(227)
        .expect("capture should contain frame 228")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let rtcp = parsed.rtcp.as_ref().expect("RTCP should be present");

    assert_eq!(rtcp.packet_type, 200);
    assert_eq!(rtcp.version, 2);
    assert_eq!(rtcp.ssrc, 0x5d93_1534);
}

#[test]
fn rtcp_fixture_frame_230_is_receiver_report() {
    let bytes = include_bytes!("pcaps/protocol-gaps/rtcp_sr_rr.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(229)
        .expect("capture should contain frame 230")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let rtcp = parsed.rtcp.as_ref().expect("RTCP should be present");

    assert_eq!(rtcp.packet_type, 201);
    assert_eq!(rtcp.ssrc, 0x0193_2db4);
}

#[test]
fn ssh_banner_fixture_frame_four_parses_openssh_client_banner() {
    let bytes = include_bytes!("pcaps/protocol-gaps/ssh_banner.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcapng should parse")
        .nth(3)
        .expect("capture should contain frame 4")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let ssh = parsed.ssh.as_ref().expect("SSH should be present");

    assert_eq!(ssh.protocol_version, "2.0");
    assert_eq!(ssh.software_version, "OpenSSH_7.6p1");
}

#[test]
fn ssh_banner_fixture_frame_eight_is_client_kexinit() {
    let bytes = include_bytes!("pcaps/protocol-gaps/ssh_banner.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcapng should parse")
        .nth(7)
        .expect("capture should contain frame 8")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let kex = parsed
        .ssh_kex_init
        .as_ref()
        .expect("SSH KEXINIT should be present");

    assert_eq!(
        kex.kex_algorithms,
        vec!["curve25519-sha256".to_string(), "ext-info-c".to_string()]
    );
    assert_eq!(
        kex.encryption_algorithms_client_to_server,
        vec!["aes128-gcm@openssh.com".to_string()]
    );
    assert_eq!(
        kex.mac_algorithms_client_to_server,
        vec!["hmac-sha2-256".to_string()]
    );
}

#[cfg(feature = "fingerprint")]
#[test]
fn ssh_banner_fixture_frame_eight_has_expected_hassh() {
    let bytes = include_bytes!("pcaps/protocol-gaps/ssh_banner.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcapng should parse")
        .nth(7)
        .expect("capture should contain frame 8")
        .expect("capture frame should parse");
    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let kex = parsed
        .ssh_kex_init
        .as_ref()
        .expect("SSH KEXINIT should be present");

    assert_eq!(fingerprint::hassh(kex), "bf34b97113a976f3eb1a7f7f86ad9d3a");
}

#[test]
fn openvpn_udp_fixture_first_five_frames_match_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/openvpn_udp_tls-auth.pcapng");
    let mut frames = iter_capture_frames(bytes).expect("pcapng should parse");
    let expected = [
        (
            OpenVpnOpcode::ControlHardResetClientV2,
            0x8138_1462_1d67_462d,
        ),
        (
            OpenVpnOpcode::ControlHardResetServerV2,
            0x5737_14a9_17f3_6048,
        ),
        (OpenVpnOpcode::AckV1, 0x8138_1462_1d67_462d),
        (OpenVpnOpcode::ControlV1, 0x8138_1462_1d67_462d),
        (OpenVpnOpcode::ControlV1, 0x8138_1462_1d67_462d),
    ];

    for (expected_opcode, expected_session_id) in expected {
        let frame = frames
            .next()
            .expect("capture should contain five frames")
            .expect("capture frame should parse");
        let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
            .expect("packet should parse");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, expected_opcode);
        assert_eq!(openvpn.session_id, Some(expected_session_id));
        assert!(parsed.udp_hints.contains(&UdpAppHint::OpenVpn));
    }
}

#[test]
fn dhcpv6_fixture_solicit_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/dhcpv6.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .nth(1)
        .expect("capture should contain frame 2")
        .expect("capture frame should parse");

    let parsed = BuiltinPacketParser::parse(frame.data).expect("packet should parse");
    let dhcp6 = parsed.dhcp6.as_ref().expect("dhcpv6 should be present");
    assert_eq!(dhcp6.msg_type, 1);
    assert_eq!(dhcp6.transaction_id, 0x10_0874);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Dhcpv6));
}

#[test]
fn tftp_rrq_fixture_first_frame_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/tftp_rrq.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");

    let parsed = BuiltinPacketParser::parse(frame.data).expect("packet should parse");
    assert_eq!(
        parsed.tftp,
        Some(TftpMessage::ReadRequest {
            filename: "rfc1350.txt".to_owned(),
            mode: "octet".to_owned(),
        })
    );
    assert!(parsed.udp_hints.contains(&UdpAppHint::Tftp));
}

#[test]
fn radius_fixture_frame_one_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/radius_localhost.pcapng");
    let frame = iter_capture_frames(bytes)
        .expect("pcapng should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");

    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    let radius = parsed.radius.as_ref().expect("RADIUS should be present");
    assert_eq!(radius.code, 1);
    assert_eq!(radius.identifier, 103);
    assert_eq!(radius.length, 87);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Radius));
}

#[test]
fn snmp_v3_fixture_frame_one_matches_tshark() {
    let bytes = include_bytes!("pcaps/protocol-gaps/snmp_usm.pcap");
    let frame = iter_capture_frames(bytes)
        .expect("pcap should parse")
        .next()
        .expect("capture should contain frame 1")
        .expect("capture frame should parse");

    let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
        .expect("packet should parse");
    assert!(matches!(
        parsed.snmp,
        Some(SnmpMessage::V3 {
            msg_id: 821_490_644,
            msg_max_size: 65_507,
            msg_flags: 0x04,
            reportable: true,
            encrypted: false,
            authenticated: false,
            msg_security_model: 3,
            pdu_type: Some(SnmpPduType::GetRequest),
            request_id: Some(2_098_071_598),
        })
    ));
    assert!(parsed.udp_hints.contains(&UdpAppHint::Snmp));
}

// ── DNS query ──────────────────────────────────────────────────────────────

#[test]
fn dns_query_pcap_has_one_frame() {
    let bytes = include_bytes!("pcaps/happy-path/dns_udp_ipv4.pcap");
    let frames = parse_pcap_frames(bytes).expect("pcap should parse");
    assert_eq!(frames.len(), 1);
    assert!(!frames[0].data.is_empty());
    assert_eq!(frames[0].linktype, 1);
}

#[test]
fn dns_query_frame_parses_ethernet_ipv4_udp_dns() {
    let bytes = include_bytes!("pcaps/happy-path/dns_udp_ipv4.pcap");
    let frames = parse_pcap_frames(bytes).expect("pcap should parse");
    let data = frames[0].data;

    let parsed = BuiltinPacketParser::parse(data).expect("frame should parse");
    assert!(parsed.ethernet.is_some(), "ethernet should be present");

    let ipv4 = parsed.ipv4.as_ref().expect("ipv4 should be present");
    assert_eq!(
        ipv4.source,
        "192.168.1.1".parse::<Ipv4Addr>().expect("valid ip")
    );
    assert_eq!(
        ipv4.destination,
        "8.8.8.8".parse::<Ipv4Addr>().expect("valid ip")
    );
    assert_eq!(ipv4.protocol, 17); // UDP

    let udp = match parsed.transport.as_ref().expect("transport") {
        TransportSegment::Udp(u) => u,
        TransportSegment::Tcp(_) => panic!("expected UDP"),
    };
    assert_eq!(udp.destination_port, 53);
    assert_eq!(udp.source_port, 12345);

    let dns = parsed.dns.as_ref().expect("dns should be present");
    assert_eq!(dns.header.transaction_id, 0x1234);
    assert_eq!(dns.header.questions, 1);
    assert_eq!(dns.header.answers, 0);
    assert_eq!(dns.questions.len(), 1);
    assert_eq!(dns.questions[0].qname, "www.example.com");
    assert_eq!(dns.questions[0].qtype, 1); // A record
    assert_eq!(dns.questions[0].qclass, 1); // IN

    assert!(parsed.udp_hints.contains(&UdpAppHint::Dns));
}

// ── DNS response ───────────────────────────────────────────────────────────

#[test]
fn dns_response_frame_parses_correctly() {
    let bytes = include_bytes!("pcaps/happy-path/dns_response_ipv4.pcap");
    let frames = parse_pcap_frames(bytes).expect("pcap should parse");
    assert_eq!(frames.len(), 1);

    let parsed = BuiltinPacketParser::parse(frames[0].data).expect("frame should parse");

    let ipv4 = parsed.ipv4.as_ref().expect("ipv4");
    assert_eq!(
        ipv4.source,
        "8.8.8.8".parse::<Ipv4Addr>().expect("valid ip")
    );
    assert_eq!(
        ipv4.destination,
        "192.168.1.1".parse::<Ipv4Addr>().expect("valid ip")
    );

    let udp = match parsed.transport.as_ref().expect("transport") {
        TransportSegment::Udp(u) => u,
        TransportSegment::Tcp(_) => panic!("expected UDP"),
    };
    assert_eq!(udp.source_port, 53);
    assert_eq!(udp.destination_port, 12345);

    let dns = parsed.dns.as_ref().expect("dns");
    assert_eq!(dns.header.transaction_id, 0x1234);
    assert_eq!(dns.header.questions, 1);
    assert_eq!(dns.header.answers, 1);

    assert!(parsed.udp_hints.contains(&UdpAppHint::Dns));
}

// ── TCP SYN ────────────────────────────────────────────────────────────────

#[test]
fn tcp_syn_pcap_parses_correctly() {
    let bytes = include_bytes!("pcaps/happy-path/tcp_syn_ipv4.pcap");
    let frames = parse_pcap_frames(bytes).expect("pcap should parse");
    assert_eq!(frames.len(), 1);

    let parsed = BuiltinPacketParser::parse(frames[0].data).expect("frame should parse");

    let ipv4 = parsed.ipv4.as_ref().expect("ipv4");
    assert_eq!(
        ipv4.source,
        "10.0.0.1".parse::<Ipv4Addr>().expect("valid ip")
    );
    assert_eq!(
        ipv4.destination,
        "10.0.0.2".parse::<Ipv4Addr>().expect("valid ip")
    );
    assert_eq!(ipv4.protocol, 6); // TCP

    let tcp = match parsed.transport.as_ref().expect("transport") {
        TransportSegment::Tcp(t) => t,
        TransportSegment::Udp(_) => panic!("expected TCP"),
    };
    assert_eq!(tcp.destination_port, 80);
    assert_eq!(tcp.source_port, 54321);
    assert_eq!(tcp.sequence_number, 0xDEAD_BEEF);
    assert!(tcp.flags.syn, "SYN flag should be set");
    assert!(!tcp.flags.ack, "ACK flag should not be set");

    let opts = parsed.tcp_options.as_ref().expect("tcp options");
    assert_eq!(opts.mss, Some(1460));
    assert_eq!(opts.window_scale, Some(7));
    assert!(opts.sack_permitted);
    assert!(opts.ts_val.is_some());
}

// ── ARP ───────────────────────────────────────────────────────────────────

#[test]
fn arp_request_pcap_parses_correctly() {
    let bytes = include_bytes!("pcaps/happy-path/arp_request.pcap");
    let frames = parse_pcap_frames(bytes).expect("pcap should parse");
    assert_eq!(frames.len(), 1);

    let parsed = BuiltinPacketParser::parse(frames[0].data).expect("frame should parse");
    let _arp = parsed.arp.as_ref().expect("arp should be present"); // ARP was parsed
    assert!(parsed.ipv4.is_none(), "no IPv4 in ARP frame");
}

// ── ICMP ──────────────────────────────────────────────────────────────────

#[test]
fn icmp_echo_pcap_parses_correctly() {
    let bytes = include_bytes!("pcaps/happy-path/icmp_echo_ipv4.pcap");
    let frames = parse_pcap_frames(bytes).expect("pcap should parse");
    assert_eq!(frames.len(), 1);

    let parsed = BuiltinPacketParser::parse(frames[0].data).expect("frame should parse");

    let ipv4 = parsed.ipv4.as_ref().expect("ipv4");
    assert_eq!(ipv4.protocol, 1); // ICMP

    let icmp = parsed.icmp.as_ref().expect("icmp");
    assert_eq!(icmp.icmp_type, 8); // Echo Request
    assert_eq!(icmp.icmp_code, 0);
}

// ── Multi-frame pcap ──────────────────────────────────────────────────────

#[test]
fn multi_frame_pcap_yields_three_frames() {
    let bytes = include_bytes!("pcaps/happy-path/multi_frame.pcap");
    let frames = parse_pcap_frames(bytes).expect("pcap should parse");
    assert_eq!(frames.len(), 3);

    // frame 0: DNS query
    let p0 = BuiltinPacketParser::parse(frames[0].data).expect("frame 0");
    assert!(p0.dns.is_some());

    // frame 1: DNS response
    let p1 = BuiltinPacketParser::parse(frames[1].data).expect("frame 1");
    let dns1 = p1.dns.as_ref().expect("dns in frame 1");
    assert_eq!(dns1.header.answers, 1);

    // frame 2: TCP SYN
    let p2 = BuiltinPacketParser::parse(frames[2].data).expect("frame 2");
    assert!(matches!(p2.transport, Some(TransportSegment::Tcp(_))));
}

#[test]
fn multi_frame_iter_yields_same_count() {
    let bytes = include_bytes!("pcaps/happy-path/multi_frame.pcap");
    let count = iter_capture_frames(bytes)
        .expect("iter init")
        .filter_map(|r| r.ok())
        .count();
    assert_eq!(count, 3);
}

// ── pcapng ────────────────────────────────────────────────────────────────

#[test]
fn dns_query_pcapng_has_one_frame() {
    let bytes = include_bytes!("pcaps/happy-path/dns_udp_ipv4.pcapng");
    let frames = parse_capture_frames(bytes).expect("pcapng should parse");
    assert_eq!(frames.len(), 1);
}

#[test]
fn dns_query_pcapng_frame_matches_pcap_frame() {
    let pcap_bytes = include_bytes!("pcaps/happy-path/dns_udp_ipv4.pcap");
    let pcapng_bytes = include_bytes!("pcaps/happy-path/dns_udp_ipv4.pcapng");

    let pcap_frames = parse_pcap_frames(pcap_bytes).expect("pcap should parse");
    let pcapng_frames = parse_capture_frames(pcapng_bytes).expect("pcapng should parse");

    assert_eq!(
        pcap_frames[0].data, pcapng_frames[0].data,
        "pcap and pcapng should contain identical frame bytes"
    );
}

#[test]
fn dns_query_pcapng_parses_with_builtin_parser() {
    let bytes = include_bytes!("pcaps/happy-path/dns_udp_ipv4.pcapng");
    let frames = parse_capture_frames(bytes).expect("pcapng should parse");

    let parsed = BuiltinPacketParser::parse(frames[0].data).expect("frame should parse");
    assert!(parsed.dns.is_some());
    let dns = parsed.dns.as_ref().expect("dns");
    assert_eq!(dns.header.transaction_id, 0x1234);
    assert_eq!(dns.questions[0].qname, "www.example.com");
}
