#![allow(clippy::cognitive_complexity, clippy::panic)]

use std::net::Ipv4Addr;

use paccel::engine::{
    BuiltinPacketParser, OpenVpnOpcode, SipMessage, SnmpMessage, SnmpPduType, TftpMessage,
    TransportSegment, UdpAppHint, iter_capture_frames, parse_capture_frames, parse_pcap_frames,
};

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
