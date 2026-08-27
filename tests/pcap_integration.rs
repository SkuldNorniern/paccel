#![allow(clippy::cognitive_complexity, clippy::panic)]

use std::{
    iter::repeat_n,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use paccel::engine::{
    BgpMessageType, BuiltinPacketParser, CoapType, Dnp3AppFunctionCode, Dnp3FunctionCode,
    FtpMessage, ImapMessage, KerberosMessageType, LdapProtocolOp, MqttPacketType, NntpMessage,
    OpenVpnOpcode, QuicConnectionTracker, RpcMessage, SipMessage, SmtpMessage, SnmpMessage,
    SnmpPduType, SsdpMessage, TelnetCommand, TftpMessage, TransportSegment, UdpAppHint,
    WireGuardMessageType, iter_capture_frames, parse_capture_frames, parse_pcap_frames,
};
#[cfg(feature = "fingerprint")]
use paccel::fingerprint;
use paccel::layer::application::quic::{
    QuicPacketType, parse_quic_long_header, parse_quic_short_header, split_coalesced_packets,
};

const SYNTHETIC_SOURCE_IP: [u8; 4] = [192, 0, 2, 1];
const SYNTHETIC_SOURCE_IPV6: [u8; 16] =
    [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (chunks, remainder) = data.as_chunks::<2>();
    for &chunk in chunks {
        sum += u32::from(u16::from_be_bytes(chunk));
    }
    if let Some(&byte) = remainder.first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum should fit in 16 bits")
}

fn build_ethernet_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ethertype_or_length: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype_or_length.to_be_bytes());
    frame.extend_from_slice(payload);
    if frame.len() < 60 {
        frame.resize(60, 0);
    }
    frame
}

fn build_ethernet_ipv4_frame(
    dst_ip: [u8; 4],
    ip_protocol: u8,
    ttl: u8,
    ip_payload: &[u8],
) -> Vec<u8> {
    let ip_total_len =
        u16::try_from(20 + ip_payload.len()).expect("payload should fit in an IPv4 packet");
    let mut ip_packet = Vec::with_capacity(usize::from(ip_total_len));
    ip_packet.push(0x45);
    ip_packet.push(0x00);
    ip_packet.extend_from_slice(&ip_total_len.to_be_bytes());
    ip_packet.extend_from_slice(&0x4a3cu16.to_be_bytes());
    ip_packet.extend_from_slice(&0x4000u16.to_be_bytes());
    ip_packet.push(ttl);
    ip_packet.push(ip_protocol);
    ip_packet.extend_from_slice(&[0x00, 0x00]);
    ip_packet.extend_from_slice(&SYNTHETIC_SOURCE_IP);
    ip_packet.extend_from_slice(&dst_ip);
    let checksum = internet_checksum(&ip_packet);
    ip_packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    ip_packet.extend_from_slice(ip_payload);

    let dst_mac = if dst_ip[0] & 0xf0 == 0xe0 {
        [0x01, 0x00, 0x5e, dst_ip[1] & 0x7f, dst_ip[2], dst_ip[3]]
    } else {
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
    };
    build_ethernet_frame(
        dst_mac,
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        0x0800,
        &ip_packet,
    )
}

fn build_ethernet_ipv4_udp_frame(
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> Vec<u8> {
    let udp_len = u16::try_from(8 + udp_payload.len()).expect("UDP payload should fit in a frame");
    let mut udp = Vec::with_capacity(usize::from(udp_len));
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]);
    udp.extend_from_slice(udp_payload);
    build_ethernet_ipv4_frame(dst_ip, 17, 64, &udp)
}

fn build_ethernet_ipv4_tcp_frame(
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_payload: &[u8],
) -> Vec<u8> {
    let tcp_len = u16::try_from(20 + tcp_payload.len()).expect("TCP segment should fit in IPv4");
    let mut tcp = Vec::with_capacity(usize::from(tcp_len));
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&0x1020_3040u32.to_be_bytes());
    tcp.extend_from_slice(&0x5060_7080u32.to_be_bytes());
    tcp.extend_from_slice(&[0x50, 0x18]);
    tcp.extend_from_slice(&0x4000u16.to_be_bytes());
    tcp.extend_from_slice(&[0x00, 0x00]);
    tcp.extend_from_slice(&[0x00, 0x00]);
    tcp.extend_from_slice(tcp_payload);

    let mut pseudo_header = Vec::with_capacity(12 + tcp.len());
    pseudo_header.extend_from_slice(&SYNTHETIC_SOURCE_IP);
    pseudo_header.extend_from_slice(&dst_ip);
    pseudo_header.extend_from_slice(&[0x00, 0x06]);
    pseudo_header.extend_from_slice(&tcp_len.to_be_bytes());
    pseudo_header.extend_from_slice(&tcp);
    let checksum = internet_checksum(&pseudo_header);
    tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

    build_ethernet_ipv4_frame(dst_ip, 6, 64, &tcp)
}

fn build_ethernet_ipv6_udp_frame(
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> Vec<u8> {
    let udp_len = u16::try_from(8 + udp_payload.len()).expect("UDP payload should fit in IPv6");
    let mut udp = Vec::with_capacity(usize::from(udp_len));
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]);
    udp.extend_from_slice(udp_payload);

    let mut pseudo_header = Vec::with_capacity(40 + udp.len());
    pseudo_header.extend_from_slice(&SYNTHETIC_SOURCE_IPV6);
    pseudo_header.extend_from_slice(&dst_ip);
    pseudo_header.extend_from_slice(&u32::from(udp_len).to_be_bytes());
    pseudo_header.extend_from_slice(&[0x00, 0x00, 0x00, 17]);
    pseudo_header.extend_from_slice(&udp);
    let checksum = internet_checksum(&pseudo_header);
    udp[6..8].copy_from_slice(&if checksum == 0 { 0xffff } else { checksum }.to_be_bytes());

    let mut ipv6 = Vec::with_capacity(40 + udp.len());
    ipv6.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
    ipv6.extend_from_slice(&udp_len.to_be_bytes());
    ipv6.extend_from_slice(&[17, 64]);
    ipv6.extend_from_slice(&SYNTHETIC_SOURCE_IPV6);
    ipv6.extend_from_slice(&dst_ip);
    ipv6.extend_from_slice(&udp);
    build_ethernet_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        0x86dd,
        &ipv6,
    )
}

fn build_tls_handshake_record(record_version: u16, handshake_type: u8, body: &[u8]) -> Vec<u8> {
    let handshake_length = u32::try_from(body.len()).expect("TLS handshake should fit in u24");
    assert!(handshake_length <= 0x00ff_ffff);
    let mut handshake = vec![handshake_type];
    handshake.extend_from_slice(&handshake_length.to_be_bytes()[1..]);
    handshake.extend_from_slice(body);

    let record_length = u16::try_from(handshake.len()).expect("TLS handshake should fit in record");
    let mut record = vec![22];
    record.extend_from_slice(&record_version.to_be_bytes());
    record.extend_from_slice(&record_length.to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn build_tls_client_hello(
    record_version: u16,
    cipher_suite: u16,
    server_name: Option<&str>,
    supported_version: Option<u16>,
) -> Vec<u8> {
    let mut hello = Vec::new();
    hello.extend_from_slice(&0x0303u16.to_be_bytes());
    hello.extend(0x40..0x60);
    hello.push(0); // session ID length
    hello.extend_from_slice(&2u16.to_be_bytes());
    hello.extend_from_slice(&cipher_suite.to_be_bytes());
    hello.extend_from_slice(&[1, 0]); // one null compression method

    let mut extensions = Vec::new();
    if let Some(hostname) = server_name {
        let hostname_length = u16::try_from(hostname.len()).expect("hostname should fit in SNI");
        let server_name_list_length = hostname_length
            .checked_add(3)
            .expect("SNI list length should fit in u16");
        let extension_length = server_name_list_length
            .checked_add(2)
            .expect("SNI extension length should fit in u16");
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&extension_length.to_be_bytes());
        extensions.extend_from_slice(&server_name_list_length.to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&hostname_length.to_be_bytes());
        extensions.extend_from_slice(hostname.as_bytes());
    }
    if let Some(version) = supported_version {
        extensions.extend_from_slice(&43u16.to_be_bytes());
        extensions.extend_from_slice(&3u16.to_be_bytes());
        extensions.push(2);
        extensions.extend_from_slice(&version.to_be_bytes());
    }
    let extensions_length =
        u16::try_from(extensions.len()).expect("ClientHello extensions should fit in u16");
    hello.extend_from_slice(&extensions_length.to_be_bytes());
    hello.extend_from_slice(&extensions);
    build_tls_handshake_record(record_version, 1, &hello)
}

fn build_tls_server_hello() -> Vec<u8> {
    let mut extensions = Vec::new();
    for (extension_type, data) in [
        (65281u16, &[0][..]),
        (11, &[1, 0][..]),
        (16, &[0, 2, 1, b'h'][..]),
        (23, &[][..]),
    ] {
        extensions.extend_from_slice(&extension_type.to_be_bytes());
        let extension_length =
            u16::try_from(data.len()).expect("ServerHello extension should fit in u16");
        extensions.extend_from_slice(&extension_length.to_be_bytes());
        extensions.extend_from_slice(data);
    }

    let mut hello = Vec::new();
    hello.extend_from_slice(&0x0303u16.to_be_bytes());
    hello.extend(0x70..0x90);
    hello.push(0); // session ID length
    hello.extend_from_slice(&0xc030u16.to_be_bytes());
    hello.push(0); // null compression method
    let extensions_length =
        u16::try_from(extensions.len()).expect("ServerHello extensions should fit in u16");
    hello.extend_from_slice(&extensions_length.to_be_bytes());
    hello.extend_from_slice(&extensions);
    build_tls_handshake_record(0x0303, 2, &hello)
}

fn push_ssh_name_list(packet: &mut Vec<u8>, algorithms: &str) {
    let length = u32::try_from(algorithms.len()).expect("SSH name-list should fit in u32");
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(algorithms.as_bytes());
}

fn build_ssh_kex_init() -> Vec<u8> {
    let mut payload = vec![20];
    payload.extend(0xa0..0xb0); // cookie
    for algorithms in [
        "diffie-hellman-group14-sha256",
        "rsa-sha2-512",
        "chacha20-poly1305@openssh.com",
        "chacha20-poly1305@openssh.com",
        "hmac-sha2-512",
        "hmac-sha2-512",
        "none",
        "none",
        "",
        "",
    ] {
        push_ssh_name_list(&mut payload, algorithms);
    }
    payload.push(0); // first_kex_packet_follows
    payload.extend_from_slice(&0u32.to_be_bytes());

    let mut padding_length = 4usize;
    while !(4 + 1 + payload.len() + padding_length).is_multiple_of(8) {
        padding_length += 1;
    }
    let packet_length =
        u32::try_from(1 + payload.len() + padding_length).expect("SSH packet should fit in u32");
    let mut packet = Vec::new();
    packet.extend_from_slice(&packet_length.to_be_bytes());
    packet.push(u8::try_from(padding_length).expect("SSH padding length should fit in u8"));
    packet.extend_from_slice(&payload);
    packet.extend(
        (0..padding_length).map(|offset| {
            0xd0 + u8::try_from(offset).expect("SSH padding offset should fit in u8")
        }),
    );
    packet
}

fn build_wireguard_message(message_type: u8, total_length: usize) -> Vec<u8> {
    let mut message = vec![0x5a; total_length];
    message[..4].copy_from_slice(&[message_type, 0, 0, 0]);
    message
}

fn encode_quic_varint(value: u16) -> [u8; 2] {
    assert!(value > 63 && value <= 0x3fff);
    (value | 0x4000).to_be_bytes()
}

fn build_quic_long_header(first_byte: u8, version: u32, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
    let mut packet = vec![first_byte];
    packet.extend_from_slice(&version.to_be_bytes());
    packet.push(u8::try_from(dcid.len()).expect("QUIC DCID length should fit in u8"));
    packet.extend_from_slice(dcid);
    packet.push(u8::try_from(scid.len()).expect("QUIC SCID length should fit in u8"));
    packet.extend_from_slice(scid);
    packet
}

fn build_quic_initial(dcid: &[u8], scid: &[u8], declared_length: u16) -> Vec<u8> {
    let mut packet = build_quic_long_header(0xc0, 1, dcid, scid);
    packet.push(0); // empty token, encoded as a one-byte varint
    packet.extend_from_slice(&encode_quic_varint(declared_length));
    packet.extend(repeat_n(0x5a, usize::from(declared_length)));
    packet
}

fn build_quic_handshake(dcid: &[u8], scid: &[u8], declared_length: u16) -> Vec<u8> {
    let mut packet = build_quic_long_header(0xe0, 1, dcid, scid);
    packet.extend_from_slice(&encode_quic_varint(declared_length));
    packet.extend(repeat_n(0x5a, usize::from(declared_length)));
    packet
}

fn build_quic_retry(dcid: &[u8], scid: &[u8], token: &[u8]) -> Vec<u8> {
    let mut packet = build_quic_long_header(0xf0, 1, dcid, scid);
    packet.extend_from_slice(token);
    packet.extend(0xe0..0xf0); // structurally parsed, not cryptographically validated
    packet
}

fn build_quic_short_header(dcid: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x41]; // short header, spin bit clear, 1-byte PN
    packet.extend_from_slice(dcid);
    packet.push(0x2a); // header-protected PN byte, not decoded structurally
    packet
}

fn build_ber_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let content_len = u8::try_from(content.len()).expect("synthetic BER content should fit in u8");
    assert!(
        content_len < 0x80,
        "synthetic BER content should use a short-form length"
    );
    let mut tlv = vec![tag, content_len];
    tlv.extend_from_slice(content);
    tlv
}

fn build_smb_direct_tcp_message(message: &[u8]) -> Vec<u8> {
    let message_len = u32::try_from(message.len()).expect("SMB message length should fit in u32");
    assert!(
        message_len <= 0x00ff_ffff,
        "SMB message should fit in the direct TCP length field"
    );
    let encoded_len = message_len.to_be_bytes();
    let mut payload = vec![0x00, encoded_len[1], encoded_len[2], encoded_len[3]];
    payload.extend_from_slice(message);
    payload
}

fn build_smb1_negotiate_message(is_response: bool) -> Vec<u8> {
    let mut message = vec![0; 32];
    message[..4].copy_from_slice(&[0xff, b'S', b'M', b'B']);
    message[4] = 0x72;
    message[9] = if is_response { 0x98 } else { 0x18 };
    message[10..12].copy_from_slice(&0x0001u16.to_le_bytes());
    message[12..14].copy_from_slice(&0x0002u16.to_le_bytes());
    message[24..26].copy_from_slice(&0u16.to_le_bytes());
    message[26..28].copy_from_slice(&0x3141u16.to_le_bytes());
    message[28..30].copy_from_slice(&0u16.to_le_bytes());
    message[30..32].copy_from_slice(&0x2718u16.to_le_bytes());
    message.push(0);
    message.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(message.len(), 35);
    build_smb_direct_tcp_message(&message)
}

fn build_smb2_negotiate_message(is_response: bool, message_id: u64) -> Vec<u8> {
    let mut header = vec![0; 64];
    header[..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
    header[4..6].copy_from_slice(&64u16.to_le_bytes());
    header[6..8].copy_from_slice(&1u16.to_le_bytes());
    header[12..14].copy_from_slice(&0u16.to_le_bytes());
    header[14..16].copy_from_slice(&7u16.to_le_bytes());
    if is_response {
        header[16..20].copy_from_slice(&1u32.to_le_bytes());
    } else {
        header[32..36].copy_from_slice(&0x1357_2468u32.to_le_bytes());
    }
    header[24..32].copy_from_slice(&message_id.to_le_bytes());
    header[36..40].copy_from_slice(&0u32.to_le_bytes());
    header[40..48].copy_from_slice(&0u64.to_le_bytes());
    build_smb_direct_tcp_message(&header)
}

fn build_bgp_message(message_type: u8, body: &[u8]) -> Vec<u8> {
    let length =
        u16::try_from(19 + body.len()).expect("BGP message should fit in its length field");
    let mut message = vec![0xff; 16];
    message.extend_from_slice(&length.to_be_bytes());
    message.push(message_type);
    message.extend_from_slice(body);
    message
}

fn dnp3_crc(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa6bc
            };
        }
    }
    !crc
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
fn dnp3_synthetic_frame_four_matches_tshark() {
    let mut dnp3 = vec![0x05, 0x64, 0x0b, 0xc4];
    dnp3.extend_from_slice(&0x1234u16.to_le_bytes());
    dnp3.extend_from_slice(&0x5678u16.to_le_bytes());
    let header_crc = dnp3_crc(&dnp3);
    dnp3.extend_from_slice(&header_crc.to_le_bytes());

    let user_data = [0xc7, 0xc3, 0x01, 30, 1, 0x06];
    dnp3.extend_from_slice(&user_data);
    let data_crc = dnp3_crc(&user_data);
    dnp3.extend_from_slice(&data_crc.to_le_bytes());

    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 20], 41_000, 20_000, &dnp3);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let dnp3 = parsed.dnp3.as_ref().expect("DNP3 should be present");

    assert_eq!(dnp3.link_function, Dnp3FunctionCode::UnconfirmedUserData);
    assert_eq!(dnp3.destination, 0x1234);
    assert_eq!(dnp3.source, 0x5678);
    assert_eq!(
        dnp3.application.map(|application| application.function),
        Some(Dnp3AppFunctionCode::Read)
    );
}

#[test]
fn bgp_synthetic_frame_one_matches_tshark() {
    let keepalive = build_bgp_message(4, &[]);
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 7], 40_000, 179, &keepalive);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let bgp = parsed.bgp.expect("BGP should be present");

    assert_eq!(bgp.message_type, BgpMessageType::Keepalive);
    assert_eq!(bgp.length, 19);
}

#[test]
fn bgp_synthetic_frame_five_is_notification() {
    let notification = build_bgp_message(3, &[2, 1, 0, 3]);
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 7], 40_000, 179, &notification);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let bgp = parsed.bgp.expect("BGP should be present");

    assert_eq!(bgp.message_type, BgpMessageType::Notification);
    assert_eq!(bgp.length, 23);
}

#[test]
fn ospf_synthetic_frame_one_is_hello() {
    let mut hello = vec![2, 1];
    hello.extend_from_slice(&44u16.to_be_bytes());
    hello.extend_from_slice(&[10, 23, 45, 67]);
    hello.extend_from_slice(&[0, 0, 0, 42]);
    hello.extend_from_slice(&[0, 0]);
    hello.extend_from_slice(&0u16.to_be_bytes());
    hello.extend_from_slice(&[0; 8]);
    hello.extend_from_slice(&[255, 255, 255, 0]);
    hello.extend_from_slice(&10u16.to_be_bytes());
    hello.extend_from_slice(&[0x02, 0x03]);
    hello.extend_from_slice(&40u32.to_be_bytes());
    hello.extend_from_slice(&[10, 23, 45, 1]);
    hello.extend_from_slice(&[10, 23, 45, 2]);
    let checksum = internet_checksum(&hello);
    hello[12..14].copy_from_slice(&checksum.to_be_bytes());

    let frame = build_ethernet_ipv4_frame([224, 0, 0, 5], 89, 1, &hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let ospf = parsed.ospf.as_ref().expect("OSPF should be present");

    assert_eq!(ospf.version, 2);
    assert_eq!(ospf.message_type, 1);
    assert_eq!(ospf.packet_length, 44);
    assert_eq!(ospf.router_id, Ipv4Addr::new(10, 23, 45, 67));
    assert_eq!(ospf.area_id, Ipv4Addr::new(0, 0, 0, 42));
}

#[test]
fn lacp_synthetic_frame_one_is_actor_state() {
    let mut lacpdu = vec![1, 1, 1, 20];
    lacpdu.extend_from_slice(&0x7000u16.to_be_bytes());
    lacpdu.extend_from_slice(&[0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01]);
    lacpdu.extend_from_slice(&0x0123u16.to_be_bytes());
    lacpdu.extend_from_slice(&0x6000u16.to_be_bytes());
    lacpdu.extend_from_slice(&27u16.to_be_bytes());
    lacpdu.extend_from_slice(&[0x3d, 0, 0, 0]);
    lacpdu.extend_from_slice(&[2, 20]);
    lacpdu.extend_from_slice(&0x7100u16.to_be_bytes());
    lacpdu.extend_from_slice(&[0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x02]);
    lacpdu.extend_from_slice(&0x0456u16.to_be_bytes());
    lacpdu.extend_from_slice(&0x6100u16.to_be_bytes());
    lacpdu.extend_from_slice(&31u16.to_be_bytes());
    lacpdu.extend_from_slice(&[0x3d, 0, 0, 0]);
    lacpdu.extend_from_slice(&[3, 16]);
    lacpdu.extend_from_slice(&0u16.to_be_bytes());
    lacpdu.extend_from_slice(&[0; 12]);
    lacpdu.extend_from_slice(&[0, 0]);
    lacpdu.extend_from_slice(&[0; 50]);

    let frame = build_ethernet_frame(
        [0x01, 0x80, 0xc2, 0x00, 0x00, 0x02],
        [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01],
        0x8809,
        &lacpdu,
    );
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let ethernet = parsed
        .ethernet
        .as_ref()
        .expect("Ethernet should be present");
    let lacp = parsed.lacp.as_ref().expect("LACP should be present");

    assert_eq!(ethernet.destination, [0x01, 0x80, 0xc2, 0x00, 0x00, 0x02]);
    assert_eq!(ethernet.ethertype, 0x8809);
    assert_eq!(lacp.subtype, 1);
    assert_eq!(lacp.version, 1);
    assert_eq!(lacp.actor_port, 27);
}

#[test]
fn cdp_synthetic_frame_one_has_device_id_header() {
    let mut cdp_payload = vec![2, 77, 0, 0];
    cdp_payload.extend_from_slice(&1u16.to_be_bytes());
    cdp_payload.extend_from_slice(&14u16.to_be_bytes());
    cdp_payload.extend_from_slice(b"paccel-rtr");
    let checksum = internet_checksum(&cdp_payload);
    cdp_payload[2..4].copy_from_slice(&checksum.to_be_bytes());

    let mut llc_snap = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];
    llc_snap.extend_from_slice(&cdp_payload);
    let payload_length = u16::try_from(llc_snap.len()).expect("CDP payload should fit in 802.3");
    let frame = build_ethernet_frame(
        [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc],
        [0x02, 0x00, 0x0c, 0x00, 0x00, 0x2a],
        payload_length,
        &llc_snap,
    );
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let cdp = parsed.cdp.as_ref().expect("CDP should be present");

    assert_eq!(cdp.version, 2);
    assert_eq!(cdp.ttl, 77);
    assert_eq!(cdp.checksum, checksum);
}

#[test]
fn hsrp_synthetic_frame_one_is_hello() {
    let mut hello = vec![0, 0, 8, 3, 10, 135, 37, 0];
    hello.extend_from_slice(b"cisco\0\0\0");
    hello.extend_from_slice(&[198, 51, 100, 254]);
    let frame = build_ethernet_ipv4_udp_frame([224, 0, 0, 2], 1985, 1985, &hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let hsrp = parsed.hsrp.as_ref().expect("HSRP should be present");
    let udp = match parsed.transport.as_ref() {
        Some(TransportSegment::Udp(udp)) => udp,
        Some(TransportSegment::Tcp(_)) | Some(TransportSegment::Sctp(_)) | None => {
            panic!("UDP should be present")
        }
    };

    assert_eq!(udp.destination_port, 1985);
    assert_eq!(hsrp.version, 0);
    assert_eq!(hsrp.opcode, 0);
    assert_eq!(hsrp.state, 8);
    assert_eq!(hsrp.group, 37);
    assert_eq!(hsrp.priority, 135);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Hsrp));
}

#[test]
fn eigrp_synthetic_frame_one_is_hello() {
    let mut hello = vec![2, 5, 0, 0];
    hello.extend_from_slice(&0u32.to_be_bytes());
    hello.extend_from_slice(&0u32.to_be_bytes());
    hello.extend_from_slice(&0u32.to_be_bytes());
    hello.extend_from_slice(&4242u32.to_be_bytes());
    hello.extend_from_slice(&1u16.to_be_bytes());
    hello.extend_from_slice(&12u16.to_be_bytes());
    hello.extend_from_slice(&[1, 0, 1, 0, 0, 0]);
    hello.extend_from_slice(&15u16.to_be_bytes());
    let checksum = internet_checksum(&hello);
    hello[2..4].copy_from_slice(&checksum.to_be_bytes());

    let frame = build_ethernet_ipv4_frame([224, 0, 0, 10], 88, 2, &hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let ipv4 = parsed.ipv4.as_ref().expect("IPv4 should be present");
    let eigrp = parsed.eigrp.as_ref().expect("EIGRP should be present");

    assert_eq!(ipv4.destination, Ipv4Addr::new(224, 0, 0, 10));
    assert_eq!(ipv4.protocol, 88);
    assert_eq!(eigrp.version, 2);
    assert_eq!(eigrp.opcode, 5);
    assert_eq!(eigrp.as_number, 4242);
}

#[test]
fn pim_synthetic_frame_one_is_hello() {
    let mut hello = vec![0x20, 0, 0, 0];
    hello.extend_from_slice(&1u16.to_be_bytes());
    hello.extend_from_slice(&2u16.to_be_bytes());
    hello.extend_from_slice(&105u16.to_be_bytes());
    let checksum = internet_checksum(&hello);
    hello[2..4].copy_from_slice(&checksum.to_be_bytes());

    let frame = build_ethernet_ipv4_frame([224, 0, 0, 13], 103, 1, &hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let pim = parsed.pim.as_ref().expect("PIM should be present");

    assert_eq!(pim.version, 2);
    assert_eq!(pim.message_type, 0);
}

#[test]
fn pim_synthetic_frame_three_is_register() {
    let encapsulated =
        build_ethernet_ipv4_udp_frame([239, 23, 45, 67], 49_000, 49_001, b"multicast-data");
    let mut register = vec![0x21, 0, 0, 0];
    register.extend_from_slice(&0u32.to_be_bytes());
    let checksum = internet_checksum(&register);
    register[2..4].copy_from_slice(&checksum.to_be_bytes());
    register.extend_from_slice(&encapsulated[14..]);

    let frame = build_ethernet_ipv4_frame([198, 51, 100, 99], 103, 64, &register);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let pim = parsed.pim.as_ref().expect("PIM should be present");

    assert_eq!(pim.version, 2);
    assert_eq!(pim.message_type, 1);
}

#[test]
fn vrrp_synthetic_frame_one_is_advertisement() {
    let mut advertisement = vec![0x21, 42, 175, 1, 0, 1, 0, 0];
    advertisement.extend_from_slice(&[192, 0, 2, 254]);
    advertisement.extend_from_slice(&[0; 8]);
    let checksum = internet_checksum(&advertisement);
    advertisement[6..8].copy_from_slice(&checksum.to_be_bytes());

    let frame = build_ethernet_ipv4_frame([224, 0, 0, 18], 112, 255, &advertisement);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let vrrp = parsed.vrrp.as_ref().expect("VRRP should be present");

    assert_eq!(vrrp.version, 2);
    assert_eq!(vrrp.packet_type, 1);
    assert_eq!(vrrp.virtual_router_id, 42);
    assert_eq!(vrrp.priority, 175);
    assert_eq!(vrrp.address_count, 1);
}

#[test]
fn rpc_synthetic_frame_one_is_nfs_getattr_call() {
    let xid = 0x2468_ace0u32;
    let mut call = Vec::new();
    call.extend_from_slice(&xid.to_be_bytes());
    call.extend_from_slice(&0u32.to_be_bytes());
    call.extend_from_slice(&2u32.to_be_bytes());
    call.extend_from_slice(&100_003u32.to_be_bytes());
    call.extend_from_slice(&3u32.to_be_bytes());
    call.extend_from_slice(&1u32.to_be_bytes());
    call.extend_from_slice(&0u32.to_be_bytes());
    call.extend_from_slice(&0u32.to_be_bytes());
    call.extend_from_slice(&0u32.to_be_bytes());
    call.extend_from_slice(&0u32.to_be_bytes());
    call.extend_from_slice(&8u32.to_be_bytes());
    call.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 30], 40_400, 2049, &call);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.rpc,
        Some(RpcMessage::Call {
            xid,
            rpc_version: 2,
            program: 100_003,
            program_version: 3,
            procedure: 1,
        })
    );
    assert!(parsed.udp_hints.contains(&UdpAppHint::Rpc));
}

#[test]
fn rpc_synthetic_frame_two_is_reply() {
    let xid = 0x2468_ace0u32;
    let mut reply = Vec::new();
    reply.extend_from_slice(&xid.to_be_bytes());
    reply.extend_from_slice(&1u32.to_be_bytes());
    reply.extend_from_slice(&0u32.to_be_bytes());
    reply.extend_from_slice(&0u32.to_be_bytes());
    reply.extend_from_slice(&0u32.to_be_bytes());
    reply.extend_from_slice(&0u32.to_be_bytes());
    reply.extend_from_slice(&2u32.to_be_bytes());

    let frame = build_ethernet_ipv4_udp_frame([192, 0, 2, 1], 2049, 40_400, &reply);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(parsed.rpc, Some(RpcMessage::Reply { xid }));
    assert!(parsed.udp_hints.contains(&UdpAppHint::Rpc));
}

#[test]
fn rip_synthetic_frame_one_is_request() {
    let mut request = vec![1, 1, 0, 0];
    request.extend_from_slice(&[0; 16]);
    request.extend_from_slice(&16u32.to_be_bytes());
    let frame = build_ethernet_ipv4_udp_frame([255, 255, 255, 255], 520, 520, &request);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let rip = parsed.rip.as_ref().expect("RIP should be present");

    assert_eq!(rip.command, 1);
    assert_eq!(rip.version, 1);
}

#[test]
fn rip_synthetic_frame_two_is_response() {
    let mut response = vec![2, 1, 0, 0];
    response.extend_from_slice(&2u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&[203, 0, 113, 0]);
    response.extend_from_slice(&[0; 8]);
    response.extend_from_slice(&3u32.to_be_bytes());
    let frame = build_ethernet_ipv4_udp_frame([255, 255, 255, 255], 520, 520, &response);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let rip = parsed.rip.as_ref().expect("RIP should be present");

    assert_eq!(rip.command, 2);
    assert_eq!(rip.version, 1);
}

#[test]
fn ikev2_synthetic_frame_one_is_sa_init_initiator_request() {
    let mut sa_payload = vec![0, 0];
    sa_payload.extend_from_slice(&40u16.to_be_bytes());
    sa_payload.extend_from_slice(&[0, 0]);
    sa_payload.extend_from_slice(&36u16.to_be_bytes());
    sa_payload.extend_from_slice(&[1, 1, 0, 3]);
    sa_payload.extend_from_slice(&[3, 0]);
    sa_payload.extend_from_slice(&12u16.to_be_bytes());
    sa_payload.extend_from_slice(&[1, 0]);
    sa_payload.extend_from_slice(&12u16.to_be_bytes());
    sa_payload.extend_from_slice(&[0x80, 0x0e, 0x00, 0x80]);
    sa_payload.extend_from_slice(&[3, 0]);
    sa_payload.extend_from_slice(&8u16.to_be_bytes());
    sa_payload.extend_from_slice(&[2, 0]);
    sa_payload.extend_from_slice(&5u16.to_be_bytes());
    sa_payload.extend_from_slice(&[0, 0]);
    sa_payload.extend_from_slice(&8u16.to_be_bytes());
    sa_payload.extend_from_slice(&[4, 0]);
    sa_payload.extend_from_slice(&14u16.to_be_bytes());
    assert_eq!(sa_payload.len(), 40);

    let total_length = u32::try_from(28 + sa_payload.len()).expect("IKE message should fit in u32");
    let mut ike = Vec::new();
    ike.extend_from_slice(&0x1020_3040_5060_7080u64.to_be_bytes());
    ike.extend_from_slice(&0u64.to_be_bytes());
    ike.extend_from_slice(&[0x21, 0x20, 0x22, 0x08]);
    ike.extend_from_slice(&0u32.to_be_bytes());
    ike.extend_from_slice(&total_length.to_be_bytes());
    ike.extend_from_slice(&sa_payload);

    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 50], 50_000, 500, &ike);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let isakmp = parsed.isakmp.as_ref().expect("ISAKMP should be present");

    assert_eq!(isakmp.initiator_spi, 0x1020_3040_5060_7080);
    assert_eq!(isakmp.next_payload, 0x21);
    assert_eq!(isakmp.major_version, 2);
    assert_eq!(isakmp.exchange_type, 0x22);
    assert!(isakmp.is_initiator);
    assert!(!isakmp.is_response);
    assert_eq!(isakmp.length, total_length);
}

#[test]
fn quic_multistream_synthetic_frame_one_has_expected_dcid() {
    let dcid = [0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93];
    let quic_packet = build_quic_long_header(0xc0, 0xff00_001d, &dcid, &[]);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 60], 45_000, 443, &quic_packet);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(quic.version, 0xff00_001d);
    assert_eq!(quic.dcid, dcid);
    assert!(!quic.is_initial);
    assert_eq!(quic.kind, QuicPacketType::Unknown);
}

#[test]
fn quic_retry_synthetic_frame_one_is_v1_initial() {
    let dcid = [0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe];
    let scid = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let quic_packet = build_quic_initial(&dcid, &scid, 1232);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 61], 45_001, 443, &quic_packet);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(quic.version, 1);
    assert_eq!(quic.kind, QuicPacketType::Initial);
    assert_eq!(quic.dcid, dcid);
    assert_eq!(quic.token, Some(Vec::new()));
    assert_eq!(quic.length, Some(1232));
}

#[test]
fn quic_retry_synthetic_frame_three_is_retry() {
    let dcid = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];
    let scid = [
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
    ];
    let retry_token = [0xc1, 0xc3, 0xc5, 0xc7, 0xc9, 0xcb, 0xcd, 0xcf];
    let quic_packet = build_quic_retry(&dcid, &scid, &retry_token);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 62], 443, 45_002, &quic_packet);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(quic.kind, QuicPacketType::Retry);
    assert_eq!(quic.scid, scid);
    assert_eq!(quic.retry_token, Some(retry_token.to_vec()));
    assert_eq!(
        quic.retry_integrity_tag,
        Some([
            0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed,
            0xee, 0xef
        ])
    );
}

#[test]
fn quic_fragmented_handshake_synthetic_frame_two_is_retry_shaped() {
    let dcid = [
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21,
    ];
    let scid = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42,
    ];
    let quic_packet = build_quic_retry(&dcid, &scid, &[0x51, 0x52, 0x53]);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 63], 443, 45_003, &quic_packet);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(quic.kind, QuicPacketType::Retry);
    assert_eq!(quic.dcid, dcid);
    assert_eq!(quic.scid, scid);
}

#[test]
fn quic_tls_upgrade_synthetic_frame_forty_seven_is_v1_initial() {
    let dcid = [0xde, 0xad, 0xbe, 0xef, 0x10, 0x20, 0x30, 0x40];
    let scid = [0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28];
    let quic_packet = build_quic_initial(&dcid, &scid, 1188);
    let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let frame = build_ethernet_ipv6_udp_frame(destination, 45_004, 443, &quic_packet);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let ipv6 = parsed.ipv6.as_ref().expect("IPv6 should be present");
    let quic = parsed.quic.as_ref().expect("QUIC should be present");

    assert_eq!(ipv6.destination, Ipv6Addr::from(destination));
    assert_eq!(quic.version, 1);
    assert_eq!(quic.kind, QuicPacketType::Initial);
    assert_eq!(quic.dcid, dcid);
    assert_eq!(quic.token, Some(Vec::new()));
    assert_eq!(quic.length, Some(1188));
}

#[test]
fn quic_tls_upgrade_synthetic_frame_four_tls_sni() {
    let client_hello = build_tls_client_hello(0x0303, 0xcca8, Some("fallback.paccel.test"), None);
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 64], 45_005, 443, &client_hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let tls = parsed.tls.as_ref().expect("TLS should be present");

    assert_eq!(tls.server_name, Some("fallback.paccel.test".to_string()));
}

#[test]
fn tls13_handshake_synthetic_frame_one_is_clienthello() {
    let client_hello = build_tls_client_hello(0x0301, 0x1301, None, Some(0x0304));
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 70], 45_010, 443, &client_hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let tls = parsed.tls.as_ref().expect("TLS should be present");

    assert_eq!(tls.record_version, 0x0301);
    assert_eq!(tls.handshake_version, 0x0303);
    assert_eq!(tls.supported_versions, vec![0x0304]);
}

#[test]
fn tls12_sni_synthetic_frame_one_has_sni() {
    let client_hello = build_tls_client_hello(0x0303, 0xcca8, Some("paccel.example.test"), None);
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 71], 45_011, 443, &client_hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let tls = parsed.tls.as_ref().expect("TLS should be present");

    assert_eq!(tls.server_name, Some("paccel.example.test".to_string()));
}

#[test]
fn tls12_sni_synthetic_frame_two_is_server_hello() {
    let server_hello = build_tls_server_hello();
    let frame = build_ethernet_ipv4_tcp_frame([192, 0, 2, 1], 443, 45_011, &server_hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let server_hello = parsed
        .tls_server_hello
        .as_ref()
        .expect("ServerHello should be present");

    assert_eq!(server_hello.record_version, 0x0303);
    assert_eq!(server_hello.handshake_version, 0x0303);
    assert_eq!(server_hello.cipher_suite, 0xc030);
    assert_eq!(server_hello.extension_types, vec![65281, 11, 16, 23]);
}

#[cfg(feature = "fingerprint")]
#[test]
fn tls12_sni_synthetic_frame_two_has_expected_ja3s() {
    let server_hello = build_tls_server_hello();
    let frame = build_ethernet_ipv4_tcp_frame([192, 0, 2, 1], 443, 45_011, &server_hello);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let server_hello = parsed
        .tls_server_hello
        .as_ref()
        .expect("ServerHello should be present");

    assert_eq!(
        fingerprint::ja3s_string(server_hello),
        "771,49200,65281-11-16-23"
    );
    assert_eq!(
        fingerprint::ja3s_hash(server_hello),
        "6aea764ee67f71caf3dc723118906199"
    );
}

#[test]
fn wireguard_psk_synthetic_frame_one_is_handshake_initiation() {
    let message = build_wireguard_message(1, 148);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 80], 45_020, 51_820, &message);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
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
fn wireguard_ping_tcp_synthetic_frame_one_is_handshake_initiation() {
    let message = build_wireguard_message(1, 148);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 81], 51_821, 45_021, &message);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
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
fn wireguard_ping_tcp_synthetic_frame_three_is_transport_data() {
    let message = build_wireguard_message(4, 32);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 81], 51_821, 45_021, &message);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let wireguard = parsed
        .wireguard
        .as_ref()
        .expect("WireGuard should be present");

    assert_eq!(wireguard.message_type, WireGuardMessageType::TransportData);
}

#[test]
fn coap_synthetic_frame_one_matches_tshark() {
    let payload = [0x42, 0x02, 0x4a, 0x2b, 0xca, 0xfe];
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 40], 45_683, 5683, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let coap = parsed.coap.expect("CoAP should be present");

    assert_eq!(coap.version, 1);
    assert_eq!(coap.message_type, CoapType::Confirmable);
    assert_eq!(coap.code_class, 0);
    assert_eq!(coap.code_detail, 2);
    assert_eq!(coap.message_id, 0x4a2b);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Coap));
}

#[test]
fn ldap_synthetic_frame_four_matches_tshark() {
    let version = build_ber_tlv(0x02, &[0x03]);
    let name = build_ber_tlv(0x04, &[]);
    let simple_authentication = build_ber_tlv(0x80, &[]);
    let mut bind_content = version;
    bind_content.extend_from_slice(&name);
    bind_content.extend_from_slice(&simple_authentication);
    assert_eq!(bind_content.len(), 7);
    let bind_request = build_ber_tlv(0x60, &bind_content);

    let message_id = build_ber_tlv(0x02, &[0x05]);
    let mut message_content = message_id;
    message_content.extend_from_slice(&bind_request);
    assert_eq!(message_content.len(), 12);
    let payload = build_ber_tlv(0x30, &message_content);
    assert_eq!(payload.len(), 14);

    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 41], 43_890, 389, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let ldap = parsed.ldap.expect("LDAP should be present");

    assert_eq!(ldap.message_id, 5);
    assert_eq!(ldap.protocol_op, LdapProtocolOp::BindRequest);
}

#[test]
fn nntp_synthetic_frame_four_matches_tshark() {
    let payload = b"200 Paccel synthetic news service ready\r\n";
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 42], 119, 46_119, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.nntp,
        Some(NntpMessage::Response {
            code: 200,
            text: "Paccel synthetic news service ready".to_string(),
        })
    );
}

#[test]
fn syslog_synthetic_frame_one_has_expected_facility_severity() {
    let payload = b"<187>Aug 25 12:00:00 paccel parser warning";
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 43], 45_514, 514, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let syslog = parsed.syslog.expect("Syslog should be present");

    assert_eq!(syslog.facility, 23);
    assert_eq!(syslog.severity, 3);
    assert!(matches!(
        parsed.transport,
        Some(TransportSegment::Udp(ref udp)) if udp.destination_port == 514
    ));
    assert!(parsed.udp_hints.contains(&UdpAppHint::Syslog));
}

#[test]
fn syslog_synthetic_frame_two_has_expected_facility_severity() {
    let payload = b"<191>Aug 25 12:00:01 paccel parser trace";
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 43], 45_514, 514, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let syslog = parsed.syslog.expect("Syslog should be present");

    assert_eq!(syslog.facility, 23);
    assert_eq!(syslog.severity, 7);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Syslog));
}

#[test]
fn imap_synthetic_frame_four_is_greeting() {
    let payload = b"* OK Aurora IMAP service ready\r\n";
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 44], 143, 41_143, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.imap,
        Some(ImapMessage::Untagged {
            text: "OK Aurora IMAP service ready".to_string(),
        })
    );
}

#[test]
fn ftp_synthetic_frame_six_is_banner_response() {
    let payload = b"220 Polaris file service ready.\r\n";
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 45], 21, 42_021, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.ftp,
        Some(FtpMessage::Response {
            code: 220,
            text: "Polaris file service ready.".to_string(),
        })
    );
}

#[test]
fn ftp_synthetic_frame_seven_is_user_command() {
    let payload = b"USER starlight\r\n";
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 45], 42_021, 21, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.ftp,
        Some(FtpMessage::Command {
            verb: "USER".to_string(),
            args: "starlight".to_string(),
        })
    );
}

#[test]
fn smb1_synthetic_frame_one_is_negotiate_request() {
    let payload = build_smb1_negotiate_message(false);
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 46], 42_445, 445, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let smb1 = parsed.smb1.as_ref().expect("SMB1 should be present");

    assert_eq!(smb1.command, 0x72);
    assert!(!smb1.is_response);
    assert_eq!(smb1.tid, 0);
    assert_eq!(smb1.pid, 0x3141);
    assert_eq!(smb1.uid, 0);
    assert_eq!(smb1.mid, 0x2718);
}

#[test]
fn smb1_synthetic_frame_two_is_negotiate_response() {
    let payload = build_smb1_negotiate_message(true);
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 46], 445, 42_445, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let smb1 = parsed.smb1.as_ref().expect("SMB1 should be present");

    assert_eq!(smb1.command, 0x72);
    assert!(smb1.is_response);
    assert_eq!(smb1.tid, 0);
    assert_eq!(smb1.pid, 0x3141);
    assert_eq!(smb1.uid, 0);
    assert_eq!(smb1.mid, 0x2718);
}

#[test]
fn smb2_synthetic_frame_one_is_negotiate_response() {
    let payload = build_smb2_negotiate_message(true, 0);
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 47], 445, 43_445, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let smb2 = parsed.smb2.as_ref().expect("SMB2 should be present");

    assert_eq!(smb2.command, 0);
    assert!(smb2.is_response);
    assert_eq!(smb2.message_id, 0);
    assert_eq!(smb2.tree_id, 0);
    assert_eq!(smb2.session_id, 0);
}

#[test]
fn smb2_synthetic_frame_two_is_negotiate_request() {
    let payload = build_smb2_negotiate_message(false, 1);
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 47], 43_445, 445, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let smb2 = parsed.smb2.as_ref().expect("SMB2 should be present");

    assert_eq!(smb2.command, 0);
    assert!(!smb2.is_response);
    assert_eq!(smb2.message_id, 1);
    assert_eq!(smb2.tree_id, 0);
    assert_eq!(smb2.session_id, 0);
}

#[test]
fn smtp_synthetic_frame_six_is_banner_response() {
    let payload = b"220 mail.orbit.example ESMTP Paccel relay ready\r\n";
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 48], 25, 42_025, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.smtp,
        Some(SmtpMessage::Response {
            code: 220,
            text: "mail.orbit.example ESMTP Paccel relay ready".to_string(),
        })
    );
}

#[test]
fn smtp_synthetic_frame_seven_is_ehlo_command() {
    let payload = b"EHLO voyager.client.example\r\n";
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 48], 42_025, 25, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.smtp,
        Some(SmtpMessage::Command {
            verb: "EHLO".to_string(),
            args: "voyager.client.example".to_string(),
        })
    );
}

#[test]
fn telnet_synthetic_frame_four_is_do_suppress_go_ahead() {
    let payload = [0xff, 0xfd, 0x03];
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 49], 42_023, 23, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert_eq!(
        parsed.telnet,
        Some(TelnetCommand {
            command: 0xfd,
            option: 0x03,
        })
    );
}

#[test]
fn mqtt_synthetic_frame_one_matches_tshark() {
    let mut connect_body = Vec::new();
    connect_body.extend_from_slice(&4u16.to_be_bytes());
    connect_body.extend_from_slice(b"MQTT");
    connect_body.push(4);
    connect_body.push(0x02);
    connect_body.extend_from_slice(&45u16.to_be_bytes());
    connect_body.extend_from_slice(&13u16.to_be_bytes());
    connect_body.extend_from_slice(b"paccel-client");
    let remaining_length = u8::try_from(connect_body.len())
        .expect("synthetic CONNECT body should use a one-byte remaining length");
    let mut payload = vec![0x10, remaining_length];
    payload.extend_from_slice(&connect_body);

    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 50], 41_883, 1883, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let mqtt = parsed.mqtt.expect("MQTT should be present");

    assert_eq!(mqtt.packet_type, MqttPacketType::Connect);
    assert_eq!(mqtt.remaining_length, u32::from(remaining_length));
    assert_eq!(mqtt.remaining_length, 25);
}

#[test]
fn modbus_synthetic_frame_two_matches_tshark() {
    let payload = [
        0x00, 0x07, 0x00, 0x00, 0x00, 0x06, 0xff, 0x04, 0x12, 0x34, 0x00, 0x03,
    ];
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 51], 45_502, 502, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let modbus = parsed.modbus.expect("Modbus should be present");

    assert_eq!(modbus.transaction_id, 7);
    assert_eq!(modbus.unit_id, 255);
    assert_eq!(modbus.function_code, 4);
    assert!(!modbus.is_exception);
}

#[test]
fn kerberos_udp_synthetic_frame_one_is_as_req() {
    let sequence = build_ber_tlv(0x30, &[]);
    assert_eq!(sequence.len(), 2);
    let payload = build_ber_tlv(0x6a, &sequence);
    assert_eq!(payload, [0x6a, 0x02, 0x30, 0x00]);

    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 52], 42_088, 88, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let kerberos = parsed.kerberos.expect("Kerberos should be present");

    assert_eq!(kerberos.message_type, KerberosMessageType::AsReq);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Kerberos));
}

#[test]
fn kerberos_tcp_synthetic_frame_five_is_tgs_req() {
    let sequence = build_ber_tlv(0x30, &[]);
    assert_eq!(sequence.len(), 2);
    let message = build_ber_tlv(0x6c, &sequence);
    assert_eq!(message, [0x6c, 0x02, 0x30, 0x00]);

    let message_len = u32::try_from(message.len()).expect("Kerberos message length should fit");
    let mut payload = message_len.to_be_bytes().to_vec();
    payload.extend_from_slice(&message);
    assert_eq!(payload.len(), 8);

    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 52], 42_088, 88, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let kerberos = parsed.kerberos.expect("Kerberos should be present");

    assert_eq!(kerberos.message_type, KerberosMessageType::TgsReq);
}

#[test]
fn sip_synthetic_frame_one_matches_tshark() {
    let payload = b"INVITE sip:echo@voice.example SIP/2.0\r\nVia: SIP/2.0/UDP client.example:5060;branch=z9hG4bK-paccel\r\nFrom: <sip:alice@voice.example>;tag=synthetic-a\r\nTo: <sip:echo@voice.example>\r\nCall-ID: synthetic-invite@paccel.test\r\nCSeq: 17 INVITE\r\nContent-Length: 0\r\n\r\n";
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 60], 45_060, 5060, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");

    assert!(matches!(
        parsed.sip,
        Some(SipMessage::Request {
            ref method,
            ref uri,
            ref call_id,
            ..
        }) if method == "INVITE"
            && uri == "sip:echo@voice.example"
            && call_id.as_deref() == Some("synthetic-invite@paccel.test")
    ));
    assert!(parsed.udp_hints.contains(&UdpAppHint::Sip));
}

#[test]
fn rtp_synthetic_frame_six_matches_tshark() {
    let mut payload = vec![0x80, 0x00];
    payload.extend_from_slice(&0x2345u16.to_be_bytes());
    payload.extend_from_slice(&0x1020_3040u32.to_be_bytes());
    payload.extend_from_slice(&0x5566_7788u32.to_be_bytes());
    payload.extend_from_slice(&[0xff, 0x7f, 0x00, 0x80]);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 61], 40_000, 40_002, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let rtp = parsed.rtp.as_ref().expect("RTP should be present");

    assert_eq!(rtp.payload_type, 0);
    assert_eq!(rtp.sequence_number, 0x2345);
    assert_eq!(rtp.timestamp, 0x1020_3040);
    assert_eq!(rtp.ssrc, 0x5566_7788);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Rtp));
}

#[test]
fn rtcp_synthetic_frame_228_is_sender_report() {
    let mut sender_report = vec![0x80, 200];
    sender_report.extend_from_slice(&6u16.to_be_bytes());
    sender_report.extend_from_slice(&0x1020_3040u32.to_be_bytes());
    sender_report.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    sender_report.extend_from_slice(&0x1122_3344u32.to_be_bytes());
    sender_report.extend_from_slice(&21u32.to_be_bytes());
    sender_report.extend_from_slice(&3_360u32.to_be_bytes());
    assert_eq!(sender_report.len(), 28);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 62], 40_001, 40_003, &sender_report);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let rtcp = parsed.rtcp.as_ref().expect("RTCP should be present");

    assert_eq!(rtcp.packet_type, 200);
    assert_eq!(rtcp.version, 2);
    assert_eq!(rtcp.report_count, 0);
    assert_eq!(rtcp.length, 6);
    assert_eq!(rtcp.ssrc, 0x1020_3040);
}

#[test]
fn rtcp_synthetic_frame_230_is_receiver_report() {
    let mut receiver_report = vec![0x80, 201];
    receiver_report.extend_from_slice(&1u16.to_be_bytes());
    receiver_report.extend_from_slice(&0x5060_7080u32.to_be_bytes());
    assert_eq!(receiver_report.len(), 8);
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 62], 40_003, 40_001, &receiver_report);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let rtcp = parsed.rtcp.as_ref().expect("RTCP should be present");

    assert_eq!(rtcp.packet_type, 201);
    assert_eq!(rtcp.report_count, 0);
    assert_eq!(rtcp.length, 1);
    assert_eq!(rtcp.ssrc, 0x5060_7080);
}

#[test]
fn ssh_banner_synthetic_frame_four_parses_openssh_client_banner() {
    let banner = b"SSH-2.0-OpenSSH_9.6\r\n";
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 90], 45_030, 22, banner);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let ssh = parsed.ssh.as_ref().expect("SSH should be present");

    assert_eq!(ssh.protocol_version, "2.0");
    assert_eq!(ssh.software_version, "OpenSSH_9.6");
}

#[test]
fn ssh_banner_synthetic_frame_eight_is_client_kexinit() {
    let kex_init = build_ssh_kex_init();
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 90], 45_030, 22, &kex_init);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let kex = parsed
        .ssh_kex_init
        .as_ref()
        .expect("SSH KEXINIT should be present");

    assert_eq!(
        kex.kex_algorithms,
        vec!["diffie-hellman-group14-sha256".to_string()]
    );
    assert_eq!(
        kex.encryption_algorithms_client_to_server,
        vec!["chacha20-poly1305@openssh.com".to_string()]
    );
    assert_eq!(
        kex.mac_algorithms_client_to_server,
        vec!["hmac-sha2-512".to_string()]
    );
    assert_eq!(
        kex.compression_algorithms_client_to_server,
        vec!["none".to_string()]
    );
}

#[cfg(feature = "fingerprint")]
#[test]
fn ssh_banner_synthetic_frame_eight_has_expected_hassh() {
    let kex_init = build_ssh_kex_init();
    let frame = build_ethernet_ipv4_tcp_frame([198, 51, 100, 90], 45_030, 22, &kex_init);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let kex = parsed
        .ssh_kex_init
        .as_ref()
        .expect("SSH KEXINIT should be present");

    assert_eq!(
        fingerprint::hassh_algorithms_string(kex),
        "diffie-hellman-group14-sha256;chacha20-poly1305@openssh.com;hmac-sha2-512;none"
    );
    assert_eq!(fingerprint::hassh(kex), "eae58349d2944626485ea59f9b00ace0");
}

#[test]
fn openvpn_udp_synthetic_first_five_frames_match_tshark() {
    const CLIENT_SESSION_ID: u64 = 0x1020_3040_5060_7080;
    const SERVER_SESSION_ID: u64 = 0x8877_6655_4433_2211;
    let expected = [
        (
            OpenVpnOpcode::ControlHardResetClientV2,
            7,
            CLIENT_SESSION_ID,
        ),
        (
            OpenVpnOpcode::ControlHardResetServerV2,
            8,
            SERVER_SESSION_ID,
        ),
        (OpenVpnOpcode::AckV1, 5, CLIENT_SESSION_ID),
        (OpenVpnOpcode::ControlV1, 4, CLIENT_SESSION_ID),
        (OpenVpnOpcode::ControlV1, 4, CLIENT_SESSION_ID),
    ];

    for (expected_opcode, opcode, expected_session_id) in expected {
        let mut packet = vec![opcode << 3];
        packet.extend_from_slice(&expected_session_id.to_be_bytes());
        let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 91], 45_031, 1194, &packet);
        let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, expected_opcode);
        assert_eq!(openvpn.session_id, Some(expected_session_id));
        assert!(parsed.udp_hints.contains(&UdpAppHint::OpenVpn));
    }
}

#[test]
fn dhcpv6_synthetic_solicit() {
    let payload = [0x01, 0x22, 0x33, 0x44];
    let dst = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2];
    let frame = build_ethernet_ipv6_udp_frame(dst, 546, 547, &payload);

    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let dhcp6 = parsed.dhcp6.as_ref().expect("dhcpv6 should be present");
    assert_eq!(dhcp6.msg_type, 1);
    assert_eq!(dhcp6.transaction_id, 0x22_3344);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Dhcpv6));
}

#[test]
fn tftp_rrq_synthetic_first_frame_matches_tshark() {
    let payload = b"\0\x01firmware-test.bin\0octet\0";
    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 70], 47_069, 69, payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    assert_eq!(
        parsed.tftp,
        Some(TftpMessage::ReadRequest {
            filename: "firmware-test.bin".to_owned(),
            mode: "octet".to_owned(),
        })
    );
    assert!(parsed.udp_hints.contains(&UdpAppHint::Tftp));
}

#[test]
fn radius_synthetic_frame_one_matches_tshark() {
    let mut payload = vec![1, 42, 0, 0];
    payload.extend_from_slice(&[
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
        0x01,
    ]);
    payload.extend_from_slice(&[1, 6]);
    payload.extend_from_slice(b"nova");
    payload.extend_from_slice(&[4, 6, 198, 51, 100, 44]);
    let radius_length = u16::try_from(payload.len()).expect("RADIUS message should fit in u16");
    payload[2..4].copy_from_slice(&radius_length.to_be_bytes());

    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 71], 41_812, 1812, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    let radius = parsed.radius.as_ref().expect("RADIUS should be present");
    assert_eq!(radius.code, 1);
    assert_eq!(radius.identifier, 42);
    assert_eq!(radius.length, 32);
    assert!(parsed.udp_hints.contains(&UdpAppHint::Radius));
}

#[test]
fn snmp_v3_synthetic_frame_one_matches_tshark() {
    let request_id = build_ber_tlv(0x02, &0x2345u16.to_be_bytes());
    let error_status = build_ber_tlv(0x02, &[0]);
    let error_index = build_ber_tlv(0x02, &[0]);
    let variable_bindings = build_ber_tlv(0x30, &[]);
    let mut get_request_content = request_id;
    get_request_content.extend_from_slice(&error_status);
    get_request_content.extend_from_slice(&error_index);
    get_request_content.extend_from_slice(&variable_bindings);
    assert_eq!(get_request_content.len(), 12);
    let get_request = build_ber_tlv(0xa0, &get_request_content);
    assert_eq!(get_request.len(), 14);

    let engine_id = build_ber_tlv(0x04, &[0x80, 0x00, 0x4f, 0xa1, 0x01]);
    let context_name = build_ber_tlv(0x04, &[]);
    let mut scoped_content = engine_id.clone();
    scoped_content.extend_from_slice(&context_name);
    scoped_content.extend_from_slice(&get_request);
    assert_eq!(scoped_content.len(), 23);
    let scoped_pdu = build_ber_tlv(0x30, &scoped_content);
    assert_eq!(scoped_pdu.len(), 25);

    let engine_boots = build_ber_tlv(0x02, &[7]);
    let engine_time = build_ber_tlv(0x02, &[11]);
    let user_name = build_ber_tlv(0x04, &[]);
    let auth_parameters = build_ber_tlv(0x04, &[]);
    let priv_parameters = build_ber_tlv(0x04, &[]);
    let mut usm_content = engine_id;
    usm_content.extend_from_slice(&engine_boots);
    usm_content.extend_from_slice(&engine_time);
    usm_content.extend_from_slice(&user_name);
    usm_content.extend_from_slice(&auth_parameters);
    usm_content.extend_from_slice(&priv_parameters);
    assert_eq!(usm_content.len(), 19);
    let usm_sequence = build_ber_tlv(0x30, &usm_content);
    assert_eq!(usm_sequence.len(), 21);
    let security_parameters = build_ber_tlv(0x04, &usm_sequence);
    assert_eq!(security_parameters.len(), 23);

    let msg_id = build_ber_tlv(0x02, &0x1234_5678u32.to_be_bytes());
    let msg_max_size = build_ber_tlv(0x02, &[0x00, 0xc3, 0x50]);
    let msg_flags = build_ber_tlv(0x04, &[0x04]);
    let msg_security_model = build_ber_tlv(0x02, &[0x03]);
    let mut global_content = msg_id;
    global_content.extend_from_slice(&msg_max_size);
    global_content.extend_from_slice(&msg_flags);
    global_content.extend_from_slice(&msg_security_model);
    assert_eq!(global_content.len(), 17);
    let global_data = build_ber_tlv(0x30, &global_content);
    assert_eq!(global_data.len(), 19);

    let version = build_ber_tlv(0x02, &[0x03]);
    let mut message_content = version;
    message_content.extend_from_slice(&global_data);
    message_content.extend_from_slice(&security_parameters);
    message_content.extend_from_slice(&scoped_pdu);
    assert_eq!(message_content.len(), 70);
    let payload = build_ber_tlv(0x30, &message_content);
    assert_eq!(payload.len(), 72);

    let frame = build_ethernet_ipv4_udp_frame([198, 51, 100, 72], 45_161, 161, &payload);
    let parsed = BuiltinPacketParser::parse(&frame).expect("packet should parse");
    assert!(matches!(
        parsed.snmp,
        Some(SnmpMessage::V3 {
            msg_id: 0x1234_5678,
            msg_max_size: 50_000,
            msg_flags: 0x04,
            reportable: true,
            encrypted: false,
            authenticated: false,
            msg_security_model: 3,
            pdu_type: Some(SnmpPduType::GetRequest),
            request_id: Some(0x2345),
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
        TransportSegment::Tcp(_) | TransportSegment::Sctp(_) => panic!("expected UDP"),
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
        TransportSegment::Tcp(_) | TransportSegment::Sctp(_) => panic!("expected UDP"),
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
        TransportSegment::Udp(_) | TransportSegment::Sctp(_) => panic!("expected TCP"),
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
fn quic_connection_migration_resolves_via_cid_tracker() {
    let client_dcid = [0xde, 0xad, 0xbe, 0xef, 0x10, 0x20, 0x30, 0x40];
    let client_scid = [0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28];

    let initial_packet = build_quic_initial(&client_dcid, &client_scid, 64);
    let original_frame =
        build_ethernet_ipv4_udp_frame([198, 51, 100, 10], 51_820, 443, &initial_packet);
    let original =
        BuiltinPacketParser::parse(&original_frame).expect("initial packet should parse");
    let ipv4 = original.ipv4.as_ref().expect("IPv4 should be present");
    let quic = original.quic.as_ref().expect("QUIC should be present");
    assert_eq!(quic.scid, client_scid);

    let mut tracker = QuicConnectionTracker::new();
    let server = Ipv4Addr::new(198, 51, 100, 20);
    tracker.observe_long_header(
        IpAddr::V4(ipv4.source),
        51_820,
        IpAddr::V4(server),
        443,
        &quic.scid,
    );

    // Client rebinds to a new source port mid-connection (NAT rebind / migration).
    // The short-header packet it now sends still carries a DCID the server
    // recognizes from the original exchange - `connection_for_dcid` must resolve
    // it back to the connection's last-known endpoints, tuple-independent. The new
    // tuple itself (51_999) is deliberately unused below: resolution must not
    // depend on it.
    let short_header_packet = build_quic_short_header(&client_scid);
    let short_header =
        parse_quic_short_header(&short_header_packet, client_scid.len()).expect("short header");
    assert_eq!(short_header.dcid, client_scid);

    assert_eq!(
        tracker.connection_for_dcid(short_header.dcid),
        Some((IpAddr::V4(ipv4.source), 51_820, IpAddr::V4(server), 443))
    );
}

#[test]
fn quic_coalesced_initial_and_handshake_feed_tracker_consistently() {
    let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let scid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];

    let initial = build_quic_initial(&dcid, &scid, 64);
    let handshake = build_quic_handshake(&dcid, &scid, 64);
    let mut datagram = initial.clone();
    datagram.extend_from_slice(&handshake);

    let packets = split_coalesced_packets(&datagram);
    assert_eq!(packets, vec![initial.as_slice(), handshake.as_slice()]);

    let mut tracker = QuicConnectionTracker::new();
    let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30));
    let server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40));

    for packet in &packets {
        let header = parse_quic_long_header(packet).expect("coalesced packet should parse");
        assert_eq!(header.scid, scid);
        tracker.observe_long_header(client, 55_001, server, 443, &header.scid);
    }

    // Both coalesced packets carry the same SCID - observing it twice must not
    // create duplicate flow/CID-index bookkeeping.
    assert_eq!(
        tracker.connection_for_dcid(&scid),
        Some((client, 55_001, server, 443))
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
