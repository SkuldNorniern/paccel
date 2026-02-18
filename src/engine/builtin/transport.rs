use crate::layer::application::dns::{parse_dns_message, DnsMessage};
use crate::layer::network::icmp::IcmpHeader;
use crate::layer::network::icmpv6::Icmpv6Header;
use crate::layer::transport::tcp::{TcpFlags, TcpHeader};
use crate::layer::transport::udp::UdpHeader;
use crate::layer::LayerError;

use super::types::{
    GeneveInfo, GreInfo, IgmpInfo, TcpOptionsParsed, TransportSegment, UdpAppHint, VxlanInfo,
};

#[derive(Debug, Default)]
pub(super) struct TransportParse {
    pub transport: Option<TransportSegment>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
    pub igmp: Option<IgmpInfo>,
    pub tcp_options: Option<TcpOptionsParsed>,
    pub gre: Option<GreInfo>,
    pub vxlan: Option<VxlanInfo>,
    pub geneve: Option<GeneveInfo>,
    pub dns: Option<DnsMessage>,
    pub hints: Vec<UdpAppHint>,
}

pub(super) fn parse_transport(protocol: u8, l4_bytes: &[u8]) -> Result<TransportParse, LayerError> {
    match protocol {
        6 => {
            let tcp = parse_tcp_header(l4_bytes)?;
            let tcp_options = tcp
                .options
                .as_deref()
                .map(parse_tcp_options)
                .unwrap_or_default();
            Ok(TransportParse {
                transport: Some(TransportSegment::Tcp(tcp)),
                icmp: None,
                icmpv6: None,
                igmp: None,
                tcp_options: Some(tcp_options),
                gre: None,
                vxlan: None,
                geneve: None,
                dns: None,
                hints: Vec::new(),
            })
        }
        17 => {
            let udp = parse_udp_header(l4_bytes)?;
            let udp_len = udp.length as usize;
            let app = &l4_bytes[8..udp_len];

            let mut hints = Vec::new();
            let mut dns = None;

            if (udp.source_port == 53 || udp.destination_port == 53) && likely_dns_message(app) {
                hints.push(UdpAppHint::Dns);
                dns = try_parse_dns_message(app);
            }

            if (udp.source_port == 5353 || udp.destination_port == 5353) && likely_dns_message(app)
            {
                push_hint_unique(&mut hints, UdpAppHint::Mdns);
                if dns.is_none() {
                    dns = try_parse_dns_message(app);
                }
            }

            if (udp.source_port == 67
                || udp.destination_port == 67
                || udp.source_port == 68
                || udp.destination_port == 68)
                && likely_dhcp_message(app)
            {
                push_hint_unique(&mut hints, UdpAppHint::Dhcp);
            }

            if (udp.source_port == 123 || udp.destination_port == 123) && likely_ntp_message(app) {
                push_hint_unique(&mut hints, UdpAppHint::Ntp);
            }

            let vxlan =
                if (udp.source_port == 4789 || udp.destination_port == 4789) && app.len() >= 8 {
                    parse_vxlan_minimal(app).ok()
                } else {
                    None
                };

            let geneve =
                if (udp.source_port == 6081 || udp.destination_port == 6081) && app.len() >= 8 {
                    parse_geneve_minimal(app).ok()
                } else {
                    None
                };

            Ok(TransportParse {
                transport: Some(TransportSegment::Udp(udp)),
                icmp: None,
                icmpv6: None,
                igmp: None,
                tcp_options: None,
                gre: None,
                vxlan,
                geneve,
                dns,
                hints,
            })
        }
        1 => {
            let icmp = parse_icmp_minimal(l4_bytes)?;
            let mut p = TransportParse::default();
            p.icmp = Some(icmp);
            Ok(p)
        }
        58 => {
            let icmpv6 = parse_icmpv6_minimal(l4_bytes)?;
            let mut p = TransportParse::default();
            p.icmpv6 = Some(icmpv6);
            Ok(p)
        }
        2 => {
            let igmp = parse_igmp_minimal(l4_bytes)?;
            let mut p = TransportParse::default();
            p.igmp = Some(igmp);
            Ok(p)
        }
        47 => {
            let gre = parse_gre_minimal(l4_bytes)?;
            let mut p = TransportParse::default();
            p.gre = Some(gre);
            Ok(p)
        }
        _ => Ok(TransportParse::default()),
    }
}

fn parse_icmp_minimal(data: &[u8]) -> Result<IcmpHeader, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    Ok(IcmpHeader {
        icmp_type: data[0],
        icmp_code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
    })
}

fn parse_icmpv6_minimal(data: &[u8]) -> Result<Icmpv6Header, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    Ok(Icmpv6Header {
        icmp_type: data[0],
        icmp_code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
    })
}

fn parse_igmp_minimal(data: &[u8]) -> Result<IgmpInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    let msg_type = data[0];
    let group_address = Some(std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]));
    Ok(IgmpInfo {
        msg_type,
        group_address,
    })
}

fn parse_tcp_options(blob: &[u8]) -> TcpOptionsParsed {
    let mut out = TcpOptionsParsed::default();
    let mut i = 0;
    while i + 1 <= blob.len() {
        let kind = blob[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 2 > blob.len() {
            break;
        }
        let len = blob[i + 1] as usize;
        if len < 2 || i + len > blob.len() {
            break;
        }
        match kind {
            2 => {
                if len >= 4 {
                    out.mss = Some(u16::from_be_bytes([blob[i + 2], blob[i + 3]]));
                }
            }
            3 => {
                if len >= 3 {
                    out.window_scale = Some(blob[i + 2]);
                }
            }
            4 => {
                if len >= 2 {
                    out.sack_permitted = true;
                }
            }
            8 => {
                if len >= 10 {
                    out.ts_val = Some(u32::from_be_bytes([
                        blob[i + 2],
                        blob[i + 3],
                        blob[i + 4],
                        blob[i + 5],
                    ]));
                    out.ts_ecr = Some(u32::from_be_bytes([
                        blob[i + 6],
                        blob[i + 7],
                        blob[i + 8],
                        blob[i + 9],
                    ]));
                }
            }
            _ => {}
        }
        i += len;
    }
    out
}

fn parse_gre_minimal(data: &[u8]) -> Result<GreInfo, LayerError> {
    if data.len() < 4 {
        return Err(LayerError::InvalidLength);
    }
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);
    Ok(GreInfo { protocol_type })
}

fn parse_vxlan_minimal(data: &[u8]) -> Result<VxlanInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    let vni = (data[4] as u32) << 16 | (data[5] as u32) << 8 | (data[6] as u32);
    Ok(VxlanInfo { vni })
}

fn parse_geneve_minimal(data: &[u8]) -> Result<GeneveInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    let version = (data[0] >> 6) & 0x03;
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);
    let vni = (data[4] as u32) << 16 | (data[5] as u32) << 8 | (data[6] as u32);
    Ok(GeneveInfo {
        version,
        protocol_type,
        vni,
    })
}

fn parse_tcp_header(l4_bytes: &[u8]) -> Result<TcpHeader, LayerError> {
    if l4_bytes.len() < 20 {
        return Err(LayerError::InvalidLength);
    }

    let source_port = u16::from_be_bytes([l4_bytes[0], l4_bytes[1]]);
    let destination_port = u16::from_be_bytes([l4_bytes[2], l4_bytes[3]]);
    let sequence_number = u32::from_be_bytes([l4_bytes[4], l4_bytes[5], l4_bytes[6], l4_bytes[7]]);
    let acknowledgment_number =
        u32::from_be_bytes([l4_bytes[8], l4_bytes[9], l4_bytes[10], l4_bytes[11]]);

    let data_offset = (l4_bytes[12] >> 4) & 0x0f;
    if data_offset < 5 {
        return Err(LayerError::InvalidHeader);
    }

    let header_length = (data_offset as usize) * 4;
    if l4_bytes.len() < header_length {
        return Err(LayerError::InvalidLength);
    }

    let flags = TcpFlags {
        fin: (l4_bytes[13] & 0x01) != 0,
        syn: (l4_bytes[13] & 0x02) != 0,
        rst: (l4_bytes[13] & 0x04) != 0,
        psh: (l4_bytes[13] & 0x08) != 0,
        ack: (l4_bytes[13] & 0x10) != 0,
        urg: (l4_bytes[13] & 0x20) != 0,
        ece: (l4_bytes[13] & 0x40) != 0,
        cwr: (l4_bytes[13] & 0x80) != 0,
        ns: (l4_bytes[12] & 0x01) != 0,
    };

    let window_size = u16::from_be_bytes([l4_bytes[14], l4_bytes[15]]);
    let checksum = u16::from_be_bytes([l4_bytes[16], l4_bytes[17]]);
    let urgent_pointer = u16::from_be_bytes([l4_bytes[18], l4_bytes[19]]);
    let options = if header_length > 20 {
        Some(l4_bytes[20..header_length].to_vec())
    } else {
        None
    };

    Ok(TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
        options,
    })
}

fn parse_udp_header(l4_bytes: &[u8]) -> Result<UdpHeader, LayerError> {
    if l4_bytes.len() < 8 {
        return Err(LayerError::InvalidLength);
    }

    let source_port = u16::from_be_bytes([l4_bytes[0], l4_bytes[1]]);
    let destination_port = u16::from_be_bytes([l4_bytes[2], l4_bytes[3]]);
    let length = u16::from_be_bytes([l4_bytes[4], l4_bytes[5]]);
    let checksum = u16::from_be_bytes([l4_bytes[6], l4_bytes[7]]);

    if length < 8 {
        return Err(LayerError::InvalidHeader);
    }
    if l4_bytes.len() < length as usize {
        return Err(LayerError::InvalidLength);
    }

    Ok(UdpHeader {
        source_port,
        destination_port,
        length,
        checksum,
    })
}

fn likely_dns_message(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }

    let opcode = (payload[2] >> 3) & 0x0f;
    if opcode > 5 {
        return false;
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);

    qdcount != 0 || ancount != 0 || nscount != 0 || arcount != 0
}

fn try_parse_dns_message(payload: &[u8]) -> Option<DnsMessage> {
    parse_dns_message(payload).ok()
}

fn likely_dhcp_message(payload: &[u8]) -> bool {
    if payload.len() < 240 {
        return false;
    }

    let op = payload[0];
    if op != 1 && op != 2 {
        return false;
    }

    payload[236..240] == [99, 130, 83, 99]
}

fn likely_ntp_message(payload: &[u8]) -> bool {
    if payload.len() < 48 {
        return false;
    }

    let first = payload[0];
    let version = (first >> 3) & 0x07;
    let mode = first & 0x07;

    (1..=4).contains(&version) && (1..=7).contains(&mode)
}

fn push_hint_unique(hints: &mut Vec<UdpAppHint>, hint: UdpAppHint) {
    if !hints.contains(&hint) {
        hints.push(hint);
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::builtin::{
        BuiltinPacketParser, ParseWarningCode, TransportSegment, UdpAppHint,
    };

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
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x12, 0x34,
            0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));
    }

    #[test]
    fn parses_ethernet_vlan_ipv4_udp_dns() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, 0x00, 0x64, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x3d, 0x12, 0x34, 0x40, 0x00, 64, 17, 0x00, 0x00, 192, 168, 1, 1, 8, 8, 8, 8,
            0x30, 0x39, 0x00, 0x35, 0x00, 0x29, 0x00, 0x00, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
        assert!(parsed.dns.is_some());
        assert!(parsed.udp_hints.contains(&UdpAppHint::Dns));
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
        payload[0] = 0x23;

        let frame = build_ethernet_ipv4_udp_frame(123, 123, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Ntp));
    }

    #[test]
    fn detects_mdns_udp_probe() {
        let payload = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let frame = build_ethernet_ipv4_udp_frame(5353, 5353, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Mdns));
        assert!(parsed.dns.is_some());
    }

    #[test]
    fn parses_tcp_options_mss_and_window_scale() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x70, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let opts = parsed.tcp_options.as_ref().expect("tcp_options");
        assert_eq!(opts.mss, Some(1460));
        assert_eq!(opts.window_scale, Some(7));
    }

    #[test]
    fn parses_ipv4_gre() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01,
            0x40, 0x00, 64, 47, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(parsed.gre.is_some());
        assert_eq!(parsed.gre.as_ref().unwrap().protocol_type, 0x0800);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::GreInner)));
    }

    #[test]
    fn gre_minimal_parsed_with_warning() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x24, 0x00, 0x01,
            0x40, 0x00, 64, 47, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.gre.is_some());
        assert_eq!(parsed.gre.as_ref().unwrap().protocol_type, 0x0800);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::GreInner)));
    }

    #[test]
    fn tcp_options_mss_and_window_scale_parsed() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.tcp_options.is_some());
        let opts = parsed.tcp_options.as_ref().unwrap();
        assert_eq!(opts.mss, Some(0x05b4));
        assert_eq!(opts.window_scale, Some(6));
    }

    #[test]
    fn vxlan_minimal_parsed_with_warning() {
        let vxlan_header: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 100, 0];
        let frame = build_ethernet_ipv4_udp_frame(4789, 4789, &vxlan_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.vxlan.is_some());
        assert_eq!(parsed.vxlan.as_ref().unwrap().vni, 100);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::VxlanInner)));
    }

    #[test]
    fn geneve_minimal_parsed_with_warning() {
        let geneve_header: [u8; 8] = [0x00, 0x00, 0x65, 0x58, 0x00, 0x00, 101, 0];
        let frame = build_ethernet_ipv4_udp_frame(6081, 6081, &geneve_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.geneve.is_some());
        assert_eq!(parsed.geneve.as_ref().unwrap().version, 0);
        assert_eq!(parsed.geneve.as_ref().unwrap().protocol_type, 0x6558);
        assert_eq!(parsed.geneve.as_ref().unwrap().vni, 101);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::GeneveInner)));
    }

    #[test]
    fn tcp_options_timestamp_and_sack_permitted() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3a, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x90, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x02, 0x08, 0x0a, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x01,
            0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let opts = parsed.tcp_options.as_ref().expect("tcp_options");
        assert!(opts.sack_permitted);
        assert_eq!(opts.ts_val, Some(0x1111_1111));
        assert_eq!(opts.ts_ecr, Some(0x2222_2222));
    }
}
