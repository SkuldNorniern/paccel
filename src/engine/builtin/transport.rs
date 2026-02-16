use crate::layer::application::dns::{parse_dns_message, DnsMessage};
use crate::layer::network::icmp::IcmpHeader;
use crate::layer::network::icmpv6::Icmpv6Header;
use crate::layer::transport::tcp::{TcpFlags, TcpHeader};
use crate::layer::transport::udp::UdpHeader;
use crate::layer::LayerError;

use super::types::{GreInfo, IgmpInfo, TcpOptionsParsed, TransportSegment, UdpAppHint};

#[derive(Debug, Default)]
pub(super) struct TransportParse {
    pub transport: Option<TransportSegment>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
    pub igmp: Option<IgmpInfo>,
    pub tcp_options: Option<TcpOptionsParsed>,
    pub gre: Option<GreInfo>,
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

            Ok(TransportParse {
                transport: Some(TransportSegment::Udp(udp)),
                icmp: None,
                icmpv6: None,
                igmp: None,
                tcp_options: None,
                gre: None,
                dns,
                hints,
            })
        }
        1 => {
            let icmp = parse_icmp_minimal(l4_bytes)?;
            Ok(TransportParse {
                transport: None,
                icmp: Some(icmp),
                icmpv6: None,
                igmp: None,
                tcp_options: None,
                gre: None,
                dns: None,
                hints: Vec::new(),
            })
        }
        58 => {
            let icmpv6 = parse_icmpv6_minimal(l4_bytes)?;
            Ok(TransportParse {
                transport: None,
                icmp: None,
                icmpv6: Some(icmpv6),
                igmp: None,
                tcp_options: None,
                gre: None,
                dns: None,
                hints: Vec::new(),
            })
        }
        2 => {
            let igmp = parse_igmp_minimal(l4_bytes)?;
            Ok(TransportParse {
                transport: None,
                icmp: None,
                icmpv6: None,
                igmp: Some(igmp),
                tcp_options: None,
                gre: None,
                dns: None,
                hints: Vec::new(),
            })
        }
        47 => {
            let gre = parse_gre_minimal(l4_bytes)?;
            Ok(TransportParse {
                transport: None,
                icmp: None,
                icmpv6: None,
                igmp: None,
                tcp_options: None,
                gre: Some(gre),
                dns: None,
                hints: Vec::new(),
            })
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
    let group_address = Some(std::net::Ipv4Addr::new(
        data[4], data[5], data[6], data[7],
    ));
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
