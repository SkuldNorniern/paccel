use super::cursor::Cursor;
use crate::layer::application::dns::{DnsMessage, DnsProcessor};
use crate::layer::datalink::arp::{ArpOperation, ArpPacket};
use crate::layer::network::ipv4::Ipv4Header;
use crate::layer::network::ipv6::Ipv6Header;
use crate::layer::transport::tcp::{TcpFlags, TcpHeader};
use crate::layer::transport::udp::UdpHeader;
use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseWarningCode {
    Ipv6NonInitialFragment,
    Ipv6ExtensionDepthLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWarning {
    pub code: ParseWarningCode,
    pub message: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct ParseConfig {
    pub max_ipv6_extension_headers: usize,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self {
            max_ipv6_extension_headers: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAppHint {
    Dns,
    Mdns,
    Dhcp,
    Ntp,
}

#[derive(Debug, Clone)]
pub struct EthernetFrame {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
    pub vlan_tags: Vec<u16>,
    pub payload_offset: usize,
}

#[derive(Debug)]
pub enum TransportSegment {
    Tcp(TcpHeader),
    Udp(UdpHeader),
}

#[derive(Debug, Default)]
pub struct ParsedPacket {
    pub ethernet: Option<EthernetFrame>,
    pub arp: Option<ArpPacket>,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub transport: Option<TransportSegment>,
    pub dns: Option<DnsMessage>,
    pub udp_hints: Vec<UdpAppHint>,
    pub warnings: Vec<ParseWarning>,
}

pub struct BuiltinPacketParser;

impl BuiltinPacketParser {
    pub fn parse(raw: &[u8]) -> Result<ParsedPacket, LayerError> {
        Self::parse_with_config(raw, ParseConfig::default())
    }

    pub fn parse_with_config(raw: &[u8], config: ParseConfig) -> Result<ParsedPacket, LayerError> {
        let (eth, l3_offset) = parse_ethernet(raw)?;
        let mut parsed = ParsedPacket {
            ethernet: Some(eth.clone()),
            ..ParsedPacket::default()
        };

        if l3_offset >= raw.len() {
            return Err(LayerError::InvalidLength);
        }

        let l3_bytes = &raw[l3_offset..];

        match eth.ethertype {
            0x0806 => {
                let arp = parse_arp_packet(l3_bytes)?;
                parsed.arp = Some(arp);
                Ok(parsed)
            }
            0x0800 => {
                let ipv4 = parse_ipv4_header(l3_bytes)?;

                let ip_header_len = (ipv4.ihl as usize) * 4;
                let total_len = ipv4.total_length as usize;
                if total_len < ip_header_len || total_len > l3_bytes.len() {
                    return Err(LayerError::InvalidLength);
                }

                let l4_bytes = &l3_bytes[ip_header_len..total_len];
                let (transport, dns, hints) = parse_transport(ipv4.protocol, l4_bytes)?;
                parsed.transport = transport;
                parsed.dns = dns;
                parsed.udp_hints = hints;
                parsed.ipv4 = Some(ipv4);
                Ok(parsed)
            }
            0x86DD => {
                let ipv6 = parse_ipv6_header(l3_bytes)?;

                let payload_len = ipv6.payload_length as usize;
                let l4_end = 40 + payload_len;
                if l4_end > l3_bytes.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ipv6_payload = &l3_bytes[..l4_end];
                let (next_header, l4_offset, non_initial_fragment, depth_limit_hit) =
                    resolve_ipv6_transport(
                        ipv6_payload,
                        ipv6.next_header,
                        config.max_ipv6_extension_headers,
                    )?;
                if l4_offset > ipv6_payload.len() {
                    return Err(LayerError::InvalidLength);
                }

                if depth_limit_hit {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6ExtensionDepthLimit,
                        message: "IPv6 extension header depth limit reached; skipping L4/L7 parse",
                    });
                }

                if non_initial_fragment {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6NonInitialFragment,
                        message:
                            "IPv6 non-initial fragment encountered; skipping L4/L7 parse without reassembly",
                    });
                }

                if !non_initial_fragment && !depth_limit_hit {
                    let l4_bytes = &ipv6_payload[l4_offset..];
                    let (transport, dns, hints) = parse_transport(next_header, l4_bytes)?;
                    parsed.transport = transport;
                    parsed.dns = dns;
                    parsed.udp_hints = hints;
                }

                parsed.ipv6 = Some(ipv6);
                Ok(parsed)
            }
            other => Err(LayerError::UnsupportedProtocol((other & 0x00ff) as u8)),
        }
    }
}

fn parse_transport(
    protocol: u8,
    l4_bytes: &[u8],
) -> Result<
    (
        Option<TransportSegment>,
        Option<DnsMessage>,
        Vec<UdpAppHint>,
    ),
    LayerError,
> {
    match protocol {
        6 => {
            let tcp = parse_tcp_header(l4_bytes)?;
            Ok((Some(TransportSegment::Tcp(tcp)), None, Vec::new()))
        }
        17 => {
            let udp = parse_udp_header(l4_bytes)?;
            let udp_len = udp.length as usize;
            let app = &l4_bytes[8..udp_len];

            let mut hints = Vec::new();
            let mut dns = None;

            if (udp.source_port == 53 || udp.destination_port == 53) && likely_dns_message(app) {
                hints.push(UdpAppHint::Dns);
                let mut dns_packet = Packet::new(app.to_vec());
                dns = DnsProcessor.parse(&mut dns_packet).ok();
            }

            if (udp.source_port == 5353 || udp.destination_port == 5353) && likely_dns_message(app)
            {
                push_hint_unique(&mut hints, UdpAppHint::Mdns);
                if dns.is_none() {
                    let mut dns_packet = Packet::new(app.to_vec());
                    dns = DnsProcessor.parse(&mut dns_packet).ok();
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

            Ok((Some(TransportSegment::Udp(udp)), dns, hints))
        }
        _ => Ok((None, None, Vec::new())),
    }
}

fn parse_arp_packet(data: &[u8]) -> Result<ArpPacket, LayerError> {
    if data.len() < 28 {
        return Err(LayerError::InvalidLength);
    }

    let hardware_type = u16::from_be_bytes([data[0], data[1]]);
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);
    let hardware_len = data[4];
    let protocol_len = data[5];

    if hardware_len != 6 || protocol_len != 4 {
        return Err(LayerError::InvalidHeader);
    }

    let expected_len = 8
        + (hardware_len as usize)
        + (protocol_len as usize)
        + (hardware_len as usize)
        + (protocol_len as usize);
    if data.len() < expected_len {
        return Err(LayerError::InvalidLength);
    }

    let operation_code = u16::from_be_bytes([data[6], data[7]]);
    let operation = match operation_code {
        1 => ArpOperation::Request,
        2 => ArpOperation::Reply,
        other => ArpOperation::Unknown(other),
    };

    let mut sender_hardware_addr = [0u8; 6];
    sender_hardware_addr.copy_from_slice(&data[8..14]);
    let sender_protocol_addr = std::net::Ipv4Addr::new(data[14], data[15], data[16], data[17]);

    let mut target_hardware_addr = [0u8; 6];
    target_hardware_addr.copy_from_slice(&data[18..24]);
    let target_protocol_addr = std::net::Ipv4Addr::new(data[24], data[25], data[26], data[27]);

    Ok(ArpPacket {
        hardware_type,
        protocol_type,
        hardware_len,
        protocol_len,
        operation,
        sender_hardware_addr,
        sender_protocol_addr,
        target_hardware_addr,
        target_protocol_addr,
    })
}

fn parse_ipv4_header(data: &[u8]) -> Result<Ipv4Header, LayerError> {
    if data.len() < 20 {
        return Err(LayerError::InvalidLength);
    }

    let first = data[0];
    let version = first >> 4;
    let ihl = first & 0x0f;
    if version != 4 || ihl < 5 {
        return Err(LayerError::InvalidHeader);
    }

    let header_len = (ihl as usize) * 4;
    if data.len() < header_len {
        return Err(LayerError::InvalidLength);
    }

    let dscp = data[1] >> 2;
    let ecn = data[1] & 0x03;
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    if data.len() < total_length as usize {
        return Err(LayerError::InvalidLength);
    }

    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_fragment = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_fragment >> 13) as u8;
    let fragment_offset = flags_fragment & 0x1fff;
    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);
    let source = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let destination = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let options = if ihl > 5 {
        Some(data[20..header_len].to_vec())
    } else {
        None
    };

    Ok(Ipv4Header {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        source,
        destination,
        options,
    })
}

fn parse_ipv6_header(data: &[u8]) -> Result<Ipv6Header, LayerError> {
    if data.len() < 40 {
        return Err(LayerError::InvalidLength);
    }

    let first_word = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let version = ((first_word >> 28) & 0x0f) as u8;
    if version != 6 {
        return Err(LayerError::InvalidHeader);
    }

    let traffic_class = ((first_word >> 20) & 0xff) as u8;
    let flow_label = first_word & 0x000f_ffff;
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    let source = std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&data[8..24]).map_err(|_| LayerError::InvalidHeader)?,
    );
    let destination = std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&data[24..40]).map_err(|_| LayerError::InvalidHeader)?,
    );

    Ok(Ipv6Header {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        source,
        destination,
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

fn resolve_ipv6_transport(
    packet: &[u8],
    initial_next_header: u8,
    max_ext_headers: usize,
) -> Result<(u8, usize, bool, bool), LayerError> {
    let mut non_initial_fragment = false;
    let mut depth_limit_hit = false;
    let mut next_header = initial_next_header;
    let mut offset = 40usize;
    let mut depth = 0usize;

    loop {
        if depth >= max_ext_headers {
            depth_limit_hit = true;
            return Ok((next_header, offset, non_initial_fragment, depth_limit_hit));
        }

        match next_header {
            0 | 43 | 60 => {
                if offset + 2 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[offset];
                let ext_len = packet[offset + 1] as usize;
                let header_len = (ext_len + 1) * 8;
                if offset + header_len > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                next_header = ext_next;
                offset += header_len;
                depth += 1;
            }
            44 => {
                if offset + 8 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[offset];
                let frag_off_flags = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                let frag_offset = (frag_off_flags & 0xFFF8) >> 3;

                next_header = ext_next;
                offset += 8;
                depth += 1;

                if frag_offset != 0 {
                    non_initial_fragment = true;
                    return Ok((next_header, offset, non_initial_fragment, depth_limit_hit));
                }
            }
            51 => {
                if offset + 2 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[offset];
                let payload_len = packet[offset + 1] as usize;
                let header_len = (payload_len + 2) * 4;
                if offset + header_len > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                next_header = ext_next;
                offset += header_len;
                depth += 1;
            }
            50 | 59 => return Ok((next_header, offset, non_initial_fragment, depth_limit_hit)),
            _ => return Ok((next_header, offset, non_initial_fragment, depth_limit_hit)),
        }
    }
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

fn parse_ethernet(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    if raw.len() < 14 {
        return Err(LayerError::InvalidLength);
    }

    let mut cursor = Cursor::new(raw);
    let destination_bytes = cursor.read_exact(6).ok_or(LayerError::InvalidLength)?;
    let source_bytes = cursor.read_exact(6).ok_or(LayerError::InvalidLength)?;

    let mut destination = [0u8; 6];
    destination.copy_from_slice(destination_bytes);

    let mut source = [0u8; 6];
    source.copy_from_slice(source_bytes);

    let mut ethertype = cursor.read_u16_be().ok_or(LayerError::InvalidLength)?;
    let mut vlan_tags = Vec::new();

    while ethertype == 0x8100 || ethertype == 0x88A8 {
        let tci = cursor.read_u16_be().ok_or(LayerError::InvalidLength)?;
        vlan_tags.push(tci);
        ethertype = cursor.read_u16_be().ok_or(LayerError::InvalidLength)?;
    }

    let offset = cursor.pos();

    Ok((
        EthernetFrame {
            destination,
            source,
            ethertype,
            vlan_tags,
            payload_offset: offset,
        },
        offset,
    ))
}

#[cfg(test)]
mod tests {
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
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
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
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let frame = build_ethernet_ipv4_udp_frame(5353, 5353, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Mdns));
        assert!(parsed.dns.is_some());
    }
}
