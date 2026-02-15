use super::cursor::Cursor;
use crate::layer::application::dns::{DnsMessage, DnsProcessor};
use crate::layer::datalink::arp::{ArpPacket, ArpProcessor};
use crate::layer::network::ipv4::{Ipv4Header, Ipv4Processor};
use crate::layer::network::ipv6::{Ipv6Header, Ipv6Processor};
use crate::layer::transport::tcp::{TcpHeader, TcpProcessor};
use crate::layer::transport::udp::{UdpHeader, UdpProcessor};
use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

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
    pub warnings: Vec<String>,
}

pub struct BuiltinPacketParser;

impl BuiltinPacketParser {
    pub fn parse(raw: &[u8]) -> Result<ParsedPacket, LayerError> {
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
                let mut packet = Packet::new(l3_bytes.to_vec());
                let arp = ArpProcessor.parse(&mut packet)?;
                parsed.arp = Some(arp);
                Ok(parsed)
            }
            0x0800 => {
                let mut packet = Packet::new(l3_bytes.to_vec());
                let ipv4 = Ipv4Processor.parse(&mut packet)?;

                let ip_header_len = (ipv4.ihl as usize) * 4;
                let total_len = ipv4.total_length as usize;
                if total_len < ip_header_len || total_len > l3_bytes.len() {
                    return Err(LayerError::InvalidLength);
                }

                let l4_bytes = &l3_bytes[ip_header_len..total_len];
                let (transport, dns) = parse_transport(ipv4.protocol, l4_bytes)?;
                parsed.transport = transport;
                parsed.dns = dns;
                parsed.ipv4 = Some(ipv4);
                Ok(parsed)
            }
            0x86DD => {
                let mut packet = Packet::new(l3_bytes.to_vec());
                let ipv6 = Ipv6Processor.parse(&mut packet)?;

                let payload_len = ipv6.payload_length as usize;
                let l4_end = 40 + payload_len;
                if l4_end > l3_bytes.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ipv6_payload = &l3_bytes[..l4_end];
                let (next_header, l4_offset, non_initial_fragment) =
                    resolve_ipv6_transport(ipv6_payload, ipv6.next_header)?;
                if l4_offset > ipv6_payload.len() {
                    return Err(LayerError::InvalidLength);
                }

                if non_initial_fragment {
                    parsed.warnings.push(
                        "IPv6 non-initial fragment encountered; skipping L4/L7 parse without reassembly"
                            .to_string(),
                    );
                } else {
                    let l4_bytes = &ipv6_payload[l4_offset..];
                    let (transport, dns) = parse_transport(next_header, l4_bytes)?;
                    parsed.transport = transport;
                    parsed.dns = dns;
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
) -> Result<(Option<TransportSegment>, Option<DnsMessage>), LayerError> {
    match protocol {
        6 => {
            let mut packet = Packet {
                packet: Vec::new(),
                payload: l4_bytes.to_vec(),
                network_offset: 0,
            };
            let tcp = TcpProcessor.parse(&mut packet)?;
            Ok((Some(TransportSegment::Tcp(tcp)), None))
        }
        17 => {
            let mut packet = Packet {
                packet: Vec::new(),
                payload: l4_bytes.to_vec(),
                network_offset: 0,
            };
            let udp = UdpProcessor.parse(&mut packet)?;

            let dns = if udp.source_port == 53 || udp.destination_port == 53 {
                let udp_len = udp.length as usize;
                if udp_len >= 8 && udp_len <= l4_bytes.len() {
                    let app = &l4_bytes[8..udp_len];
                    if likely_dns_message(app) {
                        let mut dns_packet = Packet::new(app.to_vec());
                        DnsProcessor.parse(&mut dns_packet).ok()
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            Ok((Some(TransportSegment::Udp(udp)), dns))
        }
        _ => Ok((None, None)),
    }
}

fn resolve_ipv6_transport(
    packet: &[u8],
    initial_next_header: u8,
) -> Result<(u8, usize, bool), LayerError> {
    let mut non_initial_fragment = false;
    let mut next_header = initial_next_header;
    let mut offset = 40usize;

    loop {
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

                if frag_offset != 0 {
                    non_initial_fragment = true;
                    return Ok((next_header, offset, non_initial_fragment));
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
            }
            50 | 59 => return Ok((next_header, offset, non_initial_fragment)),
            _ => return Ok((next_header, offset, non_initial_fragment)),
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
    }
}
