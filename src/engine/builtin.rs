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
                parsed.transport = parse_transport(ipv4.protocol, l4_bytes)?;
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

                let l4_bytes = &l3_bytes[40..l4_end];
                parsed.transport = parse_transport(ipv6.next_header, l4_bytes)?;
                parsed.ipv6 = Some(ipv6);
                Ok(parsed)
            }
            other => Err(LayerError::UnsupportedProtocol((other & 0x00ff) as u8)),
        }
    }
}

fn parse_transport(protocol: u8, l4_bytes: &[u8]) -> Result<Option<TransportSegment>, LayerError> {
    match protocol {
        6 => {
            let mut packet = Packet {
                packet: Vec::new(),
                payload: l4_bytes.to_vec(),
                network_offset: 0,
            };
            let tcp = TcpProcessor.parse(&mut packet)?;
            Ok(Some(TransportSegment::Tcp(tcp)))
        }
        17 => {
            let mut packet = Packet {
                packet: Vec::new(),
                payload: l4_bytes.to_vec(),
                network_offset: 0,
            };
            let udp = UdpProcessor.parse(&mut packet)?;
            Ok(Some(TransportSegment::Udp(udp)))
        }
        _ => Ok(None),
    }
}

fn parse_ethernet(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    if raw.len() < 14 {
        return Err(LayerError::InvalidLength);
    }

    let mut destination = [0u8; 6];
    destination.copy_from_slice(&raw[0..6]);

    let mut source = [0u8; 6];
    source.copy_from_slice(&raw[6..12]);

    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
    offset += 2;
    let mut vlan_tags = Vec::new();

    while ethertype == 0x8100 || ethertype == 0x88A8 {
        if raw.len() < offset + 4 {
            return Err(LayerError::InvalidLength);
        }

        let tci = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
        vlan_tags.push(tci);
        ethertype = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
    }

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
}
