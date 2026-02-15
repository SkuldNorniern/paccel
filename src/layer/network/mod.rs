pub mod icmp;
pub mod icmpv6;
pub mod igmp;
pub mod ipv4;
pub mod ipv6;
use crate::layer::{LayerError, LayerProcessor};
use crate::packet::Packet;
use ipv4::Ipv4Processor;
use ipv6::Ipv6Processor;

use super::ProtocolProcessor;

/// Supported network protocols.
#[derive(Debug)]
pub enum NetworkProtocol {
    IPv4,
    IPv6,
}

/// A network-layer processor that identifies the network protocol
/// and (when complete) will delegate processing to the appropriate parser.
pub struct NetworkProcessor;

impl NetworkProcessor {
    /// Identify the protocol based on the first byte of the header.
    /// - IPv4 packets have a version field of 4.
    /// - IPv6 packets have a version field of 6.
    pub fn identify_protocol(data: &[u8]) -> Result<NetworkProtocol, LayerError> {
        if data.is_empty() {
            return Err(LayerError::InvalidLength);
        }

        match data[0] >> 4 {
            4 => Ok(NetworkProtocol::IPv4),
            6 => Ok(NetworkProtocol::IPv6),
            other => Err(LayerError::UnsupportedProtocol(other)),
        }
    }
}

impl LayerProcessor for NetworkProcessor {
    fn process(&self, packet: &mut Packet) -> Result<(), LayerError> {
        if packet.payload.is_empty() {
            return Err(LayerError::InvalidLength);
        }

        let protocol = Self::identify_protocol(&packet.payload)?;
        let mut view_packet = Packet::new(packet.payload.clone());

        match protocol {
            NetworkProtocol::IPv4 => {
                let header = Ipv4Processor.parse(&mut view_packet)?;
                let header_len = (header.ihl as usize) * 4;
                let total_len = header.total_length as usize;
                if total_len < header_len || total_len > packet.payload.len() {
                    return Err(LayerError::InvalidLength);
                }
                packet.payload = packet.payload[header_len..total_len].to_vec();
                Ok(())
            }
            NetworkProtocol::IPv6 => {
                let header = Ipv6Processor.parse(&mut view_packet)?;
                let payload_len = header.payload_length as usize;
                let start = 40;
                let end = start + payload_len;
                if end > packet.payload.len() {
                    return Err(LayerError::InvalidLength);
                }
                packet.payload = packet.payload[start..end].to_vec();
                Ok(())
            }
        }
    }
}
