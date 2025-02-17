pub mod ipv4;
pub mod ipv6;
pub mod icmp;
pub mod arp;

use crate::packet::Packet;
use crate::layer::{LayerProcessor, LayerError};

#[derive(Debug)]
pub enum NetworkProtocol {
    IPv4,
    IPv6,
    ICMP,
    ARP,
    // Extend as needed.
}

pub struct NetworkProcessor;

impl NetworkProcessor {
    /// Identify the packet as IPv4 or IPv6 (or other)
    pub fn identify_protocol(data: &[u8]) -> Result<NetworkProtocol, LayerError> {
        if data.is_empty() {
            return Err(LayerError::InvalidLength);
        }
        match data[0] >> 4 {
            4 => Ok(NetworkProtocol::IPv4),
            6 => Ok(NetworkProtocol::IPv6),
            _ => Err(LayerError::UnsupportedProtocol(data[0])),
        }
    }
}

impl LayerProcessor for NetworkProcessor {
    fn process(&self, packet: &mut Packet) -> Result<(), LayerError> {
        // Assume `packet.payload` has the raw bytes for the network header.
        let protocol = Self::identify_protocol(&packet.payload)?;

        match protocol {
            NetworkProtocol::IPv4 => {
                // Delegate to the IPv4 parsing module, which parses and populates packet.ip_header
                // ipv4::parse(packet)?;
                todo!()
            }
            NetworkProtocol::IPv6 => {
                // Similar delegation to ipv6 parser.
                // ipv6::parse(packet)?;
                todo!()
            }
            _ => return Err(LayerError::UnsupportedProtocol(0)), // placeholder for others
        }
        Ok(())
    }
}
