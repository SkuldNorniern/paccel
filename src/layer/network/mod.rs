pub mod icmp;
pub mod icmpv6;
pub mod igmp;
pub mod ipv4;
pub mod ipv6;
use crate::layer::{LayerError, LayerProcessor};
use crate::packet::Packet;

/// Supported network protocols.
#[derive(Debug)]
pub enum NetworkProtocol {
    IPv4,
    IPv6,
    ICMP,
    ICMPv6,
    IGMP,
    // Extend as needed.
}

/// A network-layer processor that identifies the network protocol
/// and (when complete) will delegate processing to the appropriate parser.
pub struct NetworkProcessor;

impl NetworkProcessor {
    /// Identify the protocol based on the first byte of the header.
    /// For example:
    /// - IPv4 packets have a version field of 4.
    /// - IPv6 packets have a version field of 6.
    /// - Some implementations use different fields for ICMP or IGMP.
    pub fn identify_protocol(data: &[u8]) -> Result<NetworkProtocol, LayerError> {
        if data.is_empty() {
            return Err(LayerError::InvalidLength);
        }
        // In this simple example we use the high nibble.
        match data[0] >> 4 {
            4 => Ok(NetworkProtocol::IPv4),
            6 => Ok(NetworkProtocol::IPv6),
            // These mappings are examples; adjust as your header layout requires.
            1 => Ok(NetworkProtocol::ICMP),
            58 => Ok(NetworkProtocol::ICMPv6),
            2 => Ok(NetworkProtocol::IGMP),
            other => Err(LayerError::UnsupportedProtocol(other)),
        }
    }
}

impl LayerProcessor for NetworkProcessor {
    fn process(&self, packet: &mut Packet) -> Result<(), LayerError> {
        // Assume that `packet.payload` contains the raw bytes of the network layer header.
        let protocol = Self::identify_protocol(&packet.payload)?;

        match protocol {
            NetworkProtocol::IPv4 => {
                // Delegate to the IPv4 parsing module.
                // e.g., let header = ipv4::Ipv4Processor.parse(&mut packet)?;
                todo!("IPv4 processing not yet implemented");
            }
            NetworkProtocol::IPv6 => {
                // Delegate to the IPv6 parsing module.
                todo!("IPv6 processing not yet implemented");
            }
            // You could extend this with specific handling for ICMP, ICMPv6, or IGMP.
            _ => Err(LayerError::UnsupportedProtocol(0)), // placeholder error value
        }
    }
}
