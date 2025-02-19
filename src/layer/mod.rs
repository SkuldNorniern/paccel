use std::fmt;

use crate::packet::Packet;

pub mod application; // Layer 7
pub mod datalink; // Layer 2 - Ethernet frames
pub mod network; // Layer 3 - IP (v4/v6)
pub mod physical; // Layer 1
pub mod presentation; // Layer 6
pub mod session; // Layer 5
pub mod transport; // Layer 4 - TCP/UDP

#[derive(Debug, Clone)]
pub enum LayerError {
    InvalidHeader,
    UnsupportedProtocol(u8),
    MalformedPacket,
    InvalidChecksum,
    InvalidLength,
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerError::InvalidHeader => write!(f, "Invalid header"),
            LayerError::UnsupportedProtocol(protocol) => {
                write!(f, "Unsupported protocol: {}", protocol)
            }
            LayerError::MalformedPacket => write!(f, "Malformed packet"),
            LayerError::InvalidChecksum => write!(f, "Invalid checksum"),
            LayerError::InvalidLength => write!(f, "Invalid length"),
        }
    }
}

pub trait LayerProcessor {
    /// Processes the packet.
    /// Uses proper error propagation (never unwrap) to signal issues.
    fn process(&self, packet: &mut Packet) -> Result<(), LayerError>;
}

/// Generic protocol processor trait.
/// The type parameter T represents the type returned from the parsing operation (e.g. a header struct).
pub trait ProtocolProcessor<T> {
    fn parse(&self, packet: &mut Packet) -> Result<T, LayerError>;
    fn can_parse(&self, packet: &Packet) -> bool;
    fn is_valid(&self, packet: &Packet) -> bool;
}

/// A helper function that demonstrates processing a packet through multiple layers.
/// In this simplified example, we call the ARP (datalink), network, and DNS (application)
/// processors in turn. In a fully integrated parser, the output of one layer would feed into
/// the next.
pub fn parse_layers(packet: &mut Packet) -> Result<(), LayerError> {
    // Process the datalink layer.
    let _ = datalink::arp::ArpProcessor.parse(packet);
    // Process the network layer.
    let _ = network::NetworkProcessor.process(packet);
    // Process the application layer.
    let _ = application::dns::DnsProcessor.parse(packet);
    
    Ok(())
}
