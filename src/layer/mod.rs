use std::fmt;

use crate::layer::capture::CaptureInfo;
use crate::packet::Packet;

pub mod application; // Layer 7
mod capture;
pub mod datalink; // Layer 2 - Ethernet frames
pub mod network; // Layer 3 - IP (v4/v6)
pub mod physical; // Layer 1
pub mod presentation; // Layer 6
pub mod session; // Layer 5
pub mod transport; // Layer 4 - TCP/UDP

// use application::Application
use application::ApplicationProcessor;
use datalink::DatalinkProcessor;
use network::NetworkProcessor;
use transport::TransportProcessor;

/// Error types that can occur during packet parsing.
#[derive(Debug)]
pub enum LayerError {
    /// A required field is missing from the packet.
    MissingField,
    /// The packet length is invalid for the protocol being parsed.
    InvalidLength,
    /// The packet header contains invalid data.
    InvalidHeader,
    /// The packet is malformed or cannot be interpreted.
    MalformedPacket,
    /// The protocol is not supported by the parser.
    UnsupportedProtocol(u8),
    /// The packet lacks required data.
    InsufficientData,
    /// Protocol-specific error detected during validation.
    ValidationError(String),
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerError::MissingField => write!(f, "Required field is missing"),
            LayerError::InvalidLength => write!(f, "Invalid packet length"),
            LayerError::InvalidHeader => write!(f, "Invalid packet header"),
            LayerError::MalformedPacket => write!(f, "Malformed packet"),
            LayerError::UnsupportedProtocol(id) => write!(f, "Unsupported protocol ID: {}", id),
            LayerError::InsufficientData => write!(f, "Insufficient data in packet"),
            LayerError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

impl std::error::Error for LayerError {}

/// Protocol processors handle specific protocol parsing.
/// T is the protocol-specific data structure that will be returned after parsing.
pub trait ProtocolProcessor<T> {
    /// Parse a packet and extract the protocol-specific data.
    fn parse(&self, packet: &mut Packet) -> Result<T, LayerError>;

    /// Check if this processor can parse the given packet.
    /// This is typically a quick check of packet length and key header fields.
    fn can_parse(&self, packet: &Packet) -> bool {
        !packet.packet.is_empty() // Default implementation accepts all packets. Except for empty packets
    }

    /// Perform detailed validation of a packet.
    /// This may include checksum verification or other integrity checks.
    fn is_valid(&self, packet: &Packet) -> bool {
        !packet.packet.is_empty() // Default implementation considers all packets valid. Except for empty packets
    }
}

/// Layer processors handle an entire layer of the network stack.
/// They delegate to specific protocol processors based on protocol type.
pub trait LayerProcessor {
    /// Process a packet at this layer.
    /// If successful, the packet's payload will be updated to contain
    /// the payload for the next layer.
    fn process(&self, packet: &mut Packet) -> Result<(), LayerError>;
}

/// Parsed protocol information from each layer.
#[derive(Debug, Default)]
pub struct ParsedLayers {
    pub datalink: Option<datalink::arp::ArpPacket>,
    pub network_ipv4: Option<network::ipv4::Ipv4Header>,
    pub network_ipv6: Option<network::ipv6::Ipv6Header>,
    pub network_icmp: Option<network::icmp::IcmpHeader>,
    pub network_icmpv6: Option<network::icmpv6::Icmpv6Header>,
    pub transport: Option<transport::TransportInfo>,
    pub application: Option<application::ApplicationData>,
    // Add other protocol fields as needed
}

/// Parse all layers of a packet.
/// This is the main entry point for packet parsing.
/// Returns the parsed data from all layers.
pub fn parse_layers(packet: &mut Packet) -> Result<ParsedLayers, LayerError> {
    // Create a new ParsedLayers struct to store our results
    let mut parsed = ParsedLayers::default();

    println!(
        "Starting to parse packet of length: {}",
        packet.packet.len()
    );

    // Detect capture format first
    let capture_info = CaptureInfo::detect(&packet.packet).map_err(|e| {
        println!("Failed to detect capture format: {:?}", e);
        LayerError::MalformedPacket
    })?;
    packet.network_offset = capture_info.network_offset;
    println!(
        "Detected capture format {:?} with network offset: {}",
        capture_info.format, capture_info.network_offset
    );

    // Process datalink layer
    println!("Processing datalink layer...");
    process_datalink_layer(packet, &mut parsed);

    // Process network layer if we have a valid network layer
    if packet.network_offset < packet.packet.len() {
        println!(
            "Processing network layer at offset: {}",
            packet.network_offset
        );
        if let Err(e) = process_network_layer(packet, &mut parsed) {
            println!("Network layer processing error: {:?}, continuing anyway", e);
        } else {
            println!("Network layer processed successfully");
        }
    } else {
        println!(
            "Skipping network layer - invalid offset: {}",
            packet.network_offset
        );
    }

    // Process transport layer
    println!("Processing transport layer...");
    process_transport_layer(packet, &mut parsed)?;
    if parsed.transport.is_some() {
        println!("Transport layer processed successfully");
    } else {
        println!("Transport layer processing completed without data");
    }

    // Process application layer
    println!("Processing application layer...");
    process_application_layer(packet, &mut parsed)?;
    if parsed.application.is_some() {
        println!("Application layer processed successfully");
    } else {
        println!("Application layer processing completed without data");
    }

    println!("Packet parsing completed");
    Ok(parsed)
}

fn process_datalink_layer(packet: &mut Packet, _parsed: &mut ParsedLayers) {
    let datalink_processor = DatalinkProcessor;
    println!("Using DatalinkProcessor to process packet");
    match datalink_processor.process(packet) {
        Ok(_) => println!("Datalink layer processed successfully"),
        Err(e) => println!("Error in datalink processing: {:?}, continuing anyway", e),
    }
}

fn process_network_layer(packet: &mut Packet, parsed: &mut ParsedLayers) -> Result<(), LayerError> {
    // Make sure we're working with the correct part of the packet for network layer
    if packet.network_offset >= packet.packet.len() {
        return Err(LayerError::InvalidLength);
    }

    // Set the payload to start at the network offset - convert slice to Vec<u8>
    packet.payload = packet.packet[packet.network_offset..].to_vec();

    let network_processor = NetworkProcessor;
    println!(
        "Using NetworkProcessor to process packet starting at offset: {}",
        packet.network_offset
    );
    println!("Network payload length: {}", packet.payload.len());

    // First try to parse as IPv4
    let ipv4_processor = network::ipv4::Ipv4Processor;
    if ipv4_processor.can_parse(packet) {
        match ipv4_processor.parse(packet) {
            Ok(ipv4_header) => {
                println!(
                    "Successfully parsed IPv4 header: source={}, dest={}, proto={}",
                    ipv4_header.source, ipv4_header.destination, ipv4_header.protocol
                );
                // Update packet payload to the IPv4 payload for next layers
                let header_len = (ipv4_header.ihl as usize) * 4;
                let total_len = ipv4_header.total_length as usize;
                if total_len >= header_len && total_len <= packet.payload.len() {
                    packet.payload = packet.payload[header_len..total_len].to_vec();
                }
                // Save the IPv4 header in our parsed results
                parsed.network_ipv4 = Some(ipv4_header);

                return Ok(());
            }
            Err(e) => {
                println!("Failed to parse as IPv4: {:?}", e);
            }
        }
    }

    // If not IPv4, try the generic processor
    let result = network_processor.process(packet);
    if let Err(ref e) = result {
        println!("Error in network processing: {:?}", e);
    }
    result
}

fn process_transport_layer(
    packet: &mut Packet,
    parsed: &mut ParsedLayers,
) -> Result<(), LayerError> {
    let transport_processor = TransportProcessor;
    println!("Using TransportProcessor to process packet");

    // Use process_with_info to get the transport info
    match transport_processor.process_with_info(packet) {
        Ok(transport_info) => {
            println!("Transport layer successfully parsed");
            parsed.transport = Some(transport_info);
            Ok(())
        }
        Err(e) => {
            println!("Transport layer parsing failed: {:?}", e);
            // If transport processing fails, continue with the rest
            Ok(())
        }
    }
}

fn process_application_layer(
    packet: &mut Packet,
    parsed: &mut ParsedLayers,
) -> Result<(), LayerError> {
    // Process application protocols based on ports from transport layer
    if let Some(transport_info) = &parsed.transport {
        println!("Transport info available, processing application layer");
        let application_processor = ApplicationProcessor;
        match application_processor.process_with_info(packet, Some(transport_info)) {
            Ok(application_data) => {
                println!("Application layer successfully parsed");
                parsed.application = Some(application_data);
            }
            Err(e) => {
                println!("Application layer parsing failed: {:?}", e);
            }
        }
    } else {
        println!("No transport info available, skipping application layer");
    }

    Ok(())
}
