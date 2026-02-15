//! The transport layer (Layer 4) modules.
//! This layer handles protocols like TCP and UDP.

pub mod tcp;
pub mod udp;

use tcp::{TcpHeader, TcpProcessor};
use udp::{UdpHeader, UdpProcessor};

use super::{LayerProcessor, ProtocolProcessor};
use crate::packet::Packet;
use crate::LayerError;

/// Represents the parsed transport layer information.
/// This enum will contain either TCP or UDP header data.
#[derive(Debug)]
pub enum TransportInfo {
    /// TCP header and metadata
    Tcp(TcpHeader),
    /// UDP header and metadata
    Udp(UdpHeader),
}

impl TransportInfo {
    /// Returns the source port, regardless of transport protocol
    pub fn source_port(&self) -> u16 {
        match self {
            TransportInfo::Tcp(header) => header.source_port,
            TransportInfo::Udp(header) => header.source_port,
        }
    }

    /// Returns the destination port, regardless of transport protocol
    pub fn destination_port(&self) -> u16 {
        match self {
            TransportInfo::Tcp(header) => header.destination_port,
            TransportInfo::Udp(header) => header.destination_port,
        }
    }

    /// Returns the protocol name
    pub fn protocol_name(&self) -> &'static str {
        match self {
            TransportInfo::Tcp(_) => "TCP",
            TransportInfo::Udp(_) => "UDP",
        }
    }
}

/// The TransportProcessor handles protocols at the transport layer,
/// such as TCP and UDP.
pub struct TransportProcessor;

impl TransportProcessor {
    /// Process a packet and return detailed transport layer information
    pub fn process_with_info(&self, packet: &mut Packet) -> Result<TransportInfo, LayerError> {
        // Try to determine which protocol processor to use
        // First check TCP
        let tcp_processor = TcpProcessor;
        if tcp_processor.can_parse(packet) {
            let tcp_header = tcp_processor.parse(packet)?;
            return Ok(TransportInfo::Tcp(tcp_header));
        }

        // Then check UDP
        let udp_processor = UdpProcessor;
        if udp_processor.can_parse(packet) {
            let udp_header = udp_processor.parse(packet)?;
            return Ok(TransportInfo::Udp(udp_header));
        }

        // If no transport protocol could be identified
        Err(LayerError::UnsupportedProtocol(0)) // 0 is a placeholder since we don't know the protocol
    }
}

impl LayerProcessor for TransportProcessor {
    fn process(&self, packet: &mut Packet) -> Result<(), LayerError> {
        // Use the more detailed process_with_info method but discard the result
        self.process_with_info(packet)?;
        Ok(())
    }
}

/// Maps protocol numbers to their names for debugging and display purposes.
pub fn protocol_name(protocol: u8) -> Option<&'static str> {
    match protocol {
        6 => Some("TCP"),
        17 => Some("UDP"),
        // Add other protocols as needed
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a basic TCP packet
    fn create_tcp_packet() -> Vec<u8> {
        vec![
            0x12, 0x34, // Source port: 4660
            0x00, 0x50, // Destination port: 80
            0x00, 0x00, 0x00, 0x01, // Sequence number: 1
            0x00, 0x00, 0x00, 0x02, // Acknowledgment number: 2
            0x50, 0x10, // Data offset: 5, Flags: ACK
            0x10, 0x00, // Window size: 4096
            0x00, 0x00, // Checksum: 0
            0x00, 0x00, // Urgent pointer: 0
            0x01, 0x02, 0x03, 0x04, // Some payload data
        ]
    }

    /// Helper function to create a basic UDP packet
    fn create_udp_packet() -> Vec<u8> {
        vec![
            0x12, 0x34, // Source port: 4660
            0x00, 0x35, // Destination port: 53 (DNS)
            0x00, 0x10, // Length: 16 bytes (8 header + 8 data)
            0x00, 0x00, // Checksum: 0
            0x01, 0x02, 0x03, 0x04, // Some dummy payload data
            0x05, 0x06, 0x07, 0x08,
        ]
    }

    /// Helper function to create an invalid/unsupported transport packet
    fn create_invalid_packet() -> Vec<u8> {
        vec![
            0x00, 0x00, // Invalid header bytes
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn test_process_tcp() {
        let packet_data = create_tcp_packet();
        let mut packet = Packet {
            packet: vec![],
            payload: packet_data,
            network_offset: 0,
        };

        let processor = TransportProcessor;
        let result = processor.process(&mut packet);

        assert!(
            result.is_ok(),
            "Processing a valid TCP packet should succeed"
        );
    }

    #[test]
    fn test_process_with_info_tcp() {
        let packet_data = create_tcp_packet();
        let mut packet = Packet {
            packet: vec![],
            payload: packet_data,
            network_offset: 0,
        };

        let processor = TransportProcessor;
        let result = processor.process_with_info(&mut packet);

        assert!(
            result.is_ok(),
            "Processing a valid TCP packet should succeed"
        );
        if let Ok(info) = result {
            match info {
                TransportInfo::Tcp(header) => {
                    assert_eq!(header.source_port, 4660);
                    assert_eq!(header.destination_port, 80);
                    assert_eq!(header.sequence_number, 1);
                    assert_eq!(header.acknowledgment_number, 2);
                    assert!(header.flags.ack);
                    assert!(!header.flags.syn);
                }
                _ => panic!("Expected TCP header, got UDP header"),
            }
        }
    }

    #[test]
    fn test_process_udp() {
        let packet_data = create_udp_packet();
        let mut packet = Packet {
            packet: vec![],
            payload: packet_data,
            network_offset: 0,
        };

        let processor = TransportProcessor;
        let result = processor.process(&mut packet);

        assert!(
            result.is_ok(),
            "Processing a valid UDP packet should succeed"
        );
    }

    #[test]
    fn test_process_with_info_udp() {
        let packet_data = create_udp_packet();
        let mut packet = Packet {
            packet: vec![],
            payload: packet_data,
            network_offset: 0,
        };

        let processor = TransportProcessor;
        let result = processor.process_with_info(&mut packet);

        assert!(
            result.is_ok(),
            "Processing a valid UDP packet should succeed"
        );
        if let Ok(info) = result {
            match info {
                TransportInfo::Udp(header) => {
                    assert_eq!(header.source_port, 4660);
                    assert_eq!(header.destination_port, 53);
                    assert_eq!(header.length, 16);
                }
                _ => panic!("Expected UDP header, got TCP header"),
            }
        }
    }

    #[test]
    fn test_process_unsupported() {
        let packet_data = create_invalid_packet();
        let mut packet = Packet {
            packet: vec![],
            payload: packet_data,
            network_offset: 0,
        };

        let processor = TransportProcessor;
        let result = processor.process(&mut packet);

        assert!(result.is_err(), "Processing an invalid packet should fail");
        if let Err(error) = result {
            assert!(matches!(error, LayerError::UnsupportedProtocol(_)));
        }
    }

    #[test]
    fn test_transport_info_methods() {
        // Create a TCP packet and extract its info
        let mut tcp_packet = Packet {
            packet: vec![],
            payload: create_tcp_packet(),
            network_offset: 0,
        };
        let processor = TransportProcessor;
        let tcp_info = processor.process_with_info(&mut tcp_packet).unwrap();

        assert_eq!(tcp_info.source_port(), 4660);
        assert_eq!(tcp_info.destination_port(), 80);
        assert_eq!(tcp_info.protocol_name(), "TCP");

        // Create a UDP packet and extract its info
        let mut udp_packet = Packet {
            packet: vec![],
            payload: create_udp_packet(),
            network_offset: 0,
        };
        let udp_info = processor.process_with_info(&mut udp_packet).unwrap();

        assert_eq!(udp_info.source_port(), 4660);
        assert_eq!(udp_info.destination_port(), 53);
        assert_eq!(udp_info.protocol_name(), "UDP");
    }

    #[test]
    fn test_protocol_name() {
        assert_eq!(protocol_name(6), Some("TCP"));
        assert_eq!(protocol_name(17), Some("UDP"));
        assert_eq!(protocol_name(99), None);
    }
}
