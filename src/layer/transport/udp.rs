use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// Represents a UDP packet header.
///
/// The UDP header format is defined in RFC 768 and consists of:
///
///   0      7 8     15 16    23 24    31
///  +--------+--------+--------+--------+
///  |     Source      |   Destination   |
///  |      Port       |      Port       |
///  +--------+--------+--------+--------+
///  |                 |                 |
///  |     Length      |    Checksum     |
///  +--------+--------+--------+--------+
///  |                                   |
///  |            Data (variable)        |
///  +-----------------------------------+
///
#[derive(Debug, PartialEq, Eq)]
pub struct UdpHeader {
    /// Source port
    pub source_port: u16,
    /// Destination port
    pub destination_port: u16,
    /// Length of UDP header and data in bytes
    pub length: u16,
    /// Checksum of the UDP pseudo-header, header, and data
    pub checksum: u16,
}

/// Processor for UDP packets.
pub struct UdpProcessor;

impl ProtocolProcessor<UdpHeader> for UdpProcessor {
    fn parse(&self, packet: &mut Packet) -> Result<UdpHeader, LayerError> {
        // UDP header is 8 bytes long
        if packet.payload.len() < 8 {
            return Err(LayerError::InvalidLength);
        }

        // Extract fields from the packet
        let source_port = u16::from_be_bytes([packet.payload[0], packet.payload[1]]);
        let destination_port = u16::from_be_bytes([packet.payload[2], packet.payload[3]]);
        let length = u16::from_be_bytes([packet.payload[4], packet.payload[5]]);
        let checksum = u16::from_be_bytes([packet.payload[6], packet.payload[7]]);

        // Validate the length field
        if length < 8 {
            return Err(LayerError::InvalidHeader);
        }

        if packet.payload.len() < length as usize {
            return Err(LayerError::InvalidLength);
        }

        Ok(UdpHeader {
            source_port,
            destination_port,
            length,
            checksum,
        })
    }

    fn can_parse(&self, packet: &Packet) -> bool {
        // UDP header must be at least 8 bytes
        if packet.payload.len() < 8 {
            return false;
        }

        // Basic validation - check that the length field makes sense
        let length = u16::from_be_bytes([packet.payload[4], packet.payload[5]]);
        length >= 8 && packet.payload.len() >= length as usize
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        if !self.can_parse(packet) {
            return false;
        }

        // If checksum is 0, it means checksum is not used (allowed in IPv4)
        let checksum = u16::from_be_bytes([packet.payload[6], packet.payload[7]]);
        if checksum == 0 {
            return true;
        }

        // To properly validate the checksum, we would need the IP header information
        // for the pseudo-header. For simplicity, we'll just check that the length is valid.
        let length = u16::from_be_bytes([packet.payload[4], packet.payload[5]]);
        packet.payload.len() >= length as usize
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    /// Helper function to create a valid UDP packet for testing
    fn create_test_udp_packet() -> Vec<u8> {
        let source_port = 12345u16;
        let destination_port = 80u16;
        let length = 20u16; // 8 bytes header + 12 bytes data
        let checksum = 0u16; // No checksum
        let data = b"Hello, world"; // 12 bytes of data

        let mut packet = Vec::with_capacity(length as usize);
        packet.extend_from_slice(&source_port.to_be_bytes());
        packet.extend_from_slice(&destination_port.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(data);

        packet
    }

    #[test]
    fn test_parse_valid_udp() {
        let payload = create_test_udp_packet();
        let mut packet = Packet {
            packet: vec![],
            payload: payload,
            network_offset: 0,
        };
        let processor = UdpProcessor;
        let udp_header = processor
            .parse(&mut packet)
            .expect("UDP packet should parse successfully");

        assert_eq!(udp_header.source_port, 12345);
        assert_eq!(udp_header.destination_port, 80);
        assert_eq!(udp_header.length, 20);
        assert_eq!(udp_header.checksum, 0);
    }

    #[test]
    fn test_parse_invalid_length() {
        // Create a packet with a length field larger than the actual data
        let mut payload = create_test_udp_packet();
        // Set length to 30 but the actual packet is only 20 bytes
        payload[4] = 0;
        payload[5] = 30;

        let mut packet = Packet {
            packet: vec![],
            payload: payload,
            network_offset: 0,
        };
        let processor = UdpProcessor;
        let result = processor.parse(&mut packet);

        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::InvalidLength)));
    }

    #[test]
    fn test_short_packet() {
        // Create a packet shorter than the UDP header
        let payload = vec![0, 80, 0, 80, 0, 8]; // Only 6 bytes
        let mut packet = Packet {
            packet: vec![],
            payload: payload,
            network_offset: 0,
        };
        let processor = UdpProcessor;
        let result = processor.parse(&mut packet);

        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::InvalidLength)));
    }

    #[test]
    fn test_can_parse_valid() {
        let payload = create_test_udp_packet();
        let packet = Packet {
            packet: vec![],
            payload: payload,
            network_offset: 0,
        };
        let processor = UdpProcessor;

        assert!(processor.can_parse(&packet));
    }

    #[test]
    fn test_can_parse_invalid_short() {
        let payload = vec![0, 80, 0, 80]; // Only 4 bytes
        let packet = Packet {
            packet: vec![],
            payload: payload,
            network_offset: 0,
        };
        let processor = UdpProcessor;

        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_is_valid() {
        let payload = create_test_udp_packet();
        let packet = Packet {
            packet: vec![],
            payload: payload,
            network_offset: 0,
        };
        let processor = UdpProcessor;

        assert!(processor.is_valid(&packet));
    }
}
