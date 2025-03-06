use std::convert::TryInto;
use std::net::Ipv6Addr;

use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// Represents an IPv6 packet header.
///
/// The IPv6 fixed header format is defined in RFC 8200. The header is always 40 bytes:
///
///   +---------------------------------------------------------------+
///   |Version| Traffic Class (8)       |         Flow Label (20)       |
///   +---------------------------------------------------------------+
///   |         Payload Length (16)       | Next Header (8)| Hop Limit (8)|
///   +---------------------------------------------------------------+
///   |                                                               |
///   |                         Source Address (128)                  |
///   |                                                               |
///   +---------------------------------------------------------------+
///   |                                                               |
///   |                      Destination Address (128)                |
///   |                                                               |
///   +---------------------------------------------------------------+
///
/// This module extracts the fields of the IPv6 header into an `Ipv6Header` struct.
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    /// IPv6 version (should always be 6).
    pub version: u8,
    /// Traffic Class (8 bits).
    pub traffic_class: u8,
    /// Flow Label (20 bits).
    pub flow_label: u32,
    /// Payload length (16 bits).
    pub payload_length: u16,
    /// Next Header (8 bits).
    pub next_header: u8,
    /// Hop Limit (8 bits).
    pub hop_limit: u8,
    /// Source IP address (128 bits).
    pub source: Ipv6Addr,
    /// Destination IP address (128 bits).
    pub destination: Ipv6Addr,
}

/// An IPv6 processor that implements the ProtocolProcessor trait.
///
/// This implementation verifies that the packet contains at least 40 bytes and then extracts
/// the IPv6 header fields according to their fixed positions.
pub struct Ipv6Processor;

impl ProtocolProcessor<Ipv6Header> for Ipv6Processor {
    fn parse(&self, packet: &mut Packet) -> Result<Ipv6Header, LayerError> {
        let data = &packet.packet;
        if data.len() < 40 {
            return Err(LayerError::InvalidHeader);
        }
        // Parse the first 4 bytes into a u32.
        // It is safe to use unwrap here since we already checked that data has at least 40 bytes.
        let first_word = u32::from_be_bytes(
            data[0..4]
                .try_into()
                .expect("slice of length 4 available due to length check"),
        );
        let version = ((first_word >> 28) & 0xF) as u8;
        if version != 6 {
            return Err(LayerError::InvalidHeader);
        }
        let traffic_class = ((first_word >> 20) & 0xFF) as u8;
        let flow_label = first_word & 0x000F_FFFF;

        let payload_length = u16::from_be_bytes(
            data[4..6]
                .try_into()
                .map_err(|_| LayerError::InvalidHeader)?,
        );
        let next_header = data[6];
        let hop_limit = data[7];

        let source = Ipv6Addr::from(
            <[u8; 16]>::try_from(&data[8..24]).map_err(|_| LayerError::InvalidHeader)?,
        );
        let destination = Ipv6Addr::from(
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

    fn can_parse(&self, packet: &Packet) -> bool {
        if packet.packet.len() < 40 {
            return false;
        }

        // Check version (must be 6 for IPv6)
        let version = packet.packet[0] >> 4;
        version == 6
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        if packet.packet.len() < 40 {
            return false;
        }

        // Verify payload length field
        let payload_length = u16::from_be_bytes([packet.packet[4], packet.packet[5]]) as usize;
        if 40 + payload_length > packet.packet.len() {
            return false;
        }

        // Verify version is 6
        packet.packet[0] >> 4 == 6
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{LayerError, ProtocolProcessor};
    use crate::packet::Packet;
    use std::net::Ipv6Addr;

    #[test]
    fn test_valid_ipv6_header() {
        // Construct a valid IPv6 header:
        // - Version: 6 (first 4 bits)
        // - Traffic Class: 0, Flow Label: 0
        // - Payload Length: 20 (0x0014)
        // - Next Header: 6 (commonly TCP)
        // - Hop Limit: 64 (0x40)
        // - Source Address: ::1
        // - Destination Address: ::2
        let mut header_bytes = Vec::new();

        // First 4 bytes: combine version (6), traffic class (0) and flow label (0).
        // The top 4 bits represent the IPv6 version.
        let first_word: u32 = 6 << 28; // version 6, rest all 0.
        header_bytes.extend_from_slice(&first_word.to_be_bytes());

        // Payload Length (16 bits).
        header_bytes.extend_from_slice(&20u16.to_be_bytes());

        // Next Header (8 bits) and Hop Limit (8 bits).
        header_bytes.push(6);
        header_bytes.push(64);

        // Source Address: ::1 -> represented as 15 zeros followed by 1.
        let src: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        header_bytes.extend_from_slice(&src);

        // Destination Address: ::2 -> represented as 15 zeros followed by 2.
        let dst: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        header_bytes.extend_from_slice(&dst);

        // Verify header length is exactly 40 bytes.
        assert_eq!(header_bytes.len(), 40);

        let mut packet = Packet::new(header_bytes);

        let processor = Ipv6Processor;
        let result = processor
            .parse(&mut packet)
            .expect("Valid IPv6 packet should be parsed successfully");
        let expected_header = Ipv6Header {
            version: 6,
            traffic_class: 0,
            flow_label: 0,
            payload_length: 20,
            next_header: 6,
            hop_limit: 64,
            source: Ipv6Addr::from(src),
            destination: Ipv6Addr::from(dst),
        };

        assert_eq!(result, expected_header);
    }

    #[test]
    fn test_invalid_version() {
        // Construct a header with version set to 4 instead of 6.
        let mut header_bytes = Vec::new();

        let first_word: u32 = 4 << 28; // incorrect version (4 instead of 6)
        header_bytes.extend_from_slice(&first_word.to_be_bytes());
        header_bytes.extend_from_slice(&20u16.to_be_bytes());
        header_bytes.push(6);
        header_bytes.push(64);
        let src: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        header_bytes.extend_from_slice(&src);
        let dst: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        header_bytes.extend_from_slice(&dst);

        let mut packet = Packet::new(header_bytes);

        let processor = Ipv6Processor;
        let result = processor.parse(&mut packet);
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                LayerError::InvalidHeader => {}
                _ => panic!("Expected LayerError::InvalidHeader, got {:?}", e),
            }
        }
    }

    #[test]
    fn test_short_packet() {
        // A packet with fewer than 40 bytes should return an InvalidHeader error.
        let mut packet = Packet::new(vec![0; 30]);
        let processor = Ipv6Processor;
        let result = processor.parse(&mut packet);
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                LayerError::InvalidHeader => {}
                _ => panic!("Expected LayerError::InvalidHeader, got {:?}", e),
            }
        }
    }

    #[test]
    fn test_valid_ipv6_header_with_nonzero_flow_label_and_tc() {
        let mut header_bytes = Vec::new();

        // Set version = 6, Traffic Class = 0xAA, and Flow Label = some 20-bit value.
        let version: u32 = 6;
        let traffic_class: u32 = 0xAA; // Example Traffic Class.
        let flow_label: u32 = 0xABCDE & 0x000F_FFFF; // 20-bit Flow Label.
        let first_word: u32 = (version << 28) | (traffic_class << 20) | flow_label;
        header_bytes.extend_from_slice(&first_word.to_be_bytes());

        // Set Payload Length = 20 bytes.
        header_bytes.extend_from_slice(&20u16.to_be_bytes());
        // Next Header = 17 (UDP), Hop Limit = 128.
        header_bytes.push(17);
        header_bytes.push(128);
        // Source address.
        let src: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        header_bytes.extend_from_slice(&src);
        // Destination address.
        let dst: [u8; 16] = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        header_bytes.extend_from_slice(&dst);

        assert_eq!(header_bytes.len(), 40);

        let mut packet = Packet::new(header_bytes);
        let header = Ipv6Processor
            .parse(&mut packet)
            .expect("IPv6 header with nonzero TC and Flow Label should be parsed successfully");
        assert_eq!(header.version, 6);
        assert_eq!(header.traffic_class, 0xAA);
        assert_eq!(header.flow_label, flow_label);
        assert_eq!(header.payload_length, 20);
        assert_eq!(header.next_header, 17);
        assert_eq!(header.hop_limit, 128);
        assert_eq!(header.source, Ipv6Addr::from(src));
        assert_eq!(header.destination, Ipv6Addr::from(dst));
    }

    /// Creates a valid fixed 40-byte IPv6 header (with no payload).
    fn create_valid_ipv6_header() -> Vec<u8> {
        let mut header = Vec::with_capacity(40);
        // First 4 bytes: Version (6), Traffic Class = 0, Flow Label = 0.
        let first_word: u32 = 6 << 28;
        header.extend_from_slice(&first_word.to_be_bytes());
        // Payload Length (16 bits): 0 (no payload).
        header.extend_from_slice(&0u16.to_be_bytes());
        // Next Header (8 bits, e.g., UDP = 17), Hop Limit (8 bits).
        header.push(17);
        header.push(64);
        // Source Address: ::1
        let src = Ipv6Addr::LOCALHOST.octets();
        header.extend_from_slice(&src);
        // Destination Address: ::2 (or any valid IPv6 address)
        let dst = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2).octets();
        header.extend_from_slice(&dst);
        header
    }

    #[test]
    fn test_ipv6_can_parse_valid() {
        let header = create_valid_ipv6_header();
        let packet = Packet::new(header);
        let processor = Ipv6Processor;
        assert!(processor.can_parse(&packet));
    }

    #[test]
    fn test_ipv6_can_parse_invalid_short() {
        // Packet length less than the minimum IPv6 fixed header (40 bytes).
        let packet = Packet::new(vec![0; 30]);
        let processor = Ipv6Processor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_ipv6_can_parse_invalid_version() {
        let mut header = create_valid_ipv6_header();
        // Change version in the first nibble (6 -> 4)
        header[0] = (4 << 4) | (header[0] & 0x0F);
        let packet = Packet::new(header);
        let processor = Ipv6Processor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_ipv6_is_valid_valid() {
        let header = create_valid_ipv6_header();
        let packet = Packet::new(header);
        let processor = Ipv6Processor;
        // With a payload_length of 0, the header is valid.
        assert!(processor.is_valid(&packet));
    }

    #[test]
    fn test_ipv6_is_valid_invalid_payload_length() {
        let mut header = create_valid_ipv6_header();
        // Set payload length to 10 (bytes) but do not provide extra payload data.
        header[4] = 0x00;
        header[5] = 0x0A;
        // The header remains 40 bytes while the header indicates 50 bytes total.
        let packet = Packet::new(header);
        let processor = Ipv6Processor;
        assert!(!processor.is_valid(&packet));
    }
}
