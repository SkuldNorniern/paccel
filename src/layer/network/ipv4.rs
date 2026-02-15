use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;
use std::net::Ipv4Addr;

/// IPv4 Header
///
/// The IPv4 header format is defined in RFC 791. A typical header looks like:
///
///   +---------------------------------------------------------------+
///   | Version (4) | IHL (4) | DSCP (6) | ECN (2)                    |
///   +---------------------------------------------------------------+
///   |                     Total Length (16)                         |
///   +---------------------------------------------------------------+
///   |                   Identification (16)                         |
///   +---------------------------------------------------------------+
///   |Flags (3)|         Fragment Offset (13)                        |
///   +---------------------------------------------------------------+
///   |   TTL (8)   |   Protocol (8)    |    Header Checksum (16)     |
///   +---------------------------------------------------------------+
///   |                   Source IP Address (32)                      |
///   +---------------------------------------------------------------+
///   |                Destination IP Address (32)                    |
///   +---------------------------------------------------------------+
///   |             Options (if IHL > 5; Variable length)             |
///   +---------------------------------------------------------------+
///
/// This module parses the above fields into the Ipv4Header struct.
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    /// IP version (should always be 4).
    pub version: u8,
    /// Internet Header Length in 32-bit words.
    pub ihl: u8,
    /// Differentiated Services Code Point.
    pub dscp: u8,
    /// Explicit Congestion Notification.
    pub ecn: u8,
    /// Total length of the packet in bytes.
    pub total_length: u16,
    /// Identification field.
    pub identification: u16,
    /// Flags (3 bits).
    pub flags: u8,
    /// Fragment offset.
    pub fragment_offset: u16,
    /// Time To Live.
    pub ttl: u8,
    /// Protocol field.
    pub protocol: u8,
    /// Header checksum.
    pub checksum: u16,
    /// Source IP address.
    pub source: Ipv4Addr,
    /// Destination IP address.
    pub destination: Ipv4Addr,
    /// Optional header options (if IHL > 5).
    pub options: Option<Vec<u8>>,
}

/// Processor handling IPv4 packet parsing.
///
/// This implementation (based on RFC 791 and the [IPv4 article on Wikipedia](https://en.wikipedia.org/wiki/IPv4))
/// extracts:
///
///  - Version and IHL (Internet Header Length)
///  - DSCP and ECN
///  - Total Length
///  - Identification
///  - Flags and Fragment Offset
///  - TTL, Protocol, Checksum
///  - Source and Destination IP addresses
///  - Options (if present)
pub struct Ipv4Processor;

impl ProtocolProcessor<Ipv4Header> for Ipv4Processor {
    fn parse(&self, packet: &mut Packet) -> Result<Ipv4Header, LayerError> {
        // Use the correct field: `packet.packet` holds the raw bytes.
        if packet.packet.len() < 20 {
            return Err(LayerError::InvalidLength);
        }

        // Byte 0: Version and Internet Header Length (IHL).
        let first_byte = packet.packet[0];
        let version = first_byte >> 4;
        let ihl = first_byte & 0x0F;
        if version != 4 {
            return Err(LayerError::InvalidHeader); // Version mismatch.
        }
        if ihl < 5 {
            return Err(LayerError::InvalidHeader); // IHL must be at least 5.
        }
        let header_len_bytes = (ihl as usize) * 4;
        if packet.packet.len() < header_len_bytes {
            return Err(LayerError::InvalidLength);
        }

        // Byte 1: DSCP (top 6 bits) and ECN (lower 2 bits).
        let dscp = packet.packet[1] >> 2;
        let ecn = packet.packet[1] & 0x03;

        // Bytes 2-3: Total Length (16-bit, big endian).
        let total_length = u16::from_be_bytes([packet.packet[2], packet.packet[3]]);
        if packet.packet.len() < total_length as usize {
            return Err(LayerError::InvalidLength);
        }

        // Bytes 4-5: Identification.
        let identification = u16::from_be_bytes([packet.packet[4], packet.packet[5]]);

        // Bytes 6-7: Flags (top 3 bits) and Fragment Offset (lower 13 bits).
        let flags_fragment = u16::from_be_bytes([packet.packet[6], packet.packet[7]]);
        let flags = (flags_fragment >> 13) as u8;
        let fragment_offset = flags_fragment & 0x1FFF;

        // Byte 8: Time To Live.
        let ttl = packet.packet[8];
        // Byte 9: Protocol.
        let protocol = packet.packet[9];
        // Bytes 10-11: Header Checksum.
        let checksum = u16::from_be_bytes([packet.packet[10], packet.packet[11]]);

        // Bytes 12-15: Source IP address.
        let source = Ipv4Addr::new(
            packet.packet[12],
            packet.packet[13],
            packet.packet[14],
            packet.packet[15],
        );
        // Bytes 16-19: Destination IP address.
        let destination = Ipv4Addr::new(
            packet.packet[16],
            packet.packet[17],
            packet.packet[18],
            packet.packet[19],
        );

        // Options (if IHL > 5) exist in the bytes following the standard header.
        let options = if ihl > 5 {
            Some(packet.packet[20..header_len_bytes].to_vec())
        } else {
            None
        };

        Ok(Ipv4Header {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            source,
            destination,
            options,
        })
    }

    fn can_parse(&self, packet: &Packet) -> bool {
        if packet.packet.len() < 20 {
            return false;
        }

        // Check version (must be 4 for IPv4)
        let version = packet.packet[0] >> 4;
        version == 4
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        if packet.packet.len() < 20 {
            return false;
        }

        // Verify IHL (header length) is valid (>= 5)
        let ihl = packet.packet[0] & 0x0F;
        if ihl < 5 {
            return false;
        }

        // Verify total length field matches actual packet length
        let total_length = u16::from_be_bytes([packet.packet[2], packet.packet[3]]) as usize;
        if total_length > packet.packet.len() {
            return false;
        }

        // Verify header checksum
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([packet.packet[i], packet.packet[i + 1]]) as u32;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum == 0xFFFF
    }
}

/// Convenience function to parse an IPv4 packet by delegating to Ipv4Processor.
pub fn parse(packet: &mut Packet) -> Result<Ipv4Header, LayerError> {
    Ipv4Processor.parse(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    /// Test parsing a minimal valid IPv4 header (IHL = 5, no options).
    #[test]
    fn test_valid_ipv4_packet() {
        let header: [u8; 20] = [
            0x45, // Version 4, IHL 5.
            0x00, // DSCP and ECN.
            0x00, 0x14, // Total Length = 20 bytes.
            0x12, 0x34, // Identification.
            0x40, 0x00, // Flags (010) and Fragment Offset (0).
            64,   // TTL.
            6,    // Protocol (TCP).
            0x00, 0x00, // Checksum (dummy).
            192, 168, 1, 1, // Source IP: 192.168.1.1.
            192, 168, 1, 2, // Destination IP: 192.168.1.2.
        ];
        let mut packet = Packet {
            packet: header.to_vec(),
            payload: vec![],
            network_offset: 0,
        };

        let result = Ipv4Processor.parse(&mut packet);
        assert!(
            result.is_ok(),
            "Valid IPv4 packet should be parsed successfully"
        );
        let ipv4_header = result.expect("Valid IPv4 packet should be parsed successfully");

        assert_eq!(ipv4_header.version, 4);
        assert_eq!(ipv4_header.ihl, 5);
        assert_eq!(ipv4_header.dscp, 0);
        assert_eq!(ipv4_header.ecn, 0);
        assert_eq!(ipv4_header.total_length, 20);
        assert_eq!(ipv4_header.identification, 0x1234);
        assert_eq!(ipv4_header.flags, 2); // 0x40 -> binary 01000000 -> flag = 2.
        assert_eq!(ipv4_header.fragment_offset, 0);
        assert_eq!(ipv4_header.ttl, 64);
        assert_eq!(ipv4_header.protocol, 6);
        assert_eq!(ipv4_header.checksum, 0);
        assert_eq!(ipv4_header.source, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ipv4_header.destination, Ipv4Addr::new(192, 168, 1, 2));
        assert!(ipv4_header.options.is_none());
    }

    /// Test parsing an IPv4 header with options (IHL = 6).
    #[test]
    fn test_ipv4_with_options() {
        let header: [u8; 24] = [
            0x46, // Version 4, IHL 6.
            0x00, // DSCP and ECN.
            0x00, 0x18, // Total Length = 24 bytes.
            0x12, 0x34, // Identification.
            0x40, 0x00, // Flags and Fragment Offset.
            64,   // TTL.
            6,    // Protocol.
            0x00, 0x00, // Checksum.
            192, 168, 1, 1, // Source IP.
            192, 168, 1, 2, // Destination IP.
            // Options (4 bytes).
            0x01, 0x02, 0x03, 0x04,
        ];
        let mut packet = Packet {
            packet: header.to_vec(),
            payload: vec![],
            network_offset: 0,
        };

        let result = Ipv4Processor.parse(&mut packet);
        assert!(
            result.is_ok(),
            "IPv4 packet with options should be parsed successfully"
        );
        let ipv4_header = result.expect("IPv4 packet with options should be parsed successfully");

        assert_eq!(ipv4_header.ihl, 6);
        assert!(ipv4_header.options.is_some());
        assert_eq!(ipv4_header.options.unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    /// Test that a packet with an invalid version (not 4) returns an error.
    #[test]
    fn test_invalid_version() {
        let header: [u8; 20] = [
            0x65, // Version 6 (invalid for IPv4) and IHL 5.
            0x00, 0x00, 0x14, 0x12, 0x34, 0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 1, 192, 168,
            1, 2,
        ];
        let mut packet = Packet {
            packet: header.to_vec(),
            payload: vec![],
            network_offset: 0,
        };

        let result = Ipv4Processor.parse(&mut packet);
        assert!(
            result.is_err(),
            "Packet with invalid version should fail parsing"
        );
        if let Err(e) = result {
            match e {
                LayerError::InvalidHeader => {}
                _ => panic!("Expected LayerError::InvalidHeader, got {:?}", e),
            }
        }
    }

    /// Test that a packet with an IHL value less than 5 returns an error.
    #[test]
    fn test_invalid_ihl() {
        let header: [u8; 20] = [
            0x44, // Version 4 and IHL 4 (invalid; minimum is 5).
            0x00, 0x00, 0x14, 0x12, 0x34, 0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 1, 192, 168,
            1, 2,
        ];
        let mut packet = Packet {
            packet: header.to_vec(),
            payload: vec![],
            network_offset: 0,
        };

        let result = Ipv4Processor.parse(&mut packet);
        assert!(
            result.is_err(),
            "Packet with invalid IHL should fail parsing"
        );
        if let Err(e) = result {
            match e {
                LayerError::InvalidHeader => {}
                _ => panic!("Expected LayerError::InvalidHeader, got {:?}", e),
            }
        }
    }

    /// Test a header where the total length field indicates more bytes than the available packet data.
    #[test]
    fn test_invalid_total_length() {
        let header: [u8; 20] = [
            0x45, // Version 4, IHL 5.
            0x00, 0x00, 0x28, // Total Length = 40 bytes (but only 20 are provided).
            0x12, 0x34, 0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2,
        ];
        let mut packet = Packet {
            packet: header.to_vec(),
            payload: vec![],
            network_offset: 0,
        };
        let result = Ipv4Processor.parse(&mut packet);
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                LayerError::InvalidLength => {}
                _ => panic!("Expected LayerError::InvalidLength, got {:?}", e),
            }
        }
    }

    /// Helper to compute the IPv4 header checksum.
    fn compute_ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in (0..header.len()).step_by(2) {
            let word = u16::from_be_bytes([header[i], header[i + 1]]) as u32;
            sum = sum.wrapping_add(word);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Creates a minimal valid IPv4 header (20 bytes, no options).
    fn create_valid_ipv4_header() -> Vec<u8> {
        let mut header = vec![
            0x45, // Version (4) and IHL (5)
            0x00, // DSCP and ECN
            0x00, 0x14, // Total Length = 20 bytes
            0x12, 0x34, // Identification
            0x40, 0x00, // Flags (010) and Fragment Offset
            64,   // TTL
            6,    // Protocol (e.g., TCP)
            0, 0, // Checksum placeholder
            192, 168, 1, 1, // Source IP address
            192, 168, 1, 2, // Destination IP address
        ];
        let checksum = compute_ipv4_checksum(&header);
        header[10] = (checksum >> 8) as u8;
        header[11] = (checksum & 0xFF) as u8;
        header
    }

    #[test]
    fn test_ipv4_can_parse_valid() {
        let header = create_valid_ipv4_header();
        let packet = Packet {
            packet: header,
            payload: vec![],
            network_offset: 0,
        };
        let processor = Ipv4Processor;
        assert!(processor.can_parse(&packet));
    }

    #[test]
    fn test_ipv4_can_parse_invalid_short() {
        // Header is too short (less than 20 bytes).
        let packet = Packet {
            packet: vec![0x45, 0x00, 0x00, 0x14],
            payload: vec![],
            network_offset: 0,
        };
        let processor = Ipv4Processor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_ipv4_can_parse_invalid_version() {
        // Alter the version to 6 (invalid for IPv4).
        let mut header = create_valid_ipv4_header();
        header[0] = 0x65; // Version 6, IHL remains 5.
        let packet = Packet {
            packet: header,
            payload: vec![],
            network_offset: 0,
        };
        let processor = Ipv4Processor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_ipv4_is_valid_valid() {
        let header = create_valid_ipv4_header();
        let packet = Packet {
            packet: header,
            payload: vec![],
            network_offset: 0,
        };
        let processor = Ipv4Processor;
        assert!(processor.is_valid(&packet));
    }

    #[test]
    fn test_ipv4_is_valid_invalid_total_length() {
        // Modify total length to a value greater than the provided bytes.
        let mut header = create_valid_ipv4_header();
        // Set total length to 40 bytes while the header is only 20.
        header[2] = 0x00;
        header[3] = 0x28;
        let packet = Packet {
            packet: header,
            payload: vec![],
            network_offset: 0,
        };
        let processor = Ipv4Processor;
        assert!(!processor.is_valid(&packet));
    }

    #[test]
    fn test_ipv4_is_valid_invalid_checksum() {
        // Invalidate the header checksum by modifying its checksum bytes.
        let mut header = create_valid_ipv4_header();
        header[10] = 0xFF;
        header[11] = 0xFF;
        let packet = Packet {
            packet: header,
            payload: vec![],
            network_offset: 0,
        };
        let processor = Ipv4Processor;
        assert!(!processor.is_valid(&packet));
    }
}
