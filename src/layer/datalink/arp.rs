use std::convert::TryInto;
use std::net::Ipv4Addr;

use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// ARP operation codes.
#[derive(Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    /// For unrecognized operation codes.
    Unknown(u16),
}

impl ArpOperation {
    /// Convert a 16-bit value into an ArpOperation.
    fn from_u16(code: u16) -> Self {
        match code {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            other => ArpOperation::Unknown(other),
        }
    }

    /// Get the numeric value of the operation.
    pub fn to_u16(&self) -> u16 {
        match *self {
            ArpOperation::Request => 1,
            ArpOperation::Reply => 2,
            ArpOperation::Unknown(code) => code,
        }
    }
}

/// Represents an ARP packet as defined in RFC 826.
/// This implementation supports the most common ARP used for IPv4 over Ethernet.
/// It assumes:
/// - Hardware Type: Ethernet (1)
/// - Protocol Type: IPv4 (0x0800)
/// - Hardware Length: 6 bytes (MAC address)
/// - Protocol Length: 4 bytes (IPv4 address)
#[derive(Debug, PartialEq, Eq)]
pub struct ArpPacket {
    /// Link-layer protocol type (e.g., 1 for Ethernet).
    pub hardware_type: u16,
    /// Network-layer protocol type (e.g., 0x0800 for IPv4).
    pub protocol_type: u16,
    /// Length (in bytes) of the hardware address (typically 6 for Ethernet).
    pub hardware_len: u8,
    /// Length (in bytes) of the protocol address (typically 4 for IPv4).
    pub protocol_len: u8,
    /// ARP operation code.
    pub operation: ArpOperation,
    /// Sender hardware (MAC) address.
    pub sender_hardware_addr: [u8; 6],
    /// Sender protocol (IPv4) address.
    pub sender_protocol_addr: Ipv4Addr,
    /// Target hardware (MAC) address.
    pub target_hardware_addr: [u8; 6],
    /// Target protocol (IPv4) address.
    pub target_protocol_addr: Ipv4Addr,
}

impl ArpPacket {
    /// Serializes the ARP packet into a vector of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(28);
        bytes.extend_from_slice(&self.hardware_type.to_be_bytes());
        bytes.extend_from_slice(&self.protocol_type.to_be_bytes());
        bytes.push(self.hardware_len);
        bytes.push(self.protocol_len);
        bytes.extend_from_slice(&self.operation.to_u16().to_be_bytes());
        bytes.extend_from_slice(&self.sender_hardware_addr);
        bytes.extend_from_slice(&self.sender_protocol_addr.octets());
        bytes.extend_from_slice(&self.target_hardware_addr);
        bytes.extend_from_slice(&self.target_protocol_addr.octets());
        bytes
    }
}

/// A processor for ARP packets.
pub struct ArpProcessor;

impl ProtocolProcessor<ArpPacket> for ArpProcessor {
    fn parse(&self, packet: &mut Packet) -> Result<ArpPacket, LayerError> {
        // The minimum ARP packet must be:
        //   2 bytes (hardware type)
        // + 2 bytes (protocol type)
        // + 1 byte  (hardware length)
        // + 1 byte  (protocol length)
        // + 2 bytes (operation)
        // + hardware_len bytes (sender MAC)
        // + protocol_len bytes (sender IP)
        // + hardware_len bytes (target MAC)
        // + protocol_len bytes (target IP)
        //
        // For Ethernet/IPv4, this totals 2+2+1+1+2+6+4+6+4 = 28 bytes.
        if packet.packet.len() < 28 {
            return Err(LayerError::InvalidLength);
        }

        let hardware_type = u16::from_be_bytes([packet.packet[0], packet.packet[1]]);
        let protocol_type = u16::from_be_bytes([packet.packet[2], packet.packet[3]]);
        let hardware_len = packet.packet[4];
        let protocol_len = packet.packet[5];
        let operation_code = u16::from_be_bytes([packet.packet[6], packet.packet[7]]);
        let operation = ArpOperation::from_u16(operation_code);

        // We support only Ethernet/IPv4 here.
        if hardware_len != 6 || protocol_len != 4 {
            return Err(LayerError::InvalidHeader);
        }

        let expected_len = 8
            + (hardware_len as usize)
            + (protocol_len as usize)
            + (hardware_len as usize)
            + (protocol_len as usize);
        if packet.packet.len() < expected_len {
            return Err(LayerError::InvalidLength);
        }

        // Calculate slice indices for each address field.
        let sender_hw_start = 8;
        let sender_hw_end = sender_hw_start + 6; // hardware_len = 6
        let sender_proto_start = sender_hw_end;
        let sender_proto_end = sender_proto_start + 4; // protocol_len = 4
        let target_hw_start = sender_proto_end;
        let target_hw_end = target_hw_start + 6;
        let target_proto_start = target_hw_end;
        let _target_proto_end = target_proto_start + 4;

        // Use try_into() to convert slices to fixed-size arrays.
        // This is safe here because we have already ensured the slice lengths match.
        let sender_hardware_addr: [u8; 6] = packet.packet[sender_hw_start..sender_hw_end]
            .try_into()
            .expect("Slice length is exactly 6, as verified above");
        let sender_protocol_addr = Ipv4Addr::new(
            packet.packet[sender_proto_start],
            packet.packet[sender_proto_start + 1],
            packet.packet[sender_proto_start + 2],
            packet.packet[sender_proto_start + 3],
        );
        let target_hardware_addr: [u8; 6] = packet.packet[target_hw_start..target_hw_end]
            .try_into()
            .expect("Slice length is exactly 6, as verified above");
        let target_protocol_addr = Ipv4Addr::new(
            packet.packet[target_proto_start],
            packet.packet[target_proto_start + 1],
            packet.packet[target_proto_start + 2],
            packet.packet[target_proto_start + 3],
        );

        Ok(ArpPacket {
            hardware_type,
            protocol_type,
            hardware_len,
            protocol_len,
            operation,
            sender_hardware_addr,
            sender_protocol_addr,
            target_hardware_addr,
            target_protocol_addr,
        })
    }

    fn can_parse(&self, packet: &Packet) -> bool {
        // ARP packets must be at least 28 bytes long for IPv4 over Ethernet
        if packet.packet.len() < 28 {
            return false;
        }
        
        // Check hardware type (must be 1 for Ethernet)
        // and protocol type (must be 0x0800 for IPv4)
        let hw_type = u16::from_be_bytes([packet.packet[0], packet.packet[1]]);
        let proto_type = u16::from_be_bytes([packet.packet[2], packet.packet[3]]);
        
        hw_type == 1 && proto_type == 0x0800
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        // Check minimum length and basic field validity
        if packet.packet.len() < 28 {
            return false;
        }

        // Verify hardware length (must be 6 for Ethernet MAC)
        // and protocol length (must be 4 for IPv4)
        let hw_len = packet.packet[4];
        let proto_len = packet.packet[5];
        
        hw_len == 6 && proto_len == 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use std::net::Ipv4Addr;

    /// Helper to create a sample ARP request packet (28 bytes) for Ethernet/IPv4.
    fn create_sample_arp_request() -> Vec<u8> {
        // ARP Request field values:
        // Hardware Type: 1 (Ethernet)
        // Protocol Type: 0x0800 (IPv4)
        // Hardware Length: 6, Protocol Length: 4
        // Operation: 1 (Request)
        // Sender MAC: 00:11:22:33:44:55
        // Sender IP: 192.168.0.1
        // Target MAC: 00:00:00:00:00:00 (unknown)
        // Target IP: 192.168.0.2
        let hardware_type = 1u16;
        let protocol_type = 0x0800u16;
        let hardware_len = 6u8;
        let protocol_len = 4u8;
        let operation = 1u16; // Request
        let sender_hardware_addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender_protocol_addr = Ipv4Addr::new(192, 168, 0, 1).octets();
        let target_hardware_addr = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let target_protocol_addr = Ipv4Addr::new(192, 168, 0, 2).octets();

        let mut packet = Vec::with_capacity(28);
        packet.extend_from_slice(&hardware_type.to_be_bytes());
        packet.extend_from_slice(&protocol_type.to_be_bytes());
        packet.push(hardware_len);
        packet.push(protocol_len);
        packet.extend_from_slice(&operation.to_be_bytes());
        packet.extend_from_slice(&sender_hardware_addr);
        packet.extend_from_slice(&sender_protocol_addr);
        packet.extend_from_slice(&target_hardware_addr);
        packet.extend_from_slice(&target_protocol_addr);
        packet
    }

    /// Helper to create a sample ARP reply packet (28 bytes) for Ethernet/IPv4.
    fn create_sample_arp_reply() -> Vec<u8> {
        // ARP Reply field values:
        // Hardware Type: 1 (Ethernet)
        // Protocol Type: 0x0800 (IPv4)
        // Hardware Length: 6, Protocol Length: 4
        // Operation: 2 (Reply)
        // Sender MAC: 66:77:88:99:aa:bb
        // Sender IP: 192.168.0.2
        // Target MAC: 00:11:22:33:44:55
        // Target IP: 192.168.0.1
        let hardware_type = 1u16;
        let protocol_type = 0x0800u16;
        let hardware_len = 6u8;
        let protocol_len = 4u8;
        let operation = 2u16; // Reply
        let sender_hardware_addr = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let sender_protocol_addr = Ipv4Addr::new(192, 168, 0, 2).octets();
        let target_hardware_addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let target_protocol_addr = Ipv4Addr::new(192, 168, 0, 1).octets();

        let mut packet = Vec::with_capacity(28);
        packet.extend_from_slice(&hardware_type.to_be_bytes());
        packet.extend_from_slice(&protocol_type.to_be_bytes());
        packet.push(hardware_len);
        packet.push(protocol_len);
        packet.extend_from_slice(&operation.to_be_bytes());
        packet.extend_from_slice(&sender_hardware_addr);
        packet.extend_from_slice(&sender_protocol_addr);
        packet.extend_from_slice(&target_hardware_addr);
        packet.extend_from_slice(&target_protocol_addr);
        packet
    }

    #[test]
    fn test_parse_arp_request() {
        let payload = create_sample_arp_request();
        let mut packet = Packet {
            packet: payload,
            payload: vec![],
        };
        let processor = ArpProcessor;
        let arp_packet = processor
            .parse(&mut packet)
            .expect("ARP Request should parse successfully");
        assert_eq!(arp_packet.hardware_type, 1);
        assert_eq!(arp_packet.protocol_type, 0x0800);
        assert_eq!(arp_packet.hardware_len, 6);
        assert_eq!(arp_packet.protocol_len, 4);
        assert_eq!(arp_packet.operation, ArpOperation::Request);
        assert_eq!(
            arp_packet.sender_hardware_addr,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert_eq!(
            arp_packet.sender_protocol_addr,
            Ipv4Addr::new(192, 168, 0, 1)
        );
        assert_eq!(
            arp_packet.target_hardware_addr,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            arp_packet.target_protocol_addr,
            Ipv4Addr::new(192, 168, 0, 2)
        );
    }

    #[test]
    fn test_parse_arp_reply() {
        let payload = create_sample_arp_reply();
        let mut packet = Packet {
            packet: payload,
            payload: vec![],
        };
        let processor = ArpProcessor;
        let arp_packet = processor
            .parse(&mut packet)
            .expect("ARP Reply should parse successfully");
        assert_eq!(arp_packet.hardware_type, 1);
        assert_eq!(arp_packet.protocol_type, 0x0800);
        assert_eq!(arp_packet.hardware_len, 6);
        assert_eq!(arp_packet.protocol_len, 4);
        assert_eq!(arp_packet.operation, ArpOperation::Reply);
        assert_eq!(
            arp_packet.sender_hardware_addr,
            [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]
        );
        assert_eq!(
            arp_packet.sender_protocol_addr,
            Ipv4Addr::new(192, 168, 0, 2)
        );
        assert_eq!(
            arp_packet.target_hardware_addr,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert_eq!(
            arp_packet.target_protocol_addr,
            Ipv4Addr::new(192, 168, 0, 1)
        );
    }

    #[test]
    fn test_invalid_length() {
        // Create a packet that is too short.
        let mut packet = Packet {
            packet: vec![0u8; 10],
            payload: vec![],
        };
        let processor = ArpProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                LayerError::InvalidLength => {}
                _ => panic!("Expected InvalidLength error, got {:?}", e),
            }
        }
    }

    #[test]
    fn test_invalid_header_fields() {
        // Create a valid ARP request then modify hardware_len to an unsupported value.
        let mut packet = create_sample_arp_request();
        packet[4] = 5; // Invalid: should be 6.
        let mut pkt = Packet {
            packet,
            payload: vec![],
        };
        let processor = ArpProcessor;
        let result = processor.parse(&mut pkt);
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                LayerError::InvalidHeader => {}
                _ => panic!("Expected InvalidHeader error, got {:?}", e),
            }
        }
    }

    /// Helper function to create a valid ARP packet
    fn create_test_arp_packet() -> Packet {
        let mut packet = vec![
            0x00, 0x01,             // Hardware type: Ethernet (1)
            0x08, 0x00,             // Protocol type: IPv4 (0x0800)
            0x06,                   // Hardware length: 6
            0x04,                   // Protocol length: 4
            0x00, 0x01,             // Operation: Request (1)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // Sender MAC
            192, 168, 1, 100,       // Sender IP
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // Target MAC
            192, 168, 1, 1,         // Target IP
        ];
        Packet {
            packet,
            payload: vec![],
        }
    }

    #[test]
    fn test_can_parse_valid_packet() {
        let packet = create_test_arp_packet();
        let processor = ArpProcessor;
        assert!(processor.can_parse(&packet));
    }

    #[test]
    fn test_can_parse_invalid_length() {
        let packet = Packet {
            packet: vec![0; 27],  // Too short for ARP
            payload: vec![],
        };
        let processor = ArpProcessor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_can_parse_invalid_hardware_type() {
        let mut packet = create_test_arp_packet();
        // Set hardware type to 2 (invalid for our implementation)
        packet.packet[1] = 2;
        let processor = ArpProcessor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_can_parse_invalid_protocol_type() {
        let mut packet = create_test_arp_packet();
        // Set protocol type to invalid value
        packet.packet[2] = 0x00;
        packet.packet[3] = 0x01;
        let processor = ArpProcessor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_is_valid_good_packet() {
        let packet = create_test_arp_packet();
        let processor = ArpProcessor;
        assert!(processor.is_valid(&packet));
    }

    #[test]
    fn test_is_valid_invalid_hardware_length() {
        let mut packet = create_test_arp_packet();
        // Set hardware length to invalid value
        packet.packet[4] = 5;
        let processor = ArpProcessor;
        assert!(!processor.is_valid(&packet));
    }

    #[test]
    fn test_is_valid_invalid_protocol_length() {
        let mut packet = create_test_arp_packet();
        // Set protocol length to invalid value
        packet.packet[5] = 6;
        let processor = ArpProcessor;
        assert!(!processor.is_valid(&packet));
    }

    #[test]
    fn test_parse_valid_request() {
        let mut packet = create_test_arp_packet();
        let processor = ArpProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_ok());
        
        if let Ok(arp_packet) = result {
            assert_eq!(arp_packet.operation, ArpOperation::Request);
            assert_eq!(
                arp_packet.sender_hardware_addr, 
                [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
            );
            assert_eq!(
                arp_packet.sender_protocol_addr,
                Ipv4Addr::new(192, 168, 1, 100)
            );
            assert_eq!(
                arp_packet.target_hardware_addr,
                [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
            );
            assert_eq!(
                arp_packet.target_protocol_addr,
                Ipv4Addr::new(192, 168, 1, 1)
            );
        }
    }

    #[test]
    fn test_parse_valid_reply() {
        let mut packet = create_test_arp_packet();
        // Change operation to Reply (2)
        packet.packet[7] = 2;
        let processor = ArpProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_ok());
        
        if let Ok(arp_packet) = result {
            assert_eq!(arp_packet.operation, ArpOperation::Reply);
        }
    }

    #[test]
    fn test_parse_invalid_operation() {
        let mut packet = create_test_arp_packet();
        // Set operation to invalid value
        packet.packet[7] = 5;
        let processor = ArpProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_ok());
        
        if let Ok(arp_packet) = result {
            assert!(matches!(arp_packet.operation, ArpOperation::Unknown(x) if x == 5));
        }
    }

    #[test]
    fn test_parse_truncated_packet() {
        let mut packet = create_test_arp_packet();
        packet.packet.truncate(27); // Make packet too short
        let processor = ArpProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::InvalidLength)));
    }
}
