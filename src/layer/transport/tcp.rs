use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// TCP Flags as defined in RFC 793
#[derive(Debug, Default)]
pub struct TcpFlags {
    pub fin: bool, // 0x01 - Finish, no more data from sender
    pub syn: bool, // 0x02 - Synchronize sequence numbers
    pub rst: bool, // 0x04 - Reset the connection
    pub psh: bool, // 0x08 - Push function
    pub ack: bool, // 0x10 - Acknowledgment field is significant
    pub urg: bool, // 0x20 - Urgent pointer field is significant
    pub ece: bool, // 0x40 - ECN-Echo
    pub cwr: bool, // 0x80 - Congestion Window Reduced
    pub ns: bool,  // 0x100 - ECN-nonce concealment protection (RFC 3540)
}

/// Represents a TCP packet header.
///
/// The TCP header format is defined in RFC 793 and consists of:
/// - Source Port (16 bits)
/// - Destination Port (16 bits)
/// - Sequence Number (32 bits)
/// - Acknowledgment Number (32 bits)
/// - Data Offset (4 bits): Size of TCP header in 32-bit words
/// - Reserved (3 bits)
/// - Flags (9 bits): NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
/// - Window Size (16 bits)
/// - Checksum (16 bits)
/// - Urgent Pointer (16 bits)
/// - Options (variable length, optional)
#[derive(Debug)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Option<Vec<u8>>,
}

/// Processor for TCP packets.
pub struct TcpProcessor;

impl ProtocolProcessor<TcpHeader> for TcpProcessor {
    fn parse(&self, packet: &mut Packet) -> Result<TcpHeader, LayerError> {
        // Minimum TCP header is 20 bytes (5 32-bit words)
        if packet.payload.len() < 20 {
            return Err(LayerError::InvalidLength);
        }

        // Extract fixed fields
        let source_port = u16::from_be_bytes([packet.payload[0], packet.payload[1]]);
        let destination_port = u16::from_be_bytes([packet.payload[2], packet.payload[3]]);
        let sequence_number = u32::from_be_bytes([
            packet.payload[4],
            packet.payload[5],
            packet.payload[6],
            packet.payload[7],
        ]);
        let acknowledgment_number = u32::from_be_bytes([
            packet.payload[8],
            packet.payload[9],
            packet.payload[10],
            packet.payload[11],
        ]);

        // Extract data offset and flags
        let data_offset_and_reserved = packet.payload[12];
        let data_offset = (data_offset_and_reserved >> 4) & 0x0F;

        // Validate data offset (must be at least 5)
        if data_offset < 5 {
            return Err(LayerError::InvalidHeader);
        }

        // Check if the packet is long enough for the header
        let header_length = (data_offset as usize) * 4;
        if packet.payload.len() < header_length {
            return Err(LayerError::InvalidLength);
        }

        // Extract the flags
        let flags_byte1 = packet.payload[12] & 0x01; // NS bit
        let flags_byte2 = packet.payload[13];

        let flags = TcpFlags {
            fin: (flags_byte2 & 0x01) != 0,
            syn: (flags_byte2 & 0x02) != 0,
            rst: (flags_byte2 & 0x04) != 0,
            psh: (flags_byte2 & 0x08) != 0,
            ack: (flags_byte2 & 0x10) != 0,
            urg: (flags_byte2 & 0x20) != 0,
            ece: (flags_byte2 & 0x40) != 0,
            cwr: (flags_byte2 & 0x80) != 0,
            ns: (flags_byte1 & 0x01) != 0,
        };

        let window_size = u16::from_be_bytes([packet.payload[14], packet.payload[15]]);
        let checksum = u16::from_be_bytes([packet.payload[16], packet.payload[17]]);
        let urgent_pointer = u16::from_be_bytes([packet.payload[18], packet.payload[19]]);

        // Extract options if present
        let options = if header_length > 20 {
            Some(packet.payload[20..header_length].to_vec())
        } else {
            None
        };

        Ok(TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
        })
    }

    fn can_parse(&self, packet: &Packet) -> bool {
        // TCP header must be at least 20 bytes
        if packet.payload.len() < 20 {
            return false;
        }

        // Basic validation - check the data offset
        let data_offset = (packet.payload[12] >> 4) & 0x0F;
        if data_offset < 5 {
            return false;
        }

        // Check if the packet is long enough for the header
        let header_length = (data_offset as usize) * 4;
        packet.payload.len() >= header_length
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        if !self.can_parse(packet) {
            return false;
        }

        // Additional validations could be implemented here, such as:
        // - Checking for valid flag combinations
        // - Validating the checksum (requires IP header information for pseudo-header)

        // For now, just check that the data offset makes sense
        let data_offset = (packet.payload[12] >> 4) & 0x0F;
        let header_length = (data_offset as usize) * 4;

        packet.payload.len() >= header_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create a valid TCP packet for testing
    fn create_test_tcp_packet() -> Vec<u8> {
        let packet = vec![
            0x12, 0x34, // Source port: 4660
            0x00, 0x50, // Destination port: 80
            0x00, 0x00, 0x00, 0x01, // Sequence number: 1
            0x00, 0x00, 0x00, 0x02, // Acknowledgment number: 2
            0x50, 0x10, // Data offset: 5, Flags: ACK
            0x10, 0x00, // Window size: 4096
            0x00, 0x00, // Checksum: 0 (invalid, but good for testing)
            0x00, 0x00, // Urgent pointer: 0
            0x01, 0x02, 0x03, 0x04, // Some payload data
        ];

        packet
    }

    /// Helper function to create a TCP packet with options
    fn create_test_tcp_packet_with_options() -> Vec<u8> {
        let packet = vec![
            0x12, 0x34, // Source port: 4660
            0x00, 0x50, // Destination port: 80
            0x00, 0x00, 0x00, 0x01, // Sequence number: 1
            0x00, 0x00, 0x00, 0x02, // Acknowledgment number: 2
            0x60, 0x02, // Data offset: 6 (24 bytes), Flags: SYN
            0x20, 0x00, // Window size: 8192
            0x00, 0x00, // Checksum: 0
            0x00, 0x00, // Urgent pointer: 0
            0x02, 0x04, 0x05, 0xb4, // MSS Option: 1460
        ];

        packet
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_parse_valid_tcp() {
        let payload = create_test_tcp_packet();
        let mut packet = Packet {
            packet: vec![],
            payload,
            network_offset: 0,
        };
        let processor = TcpProcessor;

        let tcp_header = processor
            .parse(&mut packet)
            .expect("TCP packet should parse successfully");

        assert_eq!(tcp_header.source_port, 4660);
        assert_eq!(tcp_header.destination_port, 80);
        assert_eq!(tcp_header.sequence_number, 1);
        assert_eq!(tcp_header.acknowledgment_number, 2);
        assert_eq!(tcp_header.data_offset, 5);
        assert_eq!(tcp_header.window_size, 4096);
        assert!(tcp_header.flags.ack);
        assert!(!tcp_header.flags.syn);
        assert!(!tcp_header.flags.fin);
        assert!(tcp_header.options.is_none());
    }

    #[test]
    fn test_parse_tcp_with_options() {
        let payload = create_test_tcp_packet_with_options();
        let mut packet = Packet {
            packet: vec![],
            payload,
            network_offset: 0,
        };
        let processor = TcpProcessor;

        let tcp_header = processor
            .parse(&mut packet)
            .expect("TCP packet with options should parse successfully");

        assert_eq!(tcp_header.data_offset, 6);
        assert!(tcp_header.flags.syn);
        assert!(!tcp_header.flags.ack);

        // Verify that options were extracted correctly
        let options = tcp_header.options.expect("Options should be present");
        assert_eq!(options, vec![0x02, 0x04, 0x05, 0xb4]);
    }

    #[test]
    fn test_parse_invalid_data_offset() {
        let mut payload = create_test_tcp_packet();
        // Set data offset to 3 (invalid, must be at least 5)
        payload[12] = 0x30;

        let mut packet = Packet {
            packet: vec![],
            payload,
            network_offset: 0,
        };
        let processor = TcpProcessor;
        let result = processor.parse(&mut packet);

        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::InvalidHeader)));
    }

    #[test]
    fn test_short_packet() {
        // Create a packet shorter than the minimum TCP header
        let payload = vec![0, 80, 0, 80, 0, 0, 0, 1]; // Only 8 bytes
        let mut packet = Packet {
            packet: vec![],
            payload,
            network_offset: 0,
        };
        let processor = TcpProcessor;
        let result = processor.parse(&mut packet);

        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::InvalidLength)));
    }

    #[test]
    fn test_can_parse_valid() {
        let payload = create_test_tcp_packet();
        let packet = Packet {
            packet: vec![],
            payload,
            network_offset: 0,
        };
        let processor = TcpProcessor;

        assert!(processor.can_parse(&packet));
    }

    #[test]
    fn test_can_parse_invalid() {
        let mut payload = create_test_tcp_packet();
        // Set data offset to 3 (invalid, must be at least 5)
        payload[12] = 0x30;

        let packet = Packet {
            packet: vec![],
            payload,
            network_offset: 0,
        };
        let processor = TcpProcessor;

        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_is_valid() {
        let payload = create_test_tcp_packet();
        let packet = Packet {
            packet: vec![],
            payload,
            network_offset: 0,
        };
        let processor = TcpProcessor;

        assert!(processor.is_valid(&packet));
    }
}
