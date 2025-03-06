use std::convert::TryInto;
use std::str;

use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// Represents the DNS header (first 12 bytes of a DNS message).
#[derive(Debug)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authorities: u16,
    pub additionals: u16,
}

/// Represents a DNS question section.
///
/// A question comprises a queried domain name (qname), a query type (qtype)
/// and a query class (qclass). For simplicity the qname is stored as a `String`
/// (in many cases a borrowed slice might be used, but here we build an owned string
/// due to the non-contiguous layout of labels in the DNS message).
#[derive(Debug)]
pub struct DnsQuestion {
    // TASK: TODO: change the qname to a borrowed slice rather than an owned string
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Represents a parsed DNS message.
///
/// For now, this includes only the header and the question section(s).
#[derive(Debug)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    // Answers, authority, and additional sections can be added later.
}

/// Parses a domain name from the DNS message.
///
/// DNS names are represented as a sequence of labels. Each label is prefixed with
/// its length, and the sequence is terminated with a zero-length byte (0).
/// Pointers (when the high two bits are 1) are also supported as per RFC 1035.
///
/// This function returns the decoded domain name as a `String` and the position
/// in the packet immediately after the name.
///
/// Note: This implementation builds a new `String` to hold the fully qualified name.
///
/// # Errors
/// Returns `LayerError::InvalidLength` if the packet is too short, or
/// `LayerError::MalformedPacket` if the name cannot be parsed.
fn parse_domain_name(packet: &[u8], mut pos: usize) -> Result<(String, usize), LayerError> {
    let mut name = String::new();
    let mut jumped = false;
    let mut pointer_end: Option<usize> = None;
    let mut iterations = 0;
    let max_iterations = packet.len();

    loop {
        if iterations > max_iterations {
            return Err(LayerError::MalformedPacket);
        }
        if pos >= packet.len() {
            return Err(LayerError::InvalidLength);
        }

        let len = packet[pos];
        // A zero length indicates the end of the domain name.
        if len == 0 {
            pos += 1;
            break;
        }

        // Validate label length (RFC 1035: labels must be 63 characters or less)
        if len > 63 && (len & 0xC0) != 0xC0 {
            return Err(LayerError::MalformedPacket);
        }

        // Check for pointer compression:
        // Pointers have the two high-order bits set (i.e. 0xC0).
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err(LayerError::InvalidLength);
            }
            // Calculate the pointer offset (the pointer occupies two bytes).
            let b2 = packet[pos + 1];
            let pointer_offset = (((len & 0x3F) as usize) << 8) | (b2 as usize);

            // Validate pointer offset
            if pointer_offset >= pos {
                return Err(LayerError::MalformedPacket); // Forward references are invalid
            }

            // If this is the first jump, record where to resume reading.
            if !jumped {
                pointer_end = Some(pos + 2);
            }
            pos = pointer_offset;
            jumped = true;
            iterations += 1;
            continue;
        }

        // Regular label: read the length, then the label bytes.
        let label_len = len as usize;
        pos += 1;
        if pos + label_len > packet.len() {
            return Err(LayerError::InvalidLength);
        }

        let label_bytes = &packet[pos..pos + label_len];
        // Convert label bytes to &str (DNS labels are ASCII).
        let label = str::from_utf8(label_bytes).map_err(|_| LayerError::MalformedPacket)?;

        // Validate label characters (RFC 1035: letters, digits, and hyphens only)
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(LayerError::MalformedPacket);
        }

        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        pos += label_len;
        iterations += 1;
    }

    // If we had a jump, use the recorded pointer end as the final position.
    let final_pos = if jumped {
        pointer_end.ok_or(LayerError::MalformedPacket)?
    } else {
        pos
    };

    Ok((name, final_pos))
}

/// Parses a DNS question section from the packet starting at `pos`.
///
/// A question consists of the domain name followed by a 2-byte type and a 2-byte class.
///
/// # Errors
/// Returns an error if the packet is too short or the question fields are malformed.
fn parse_question(packet: &[u8], pos: usize) -> Result<(DnsQuestion, usize), LayerError> {
    let (qname, pos) = parse_domain_name(packet, pos)?;
    if pos + 4 > packet.len() {
        return Err(LayerError::InvalidLength);
    }
    let qtype = u16::from_be_bytes(
        packet[pos..pos + 2]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    let qclass = u16::from_be_bytes(
        packet[pos + 2..pos + 4]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    Ok((
        DnsQuestion {
            qname,
            qtype,
            qclass,
        },
        pos + 4,
    ))
}

/// The DNS processor implements the ProtocolProcessor trait to parse DNS messages.
///
/// Refer to the [Wikipedia article on DNS](https://en.wikipedia.org/wiki/Domain_Name_System)
/// for more on the packet format.
pub struct DnsProcessor;

impl ProtocolProcessor<DnsMessage> for DnsProcessor {
    fn parse(&self, packet: &mut Packet) -> Result<DnsMessage, LayerError> {
        // A DNS message must be at least 12 bytes long (the header size).
        if packet.packet.len() < 12 {
            return Err(LayerError::InvalidLength);
        }
        // Parse DNS header fields (all in network byte order, i.e. big-endian).
        let id = u16::from_be_bytes(
            packet.packet[0..2]
                .try_into()
                .map_err(|_| LayerError::MalformedPacket)?,
        );
        let flags = u16::from_be_bytes(
            packet.packet[2..4]
                .try_into()
                .map_err(|_| LayerError::MalformedPacket)?,
        );
        let qdcount = u16::from_be_bytes(
            packet.packet[4..6]
                .try_into()
                .map_err(|_| LayerError::MalformedPacket)?,
        );
        let ancount = u16::from_be_bytes(
            packet.packet[6..8]
                .try_into()
                .map_err(|_| LayerError::MalformedPacket)?,
        );
        let nscount = u16::from_be_bytes(
            packet.packet[8..10]
                .try_into()
                .map_err(|_| LayerError::MalformedPacket)?,
        );
        let arcount = u16::from_be_bytes(
            packet.packet[10..12]
                .try_into()
                .map_err(|_| LayerError::MalformedPacket)?,
        );

        let header = DnsHeader {
            transaction_id: id,
            flags,
            questions: qdcount,
            answers: ancount,
            authorities: nscount,
            additionals: arcount,
        };

        let mut offset = 12;
        let mut questions = Vec::with_capacity(header.questions as usize);
        // Parse each question record.
        for _ in 0..header.questions {
            let (question, new_offset) = parse_question(&packet.packet, offset)?;
            questions.push(question);
            offset = new_offset;
        }

        Ok(DnsMessage { header, questions })
    }

    fn can_parse(&self, packet: &Packet) -> bool {
        // DNS packets must be at least 12 bytes (header size)
        if packet.packet.len() < 12 {
            return false;
        }

        // Check QR bit and OPCODE (bits 7-11 of flags)
        // For a typical query/response: flags[0] should be 0x00 or 0x80
        let flags = packet.packet[2];
        (flags & 0x78) == 0 // OPCODE should be 0 for standard query/response
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        if packet.packet.len() < 12 {
            return false;
        }

        // Get the counts from the header
        let questions = u16::from_be_bytes([packet.packet[4], packet.packet[5]]) as usize;
        let answers = u16::from_be_bytes([packet.packet[6], packet.packet[7]]) as usize;
        let authorities = u16::from_be_bytes([packet.packet[8], packet.packet[9]]) as usize;
        let additionals = u16::from_be_bytes([packet.packet[10], packet.packet[11]]) as usize;

        // Verify that at least one section exists
        if questions + answers + authorities + additionals == 0 {
            return false;
        }

        // Verify that the packet is long enough to potentially contain
        // the number of records specified (rough estimate: at least 12 bytes per record)
        let minimum_length = 12 + (questions + answers + authorities + additionals) * 12;
        packet.packet.len() >= minimum_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    /// Helper function to create a valid DNS query packet
    fn create_test_dns_query() -> Packet {
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Question section: "www.example.com" Type A, Class IN
            0x03, b'w', b'w', b'w', // First label: "www"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // Second label: "example"
            0x03, b'c', b'o', b'm', // Third label: "com"
            0x00, // End of name
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        Packet::new(packet)
    }

    /// Helper function to create a valid DNS response packet
    fn create_test_dns_response() -> Packet {
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags (standard response)
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answer RRs: 1
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Question section (same as query)
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            // Answer section
            0xc0, 0x0c, // Name pointer to offset 12
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x04, // Data length: 4
            0xc0, 0xa8, 0x01, 0x01, // IP: 192.168.1.1
        ];
        Packet::new(packet)
    }

    #[test]
    fn test_can_parse_valid_query() {
        let packet = create_test_dns_query();
        let processor = DnsProcessor;
        assert!(processor.can_parse(&packet));
    }

    #[test]
    fn test_can_parse_valid_response() {
        let packet = create_test_dns_response();
        let processor = DnsProcessor;
        assert!(processor.can_parse(&packet));
    }

    #[test]
    fn test_can_parse_invalid_length() {
        let packet = Packet::new(vec![0; 11]); // Too short for DNS header
        let processor = DnsProcessor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_can_parse_invalid_opcode() {
        let mut packet = create_test_dns_query();
        // Set invalid opcode in flags
        packet.packet[2] = 0x78; // Set bits 3-6 to invalid opcode
        let processor = DnsProcessor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_is_valid_good_query() {
        let packet = create_test_dns_query();
        let processor = DnsProcessor;
        assert!(processor.is_valid(&packet));
    }

    #[test]
    fn test_is_valid_good_response() {
        let packet = create_test_dns_response();
        let processor = DnsProcessor;
        assert!(processor.is_valid(&packet));
    }

    #[test]
    fn test_is_valid_invalid_counts() {
        let mut packet = create_test_dns_query();
        // Set questions count to 0
        packet.packet[4] = 0;
        packet.packet[5] = 0;
        let processor = DnsProcessor;
        assert!(!processor.is_valid(&packet));
    }

    #[test]
    fn test_parse_valid_query() {
        let mut packet = create_test_dns_query();
        let processor = DnsProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_ok());

        if let Ok(dns_msg) = result {
            assert_eq!(dns_msg.header.transaction_id, 0x1234);
            assert_eq!(dns_msg.header.questions, 1);
            assert_eq!(dns_msg.questions.len(), 1);
            assert_eq!(dns_msg.questions[0].qname, "www.example.com");
            assert_eq!(dns_msg.questions[0].qtype, 1); // A record
            assert_eq!(dns_msg.questions[0].qclass, 1); // IN class
        }
    }

    #[test]
    fn test_parse_valid_response() {
        let mut packet = create_test_dns_response();
        let processor = DnsProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_ok());

        if let Ok(dns_msg) = result {
            assert_eq!(dns_msg.header.transaction_id, 0x1234);
            assert_eq!(dns_msg.header.questions, 1);
            assert_eq!(dns_msg.header.answers, 1);
            assert_eq!(dns_msg.questions.len(), 1);
            assert_eq!(dns_msg.questions[0].qname, "www.example.com");
        }
    }

    #[test]
    fn test_parse_truncated_packet() {
        let mut packet = create_test_dns_query();
        packet.packet.truncate(20); // Truncate in the middle of question section
        let processor = DnsProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::InvalidLength)));
    }

    #[test]
    fn test_parse_invalid_name() {
        let mut packet = create_test_dns_query();
        // Set an invalid label length
        packet.packet[12] = 64; // Too long for a single label
        let processor = DnsProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::MalformedPacket)));
    }

    #[test]
    fn test_parse_compressed_name() {
        let mut packet = create_test_dns_response();
        let processor = DnsProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_ok());
        // Verify that name compression was handled correctly
        if let Ok(dns_msg) = result {
            assert_eq!(dns_msg.questions[0].qname, "www.example.com");
        }
    }
}
