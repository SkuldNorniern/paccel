use std::net::Ipv6Addr;

use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// Represents the basic fields of an ICMPv6 header.
///
/// The layout of an ICMPv6 message is:
///
///   0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +---------------------------------------------------------------+
///   |     Type      |     Code      |           Checksum            |
///   +---------------------------------------------------------------+
///   |           Rest of Header (variable, depends on type and code)   |
///   +---------------------------------------------------------------+
///   |                       Data (variable length)                  |
///   +---------------------------------------------------------------+
///
/// Fields:
/// - `icmp_type`: The ICMPv6 message type (e.g., Echo Request is 128, Echo Reply is 129).
/// - `icmp_code`: Provides additional context for the ICMPv6 type.
/// - `checksum`: 16-bit checksum computed (using ones' complement arithmetic) over the
///               pseudo header (from the IPv6 layer) and the ICMPv6 message.
///
/// For more details, see [ICMPv6 on Wikipedia](https://en.wikipedia.org/wiki/ICMPv6).
#[derive(Debug, Default)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    // Additional fields can be added here (e.g., identifier, sequence number for Echo messages)
}

/// Processor for handling ICMPv6 packet parsing.
///
/// This implementation requires the source and destination IPv6 addresses (from the IPv6 header)
/// to compute the ICMPv6 checksum. It verifies that the packet is at least 8 bytes long,
/// extracts the type, code, and checksum fields, and validates the checksum by computing the
/// one's complement over both a pseudo header and the ICMPv6 message.
pub struct Icmpv6Processor {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl ProtocolProcessor<Icmpv6Header> for Icmpv6Processor {
    fn parse(&self, packet: &mut Packet) -> Result<Icmpv6Header, LayerError> {
        // Ensure the ICMPv6 message is at least 8 bytes.
        if packet.packet.len() < 8 {
            return Err(LayerError::InvalidLength);
        }

        // Extract the ICMPv6 type.
        let icmp_type = packet.packet[0];

        // Safely extract the code (byte 1) to avoid panics.
        let icmp_code = *packet.packet.get(1).ok_or(LayerError::InvalidLength)?;

        // Extract the checksum (bytes 2 and 3).
        let checksum = u16::from_be_bytes([packet.packet[2], packet.packet[3]]);

        // Compute the expected checksum using the pseudo header (with our IPv6 addresses)
        // and the ICMPv6 message. For a valid packet the computed checksum must be 0.
        if compute_icmpv6_checksum(&packet.packet, &self.src, &self.dst) != 0 {
            return Err(LayerError::InvalidHeader); // Checksum did not validate.
        }

        Ok(Icmpv6Header {
            icmp_type,
            icmp_code,
            checksum,
        })
    }

    fn can_parse(&self, packet: &Packet) -> bool {
        // ICMPv6 packets must be at least 8 bytes
        if packet.packet.len() < 8 {
            return false;
        }

        // ICMPv6 types are more numerous than ICMPv4
        // Common types include 1-4 (error messages), 128-129 (echo), 133-137 (NDP)
        let icmp_type = packet.packet[0];
        icmp_type <= 137
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        if packet.packet.len() < 8 {
            return false;
        }

        // Note: ICMPv6 checksum validation requires IPv6 pseudo-header
        // This is a simplified check that just verifies length and type
        let icmp_type = packet.packet[0];

        // Check if type is valid (common types: 1-4, 128-129, 133-137)
        matches!(icmp_type, 1..=4 | 128..=129 | 133..=137)
    }
}

/// Computes the ICMPv6 checksum over the pseudo header and ICMPv6 message.
///
/// The pseudo header is built from:
/// - Source Address (16 bytes)
/// - Destination Address (16 bytes)
/// - Upper-Layer Packet Length (4 bytes; the length of the ICMPv6 message)
/// - Next Header: 3 bytes of zero followed by the actual Next Header value (58 for ICMPv6)
///
/// The algorithm is as follows:
/// 1. Sum the pseudo header (interpreting every 16-bit word in network (big-endian) order).
/// 2. Sum the ICMPv6 message bytes in the same way (padding an odd trailing byte, if any).
/// 3. Fold any carry bits, then return the one's complement of the computed 16-bit sum.
///
/// For a valid ICMPv6 packet, the computed checksum should equal 0.
fn compute_icmpv6_checksum(icmpv6: &[u8], src: &Ipv6Addr, dst: &Ipv6Addr) -> u16 {
    let mut sum: u32 = 0;

    // --- Add Source Address (16 bytes) ---
    let src_octets = src.octets();
    sum = add_bytes_to_sum(&src_octets, sum);

    // --- Add Destination Address (16 bytes) ---
    let dst_octets = dst.octets();
    sum = add_bytes_to_sum(&dst_octets, sum);

    // --- Add Upper-Layer Packet Length (4 bytes) ---
    let len = (icmpv6.len() as u32).to_be_bytes();
    sum = add_bytes_to_sum(&len, sum);

    // --- Add Next Header field (4 bytes): 3 zero bytes followed by 58 ---
    let next_header = [0u8, 0u8, 0u8, 58u8];
    sum = add_bytes_to_sum(&next_header, sum);

    // --- Add the ICMPv6 message itself ---
    sum = add_bytes_to_sum(icmpv6, sum);

    // Fold any carry bits into the lower 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // The checksum is the one's complement of the computed sum.
    !(sum as u16)
}

/// Helper function to sum the bytes of a slice in 16-bit words.
///
/// For any trailing odd byte, it is treated as the high order byte of a 16-bit word.
fn add_bytes_to_sum(data: &[u8], mut sum: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }
    if let Some(&rem) = chunks.remainder().first() {
        // Treat the remaining byte as the high-order part.
        sum = sum.wrapping_add((rem as u32) << 8);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    /// Helper function to construct a valid ICMPv6 payload.
    ///
    /// This creates a minimal 8-byte ICMPv6 packet with:
    /// - Type = 128 (Echo Request)
    /// - Code = 0
    /// - Checksum set appropriately so that `compute_icmpv6_checksum` returns 0.
    fn create_valid_icmpv6_payload(src: &Ipv6Addr, dst: &Ipv6Addr) -> Vec<u8> {
        // Start with a header with the checksum field set to zero.
        let mut payload = vec![128, 0, 0, 0, 0, 0, 0, 0];
        // Compute the checksum using the pseudo header (IPv6 addresses) and the ICMPv6 message.
        let chk = compute_icmpv6_checksum(&payload, src, dst);
        // Insert the computed checksum into the ICMPv6 header.
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        // Verify the checksum over the updated payload returns 0.
        assert_eq!(compute_icmpv6_checksum(&payload, src, dst), 0);
        payload
    }

    #[test]
    fn test_valid_icmpv6() {
        let src = Ipv6Addr::LOCALHOST; // ::1
        let dst = Ipv6Addr::LOCALHOST; // ::1
        let payload = create_valid_icmpv6_payload(&src, &dst);
        let mut packet = Packet::new(payload);
        // Create the processor with the given source and destination addresses.
        let processor = Icmpv6Processor { src, dst };
        let header = processor
            .parse(&mut packet)
            .expect("Valid ICMPv6 packet should be parsed successfully");
        assert_eq!(header.icmp_type, 128);
        assert_eq!(header.icmp_code, 0);
        let expected_checksum = u16::from_be_bytes([packet.packet[2], packet.packet[3]]);
        assert_eq!(header.checksum, expected_checksum);
    }

    #[test]
    fn test_invalid_checksum() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        let mut payload = create_valid_icmpv6_payload(&src, &dst);
        // Tamper with the payload so the checksum becomes invalid (e.g., change the code).
        payload[1] = 1;
        let mut packet = Packet::new(payload);
        let processor = Icmpv6Processor { src, dst };
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
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        // Create a payload that is too short (less than 8 bytes).
        let payload = vec![128, 0, 0];
        let mut packet = Packet::new(payload);
        let processor = Icmpv6Processor { src, dst };
        let result = processor.parse(&mut packet);
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                LayerError::InvalidLength => {}
                _ => panic!("Expected LayerError::InvalidLength, got {:?}", e),
            }
        }
    }

    /// Test a valid ICMPv6 echo request with extra data appended.
    #[test]
    fn test_valid_icmpv6_with_data() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        // Start with an 8-byte header: type 128 (Echo Request) and code 0.
        let mut payload = vec![128, 0, 0, 0, 0, 0, 0, 0];
        // Append extra data.
        let extra_data = vec![10, 20, 30, 40, 50];
        payload.extend_from_slice(&extra_data);
        // Compute and insert the ICMPv6 checksum using the pseudo header.
        let chk = compute_icmpv6_checksum(&payload, &src, &dst);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        assert_eq!(compute_icmpv6_checksum(&payload, &src, &dst), 0);

        let mut packet = Packet::new(payload);
        let processor = Icmpv6Processor { src, dst };
        let header = processor
            .parse(&mut packet)
            .expect("Valid ICMPv6 packet with additional data should be parsed successfully");
        assert_eq!(header.icmp_type, 128);
        assert_eq!(header.icmp_code, 0);
    }

    /// Test that an ICMPv6 echo reply (type 129) is parsed correctly.
    #[test]
    fn test_echo_reply_icmpv6() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        // Create an 8-byte header with type 129 (Echo Reply) and code 0.
        let mut payload = vec![129, 0, 0, 0, 0, 0, 0, 0];
        let chk = compute_icmpv6_checksum(&payload, &src, &dst);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        assert_eq!(compute_icmpv6_checksum(&payload, &src, &dst), 0);

        let mut packet = Packet::new(payload);
        let processor = Icmpv6Processor { src, dst };
        let header = processor
            .parse(&mut packet)
            .expect("ICMPv6 Echo Reply should be parsed successfully");
        assert_eq!(header.icmp_type, 129);
        assert_eq!(header.icmp_code, 0);
    }
}
