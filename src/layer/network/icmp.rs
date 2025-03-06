use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// Represents the basic fields of an ICMP header.
///
/// The ICMP header has the following layout:
///
///   0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +---------------------------------------------------------------+
///   |     Type      |     Code      |           Checksum            |
///   +---------------------------------------------------------------+
///   |           Rest of Header (variable, depends on type and code) |
///   +---------------------------------------------------------------+
///   |                       Data (variable length)                  |
///   +---------------------------------------------------------------+
/// Fields:
/// - `icmp_type`: Specifies the type of the ICMP message.
/// - `icmp_code`: Provides additional context for the ICMP type.
/// - `checksum`: 16-bit checksum computed over the entire ICMP message.

#[derive(Debug, Default)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
}

/// Processor for handling ICMP packet parsing.
///
/// This implementation verifies that the packet contains at least 8 bytes (the minimal
/// header length), safely extracts the type, code, and checksum fields, and then validates
/// the header checksum. The checksum is calculated via the one's complement algorithm.
pub struct IcmpProcessor;

impl ProtocolProcessor<IcmpHeader> for IcmpProcessor {
    fn parse(&self, packet: &mut Packet) -> Result<IcmpHeader, LayerError> {
        // Ensure the packet payload is at least the minimum size for an ICMP header (8 bytes).
        if packet.packet.len() < 8 {
            return Err(LayerError::InvalidLength);
        }

        // Extract the ICMP type (first byte).
        let icmp_type = packet.packet[0];

        // Safely extract the ICMP code (second byte) using .get() to avoid panics.
        let icmp_code = *packet.packet.get(1).ok_or(LayerError::InvalidLength)?;

        // Extract the checksum field from bytes 2 and 3. Since we are indexing fixed positions
        // after the length check, this is safe.
        let checksum = u16::from_be_bytes([packet.packet[2], packet.packet[3]]);

        // Validate the checksum over the entire ICMP message.
        // When verifying an ICMP message, the computed checksum (via the one's complement sum) should be 0.
        if compute_checksum(&packet.packet) != 0 {
            return Err(LayerError::InvalidHeader); // Checksum mismatch.
        }

        // TODO: Extend the parsing logic if required to support additional fields for specific ICMP types,
        //       such as identifier and sequence number in echo requests or replies.

        Ok(IcmpHeader {
            icmp_type,
            icmp_code,
            checksum,
        })
    }

    fn can_parse(&self, packet: &Packet) -> bool {
        // ICMP packets must be at least 8 bytes (header size)
        if packet.packet.len() < 8 {
            return false;
        }

        // Check ICMP type (0-18 are the most common valid types)
        let icmp_type = packet.packet[0];
        icmp_type <= 18
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        if packet.packet.len() < 8 {
            return false;
        }

        // Verify ICMP checksum
        let mut sum = 0u32;
        for i in (0..packet.packet.len()).step_by(2) {
            let word = if i + 1 < packet.packet.len() {
                u16::from_be_bytes([packet.packet[i], packet.packet[i + 1]])
            } else {
                u16::from_be_bytes([packet.packet[i], 0])
            } as u32;
            sum += word;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum == 0xFFFF
    }
}

/// Computes the one's complement checksum over the provided data slice.
///
/// Algorithm:
/// 1. Interpret the data as a sequence of 16-bit big-endian words.
/// 2. Sum all words using wrapping addition.
/// 3. If there is an odd number of bytes, pad the last byte (shifted into the high-order byte).
/// 4. Fold any carry bits into the lower 16 bits.
/// 5. Return the one's complement of the final sum.
///
/// For a valid ICMP message, the computed checksum should be 0.
fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Process all complete 16-bit words.
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        // It is safe to use try_into here since each chunk is guaranteed to have exactly 2 bytes.
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }

    // If there's a remaining byte, process it as the high order byte of a 16-bit word.
    if let Some(&rem) = chunks.remainder().first() {
        sum = sum.wrapping_add((rem as u32) << 8);
    }

    // Fold the 32-bit sum to 16 bits: add the overflow bits from the upper 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Return the one's complement of the 16-bit sum.
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    /// Helper function to compute a valid ICMP payload.
    ///
    /// This creates a minimal 8-byte ICMP packet with:
    /// - type = 8 (commonly used for an echo request),
    /// - code = 0, and
    /// - checksum set appropriately so that `compute_checksum` will return 0.
    fn create_valid_icmp_payload() -> Vec<u8> {
        // Start with a header where the checksum field is zero.
        let mut payload = vec![8, 0, 0, 0, 0, 0, 0, 0];
        // Compute the checksum for the header with a zero checksum.
        let chk = compute_checksum(&payload);
        // Insert the computed checksum into the header.
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        // Verify the checksum over the updated payload returns 0.
        assert_eq!(compute_checksum(&payload), 0);
        payload
    }

    #[test]
    fn test_valid_icmp() {
        let payload = create_valid_icmp_payload();
        let mut packet = Packet::new(payload);
        let processor = IcmpProcessor;
        let icmp_header = processor
            .parse(&mut packet)
            .expect("Valid ICMP packet should be parsed successfully");
        assert_eq!(icmp_header.icmp_type, 8);
        assert_eq!(icmp_header.icmp_code, 0);
        // Compare the checksum field with the one computed from the payload.
        let expected_checksum = u16::from_be_bytes([packet.packet[2], packet.packet[3]]);
        assert_eq!(icmp_header.checksum, expected_checksum);
    }

    #[test]
    fn test_invalid_checksum() {
        // Start with a valid payload.
        let mut payload = create_valid_icmp_payload();
        // Tamper with the payload so that the checksum becomes invalid.
        payload[1] = 1; // Change the ICMP code.
        let mut packet = Packet::new(payload);
        let processor = IcmpProcessor;
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
        // Create a payload that is too short (less than 8 bytes).
        let payload = vec![8, 0, 0]; // Only 3 bytes.
        let mut packet = Packet::new(payload);
        let processor = IcmpProcessor;
        let result = processor.parse(&mut packet);
        assert!(result.is_err());
        if let Err(e) = result {
            match e {
                LayerError::InvalidLength => {}
                _ => panic!("Expected LayerError::InvalidLength, got {:?}", e),
            }
        }
    }

    /// Test a valid ICMP echo request which also includes extra data (payload beyond the 8-byte header).
    #[test]
    fn test_valid_icmp_with_data() {
        // Start with a basic 8-byte header: type 8 (echo request), code 0.
        let mut payload = vec![8, 0, 0, 0, 0, 0, 0, 0];
        // Append some extra data.
        let extra_data = vec![1, 2, 3, 4];
        payload.extend_from_slice(&extra_data);
        // Compute and insert the checksum over the full payload.
        let chk = compute_checksum(&payload);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        // Verify that the checksum now evaluates to 0.
        assert_eq!(compute_checksum(&payload), 0);

        let mut packet = Packet::new(payload);
        let processor = IcmpProcessor;
        let header = processor
            .parse(&mut packet)
            .expect("Valid ICMP packet with additional data should be parsed successfully");
        assert_eq!(header.icmp_type, 8);
        assert_eq!(header.icmp_code, 0);
    }
}
