use super::{ChecksumAccumulator, Encode, EncodeError, PseudoHeader, WriteCursor};

/// An ICMP header, RFC 792, or an ICMPv6 one, RFC 4443.
///
/// The four bytes after the checksum mean different things per type, so they
/// are carried as `rest`: an echo puts its identifier and sequence there, a
/// destination-unreachable leaves them zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub rest: u32,
    pub checksum: u16,
}

impl IcmpHeader {
    pub fn new(icmp_type: u8, code: u8) -> Self {
        Self {
            icmp_type,
            code,
            rest: 0,
            checksum: 0,
        }
    }

    pub fn echo_request(identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type: 8,
            code: 0,
            rest: (u32::from(identifier) << 16) | u32::from(sequence),
            checksum: 0,
        }
    }

    /// The checksum over this header and `payload`.
    ///
    /// RFC 792 sums the ICMP message alone. RFC 4443 sec 2.3 puts a
    /// pseudo-header in front of it, so ICMPv6 passes one and ICMP does not.
    pub fn checksum_over(
        &self,
        pseudo: Option<PseudoHeader>,
        payload: &[u8],
    ) -> Result<u16, EncodeError> {
        let mut sum = ChecksumAccumulator::new();
        if let Some(pseudo) = pseudo {
            pseudo.add_to(&mut sum)?;
        }
        sum.add_u16(u16::from_be_bytes([self.icmp_type, self.code]));
        sum.add_u32(self.rest);
        sum.add_bytes(payload);
        Ok(sum.finish())
    }
}

impl Encode for IcmpHeader {
    fn encoded_len(&self) -> usize {
        8
    }

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let mut cursor = WriteCursor::new(buffer);
        cursor.write_u8(self.icmp_type)?;
        cursor.write_u8(self.code)?;
        cursor.write_u16_be(self.checksum)?;
        cursor.write_u32_be(self.rest)?;
        Ok(cursor.position())
    }
}
