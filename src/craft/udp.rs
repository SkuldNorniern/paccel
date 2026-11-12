use super::{ChecksumAccumulator, Encode, EncodeError, PseudoHeader, WriteCursor};

/// A UDP header, RFC 768.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload_len: usize,
    /// Left as given. [`Self::checksum_over`] works out the right value, and
    /// over IPv4 zero is legal and means "not computed".
    pub checksum: u16,
}

impl UdpHeader {
    pub fn new(source_port: u16, destination_port: u16, payload_len: usize) -> Self {
        Self {
            source_port,
            destination_port,
            payload_len,
            checksum: 0,
        }
    }

    /// The checksum for this header over `payload`.
    ///
    /// RFC 768 sends all-ones in place of a computed zero, so the value can be
    /// told apart from "not computed".
    pub fn checksum_over(&self, pseudo: PseudoHeader, payload: &[u8]) -> Result<u16, EncodeError> {
        let length = self.length()?;
        let mut sum = ChecksumAccumulator::new();
        pseudo.add_to(&mut sum)?;
        sum.add_u16(self.source_port);
        sum.add_u16(self.destination_port);
        sum.add_u16(length);
        sum.add_bytes(payload);
        Ok(match sum.finish() {
            0 => 0xffff,
            value => value,
        })
    }

    fn length(&self) -> Result<u16, EncodeError> {
        let too_long = EncodeError::PayloadTooLong {
            max: usize::from(u16::MAX) - 8,
            got: self.payload_len,
        };
        let total = self.payload_len.checked_add(8).ok_or(too_long)?;
        u16::try_from(total).map_err(|_| too_long)
    }
}

impl UdpHeader {
    /// Writes the header with `length` exactly as given rather than derived,
    /// and the checksum as the field holds it.
    pub fn encode_raw_into(&self, buffer: &mut [u8], length: u16) -> Result<usize, EncodeError> {
        let mut cursor = WriteCursor::new(buffer);
        cursor.write_u16_be(self.source_port)?;
        cursor.write_u16_be(self.destination_port)?;
        cursor.write_u16_be(length)?;
        cursor.write_u16_be(self.checksum)?;
        Ok(cursor.position())
    }
}

impl Encode for UdpHeader {
    fn encoded_len(&self) -> usize {
        8
    }

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        self.encode_raw_into(buffer, self.length()?)
    }
}
