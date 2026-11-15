use super::ipv4::header_words;
use super::{ChecksumAccumulator, Encode, EncodeError, Options, PseudoHeader, WriteCursor};

/// A TCP header, RFC 9293.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u8,
    pub window: u16,
    pub urgent_pointer: u16,
    pub options: Options,
    pub payload_len: usize,
    pub checksum: u16,
}

impl TcpHeader {
    pub fn new(source_port: u16, destination_port: u16, payload_len: usize) -> Self {
        Self {
            source_port,
            destination_port,
            sequence: 0,
            acknowledgement: 0,
            flags: 0,
            window: 65535,
            urgent_pointer: 0,
            options: Options::default(),
            payload_len,
            checksum: 0,
        }
    }

    /// The checksum for this header over `payload`.
    pub fn checksum_over(&self, pseudo: PseudoHeader, payload: &[u8]) -> Result<u16, EncodeError> {
        let mut header = *self;
        header.checksum = 0;
        let mut bytes = [0u8; 60];
        let written = header.encode_into(&mut bytes)?;

        let mut sum = ChecksumAccumulator::new();
        pseudo.add_to(&mut sum)?;
        sum.add_bytes(&bytes[..written]);
        sum.add_bytes(payload);
        Ok(sum.finish())
    }
}

impl TcpHeader {
    /// Writes the header with the data-offset byte exactly as given, deriving
    /// nothing.
    ///
    /// `offset_and_reserved` is the whole byte at offset 12: the data offset in
    /// the high nibble, the four reserved bits in the low one. A data offset
    /// that disagrees with the options actually written is a known IDS evasion,
    /// so nothing here stops you writing one. `checksum` is already written
    /// from the field, so the derived encode is the only one that computes it.
    pub fn encode_raw_into(
        &self,
        buffer: &mut [u8],
        offset_and_reserved: u8,
    ) -> Result<usize, EncodeError> {
        let mut cursor = WriteCursor::new(buffer);
        self.write_fixed(&mut cursor, offset_and_reserved)?;
        Ok(cursor.position())
    }

    fn write_fixed(
        &self,
        cursor: &mut WriteCursor<'_>,
        offset_and_reserved: u8,
    ) -> Result<(), EncodeError> {
        cursor.write_u16_be(self.source_port)?;
        cursor.write_u16_be(self.destination_port)?;
        cursor.write_u32_be(self.sequence)?;
        cursor.write_u32_be(self.acknowledgement)?;
        cursor.write_u8(offset_and_reserved)?;
        cursor.write_u8(self.flags)?;
        cursor.write_u16_be(self.window)?;
        cursor.write_u16_be(self.checksum)?;
        cursor.write_u16_be(self.urgent_pointer)?;
        cursor.write_bytes(self.options.as_slice())?;
        Ok(())
    }
}

impl Encode for TcpHeader {
    fn encoded_len(&self) -> usize {
        20 + self.options.len()
    }

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let header_len = self.encoded_len();
        let mut cursor = WriteCursor::new(buffer);
        // Reserved bits zero; the options actually written set the offset.
        self.write_fixed(&mut cursor, header_words(header_len) << 4)?;
        Ok(cursor.position())
    }
}

#[cfg(test)]
mod tests {
    use super::{Encode, Options, TcpHeader};

    /// IDS testing needs a data offset that disagrees with the options really
    /// written. The raw encode writes the byte it was handed; the derived one
    /// still works the offset out for itself.
    #[test]
    fn a_raw_encode_writes_the_data_offset_it_was_given() {
        let mut header = TcpHeader::new(1234, 80, 0);
        header.options = Options::new(&[0x02, 0x04, 0x05, 0xb4]).expect("aligned");

        let mut raw = [0u8; 24];
        let written = header.encode_raw_into(&mut raw, 0xf5).expect("room");
        assert_eq!(written, 24);
        assert_eq!(raw[12], 0xf5, "fifteen words and every reserved bit set");

        let derived = header.build().expect("room");
        assert_eq!(derived[12], 6 << 4, "twenty-four bytes is six words");
        assert_eq!(derived.len(), 24);
    }
}
