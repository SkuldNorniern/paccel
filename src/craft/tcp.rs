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

impl Encode for TcpHeader {
    fn encoded_len(&self) -> usize {
        20 + self.options.len()
    }

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let header_len = self.encoded_len();
        let mut cursor = WriteCursor::new(buffer);
        cursor.write_u16_be(self.source_port)?;
        cursor.write_u16_be(self.destination_port)?;
        cursor.write_u32_be(self.sequence)?;
        cursor.write_u32_be(self.acknowledgement)?;
        cursor.write_u8(header_words(header_len) << 4)?;
        cursor.write_u8(self.flags)?;
        cursor.write_u16_be(self.window)?;
        cursor.write_u16_be(self.checksum)?;
        cursor.write_u16_be(self.urgent_pointer)?;
        cursor.write_bytes(self.options.as_slice())?;
        Ok(cursor.position())
    }
}
