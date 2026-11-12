use std::net::Ipv4Addr;

use super::{ChecksumAccumulator, Encode, EncodeError, Options, WriteCursor};

/// An IPv4 header, RFC 791.
///
/// `payload_len` is here because `total_length` covers the payload, and the
/// header does not own the payload bytes. A builder sets it; a caller encoding
/// a header alone sets it to whatever follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ipv4Header {
    pub dscp: u8,
    pub ecn: u8,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: Options,
    pub payload_len: usize,
}

impl Ipv4Header {
    pub fn new(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload_len: usize) -> Self {
        Self {
            dscp: 0,
            ecn: 0,
            identification: 0,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol,
            source,
            destination,
            options: Options::default(),
            payload_len,
        }
    }

    fn total_length(&self) -> Result<u16, EncodeError> {
        let too_long = EncodeError::PayloadTooLong {
            max: usize::from(u16::MAX) - self.encoded_len(),
            got: self.payload_len,
        };
        let total = self
            .encoded_len()
            .checked_add(self.payload_len)
            .ok_or(too_long)?;
        u16::try_from(total).map_err(|_| too_long)
    }

    fn flags_and_fragment(&self) -> u16 {
        let mut value = self.fragment_offset & 0x1fff;
        if self.more_fragments {
            value |= 0x2000;
        }
        if self.dont_fragment {
            value |= 0x4000;
        }
        value
    }
}

/// Header length in four-byte words, which is what the IHL and data-offset
/// fields count in. Both headers cap at sixty bytes, so this always fits.
pub(super) fn header_words(header_len: usize) -> u8 {
    u8::try_from(header_len / 4).unwrap_or(0x0f)
}

impl Ipv4Header {
    /// Writes the header with `total_length` and `checksum` exactly as given,
    /// deriving neither.
    ///
    /// The high-level encode works both out, which is what you want for a
    /// frame that should be correct. Fuzzing, IDS testing and
    /// malformed-packet research want the opposite, so this stays available.
    pub fn encode_raw_into(
        &self,
        buffer: &mut [u8],
        total_length: u16,
        checksum: u16,
    ) -> Result<usize, EncodeError> {
        let mut cursor = WriteCursor::new(buffer);
        self.write_fixed(&mut cursor, total_length, checksum)?;
        Ok(cursor.position())
    }

    fn write_fixed(
        &self,
        cursor: &mut WriteCursor<'_>,
        total_length: u16,
        checksum: u16,
    ) -> Result<(), EncodeError> {
        cursor.write_u8(0x40 | header_words(self.encoded_len()))?;
        cursor.write_u8((self.dscp << 2) | (self.ecn & 0x03))?;
        cursor.write_u16_be(total_length)?;
        cursor.write_u16_be(self.identification)?;
        cursor.write_u16_be(self.flags_and_fragment())?;
        cursor.write_u8(self.ttl)?;
        cursor.write_u8(self.protocol)?;
        cursor.write_u16_be(checksum)?;
        cursor.write_bytes(&self.source.octets())?;
        cursor.write_bytes(&self.destination.octets())?;
        cursor.write_bytes(self.options.as_slice())?;
        Ok(())
    }
}

impl Encode for Ipv4Header {
    fn encoded_len(&self) -> usize {
        20 + self.options.len()
    }

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let total_length = self.total_length()?;
        let header_len = self.encoded_len();

        // Written with a zero checksum first, because RFC 791 sums the header
        // with that field zero; the real value is patched in after.
        let mut cursor = WriteCursor::new(buffer);
        self.write_fixed(&mut cursor, total_length, 0)?;

        let mut sum = ChecksumAccumulator::new();
        sum.add_bytes(&buffer[..header_len]);
        let checksum = sum.finish();
        let mut cursor = WriteCursor::new(buffer);
        cursor.patch_u16_be(10, checksum)?;

        Ok(header_len)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{ChecksumAccumulator, Encode, EncodeError, Ipv4Header, Options};
    use crate::craft::EthernetHeader;
    use crate::craft::UdpHeader;
    use crate::engine::BuiltinPacketParser;

    #[test]
    fn a_crafted_ipv4_header_parses_back_with_a_valid_checksum() {
        let mut header = Ipv4Header::new(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 2),
            17,
            8,
        );
        header.identification = 0x1234;
        header.options = Options::new(&[1, 1, 1, 0]).expect("aligned");

        let mut frame = EthernetHeader::new([0xff; 6], [0x11; 6], 0x0800)
            .build()
            .expect("room");
        frame.extend(header.build().expect("room"));
        frame.extend([0x04, 0xd2, 0x16, 0x2e, 0x00, 0x08, 0x00, 0x00]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
        let ipv4 = parsed.ipv4.as_ref().expect("the IPv4 header");
        assert_eq!(ipv4.source, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ipv4.destination, Ipv4Addr::new(198, 51, 100, 2));
        assert_eq!(ipv4.identification, 0x1234);
        assert_eq!(ipv4.total_length, 32, "header, options and payload");
        assert_eq!(ipv4.ihl, 6, "five words plus one of options");

        // The parser keeps the checksum as written; summing the whole header
        // including it must come to zero when it is right.
        let at = parsed.network_offset.expect("where the header sits");
        let mut sum = ChecksumAccumulator::new();
        sum.add_bytes(&frame[at..at + 24]);
        assert_eq!(sum.finish(), 0, "the checksum the encoder wrote is correct");
    }

    /// Research traffic needs headers that lie. The raw encode writes the
    /// length and checksum it was handed, however wrong.
    #[test]
    fn a_raw_encode_writes_the_wrong_values_it_was_given() {
        let header = Ipv4Header::new(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
            17,
            0,
        );

        let mut raw = [0u8; 20];
        header
            .encode_raw_into(&mut raw, 0xffff, 0xdead)
            .expect("room");
        assert_eq!(u16::from_be_bytes([raw[2], raw[3]]), 0xffff);
        assert_eq!(u16::from_be_bytes([raw[10], raw[11]]), 0xdead);

        // The derived path still works out both for itself.
        let derived = header.build().expect("room");
        assert_eq!(u16::from_be_bytes([derived[2], derived[3]]), 20);
        let mut sum = ChecksumAccumulator::new();
        sum.add_bytes(&derived);
        assert_eq!(sum.finish(), 0, "the derived checksum is right");
    }

    /// Too long to describe, and too long to add up: both have to come back
    /// as the same refusal rather than wrapping or panicking.
    #[test]
    fn a_payload_past_the_length_field_is_refused() {
        let mut header = Ipv4Header::new(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 17, 0);
        for payload_len in [65_536, usize::MAX] {
            header.payload_len = payload_len;
            assert!(
                matches!(header.build(), Err(EncodeError::PayloadTooLong { .. })),
                "payload of {payload_len}"
            );
        }

        let udp = UdpHeader::new(1, 2, usize::MAX);
        assert!(matches!(
            udp.build(),
            Err(EncodeError::PayloadTooLong { .. })
        ));
    }
}
