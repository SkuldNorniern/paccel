use std::net::Ipv6Addr;

use super::{Encode, EncodeError, WriteCursor};

/// An IPv6 fixed header, RFC 8200. Extension headers are not encodable yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub payload_len: usize,
}

impl Ipv6Header {
    pub fn new(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        next_header: u8,
        payload_len: usize,
    ) -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            next_header,
            hop_limit: 64,
            source,
            destination,
            payload_len,
        }
    }
}

impl Encode for Ipv6Header {
    fn encoded_len(&self) -> usize {
        40
    }

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let payload_len =
            u16::try_from(self.payload_len).map_err(|_| EncodeError::PayloadTooLong {
                max: usize::from(u16::MAX),
                got: self.payload_len,
            })?;

        let mut cursor = WriteCursor::new(buffer);
        let lead =
            (6 << 28) | (u32::from(self.traffic_class) << 20) | (self.flow_label & 0x000f_ffff);
        cursor.write_u32_be(lead)?;
        cursor.write_u16_be(payload_len)?;
        cursor.write_u8(self.next_header)?;
        cursor.write_u8(self.hop_limit)?;
        cursor.write_bytes(&self.source.octets())?;
        cursor.write_bytes(&self.destination.octets())?;
        Ok(cursor.position())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::{Encode, Ipv6Header};
    use crate::craft::EthernetHeader;
    use crate::engine::BuiltinPacketParser;

    #[test]
    fn a_crafted_ipv6_header_parses_back() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut header = Ipv6Header::new(source, destination, 17, 8);
        header.traffic_class = 0x28;
        header.flow_label = 0x0b_cdef;

        let mut frame = EthernetHeader::new([0xff; 6], [0x11; 6], 0x86dd)
            .build()
            .expect("room");
        frame.extend(header.build().expect("room"));
        frame.extend([0x04, 0xd2, 0x16, 0x2e, 0x00, 0x08, 0x00, 0x00]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
        let ipv6 = parsed.ipv6.as_ref().expect("the IPv6 header");
        assert_eq!(ipv6.source, source);
        assert_eq!(ipv6.destination, destination);
        assert_eq!(ipv6.traffic_class, 0x28);
        assert_eq!(ipv6.flow_label, 0x0b_cdef);
        assert_eq!(ipv6.payload_length, 8);
    }
}
