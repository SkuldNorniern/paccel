use std::net::Ipv4Addr;

use crate::layer::LayerError;

const HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfHeader {
    pub version: u8,
    pub message_type: u8,
    pub packet_length: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
}

pub fn parse_ospf_header(payload: &[u8]) -> Result<OspfHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let version = header[0];
    if !matches!(version, 1 | 2) {
        return Err(LayerError::InvalidHeader);
    }
    let message_type = header[1];
    if !(1..=5).contains(&message_type) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(OspfHeader {
        version,
        message_type,
        packet_length: u16::from_be_bytes([header[2], header[3]]),
        router_id: Ipv4Addr::new(header[4], header[5], header[6], header[7]),
        area_id: Ipv4Addr::new(header[8], header[9], header[10], header[11]),
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::parse_ospf_header;
    use crate::layer::LayerError;

    const HELLO: [u8; 24] = [
        0x02, 0x01, 0x00, 0x2c, 0xc0, 0xa8, 0xaa, 0x08, 0x00, 0x00, 0x00, 0x01, 0x27, 0x3b, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parses_ospf_hello_header() {
        let header = parse_ospf_header(&HELLO).expect("OSPF hello should parse");

        assert_eq!(header.version, 2);
        assert_eq!(header.message_type, 1);
        assert_eq!(header.packet_length, 44);
        assert_eq!(header.router_id, Ipv4Addr::new(192, 168, 170, 8));
        assert_eq!(header.area_id, Ipv4Addr::new(0, 0, 0, 1));
    }

    #[test]
    fn rejects_invalid_version_and_short_header() {
        let mut invalid = HELLO;
        invalid[0] = 3;
        assert!(matches!(
            parse_ospf_header(&invalid),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_ospf_header(&HELLO[..23]),
            Err(LayerError::InvalidLength)
        ));
    }
}
