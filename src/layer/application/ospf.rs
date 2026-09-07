use std::net::Ipv4Addr;

use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

/// RFC 2328 sec A.3.1.
const V2_HEADER_LEN: usize = 24;
/// RFC 5340 sec A.3.1 drops the authentication fields, so v3 is shorter.
const V3_HEADER_LEN: usize = 16;

/// The fixed fields v2 and v3 share sit in the first twelve bytes.
const COMMON_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfHeader {
    pub version: u8,
    pub message_type: u8,
    pub packet_length: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
}

pub fn parse_ospf_header(payload: &[u8]) -> Result<OspfHeader, LayerError> {
    let Some(header) = payload.get(..COMMON_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let version = header[0];
    let Some(header_len) = ospf_header_len(version) else {
        return Err(LayerError::InvalidHeader);
    };
    if payload.len() < header_len {
        return Err(LayerError::InvalidLength);
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

/// How long the header is for `version`, or `None` if it is not OSPF.
fn ospf_header_len(version: u8) -> Option<usize> {
    match version {
        1 | 2 => Some(V2_HEADER_LEN),
        3 => Some(V3_HEADER_LEN),
        _ => None,
    }
}

/// Probes an OSPF header by version and message type.
///
/// RFC 2328 sec A.3.1 for v2 and RFC 5340 sec A.3.1 for v3, which share the
/// five packet types. Version 1 is accepted for the same reason the parser
/// does.
#[must_use]
pub fn probe_ospf(payload: &[u8]) -> ProbeResult<OspfHeader> {
    let Some(head) = payload.get(..2) else {
        return ProbeResult::Incomplete {
            needed: Some(V3_HEADER_LEN),
            available: payload.len(),
        };
    };
    let Some(header_len) = ospf_header_len(head[0]) else {
        return ProbeResult::NoMatch;
    };
    if !(1..=5).contains(&head[1]) {
        return ProbeResult::NoMatch;
    }
    if payload.len() < header_len {
        return ProbeResult::Incomplete {
            needed: Some(header_len),
            available: payload.len(),
        };
    }

    match parse_ospf_header(payload) {
        Ok(value) => ProbeResult::Match(value),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("ospf"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{V3_HEADER_LEN, parse_ospf_header};
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
        invalid[0] = 4;
        assert!(matches!(
            parse_ospf_header(&invalid),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_ospf_header(&HELLO[..23]),
            Err(LayerError::InvalidLength)
        ));
    }

    /// RFC 5340 sec A.3.1: OSPFv3 is version 3 and its header is sixteen
    /// bytes, the authentication fields having gone. Router and area id sit
    /// where v2 keeps them.
    #[test]
    fn parses_an_ospfv3_header() {
        let mut hello = HELLO;
        hello[0] = 3;

        let header = parse_ospf_header(&hello[..V3_HEADER_LEN]).expect("v3 is sixteen bytes");
        assert_eq!(header.version, 3);
        assert_eq!(header.message_type, 1);
        assert_eq!(header.router_id, Ipv4Addr::new(192, 168, 170, 8));

        assert!(
            matches!(
                parse_ospf_header(&hello[..V3_HEADER_LEN - 1]),
                Err(LayerError::InvalidLength)
            ),
            "one byte short is still short"
        );
    }
}
