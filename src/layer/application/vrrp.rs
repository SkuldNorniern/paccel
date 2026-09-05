use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HEADER_LEN: usize = 8;
const ADVERTISEMENT_TYPE: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrrpHeader {
    pub version: u8,
    pub packet_type: u8,
    pub virtual_router_id: u8,
    pub priority: u8,
    pub address_count: u8,
}

pub fn parse_vrrp_header(payload: &[u8]) -> Result<VrrpHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let version = header[0] >> 4;
    if !matches!(version, 2 | 3) {
        return Err(LayerError::InvalidHeader);
    }
    let packet_type = header[0] & 0x0f;
    if packet_type != ADVERTISEMENT_TYPE {
        return Err(LayerError::InvalidHeader);
    }

    Ok(VrrpHeader {
        version,
        packet_type,
        virtual_router_id: header[1],
        priority: header[2],
        address_count: header[3],
    })
}

/// Probes a VRRP header by version and packet type.
///
/// RFC 5798 sec 5.1: versions 2 and 3, and advertisement is the only type.
#[must_use]
pub fn probe_vrrp(payload: &[u8]) -> ProbeResult<VrrpHeader> {
    let Some(head) = payload.get(..1) else {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    };
    if !matches!(head[0] >> 4, 2 | 3) || head[0] & 0x0f != ADVERTISEMENT_TYPE {
        return ProbeResult::NoMatch;
    }
    if payload.len() < HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_vrrp_header(payload) {
        Ok(value) => ProbeResult::Match(value),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("vrrp"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_vrrp_header;
    use crate::layer::LayerError;

    #[test]
    fn parses_v2_advertisement() {
        let header = parse_vrrp_header(&[0x21, 1, 100, 1, 0, 1, 0x12, 0x34])
            .expect("VRRP advertisement should parse");

        assert_eq!(header.version, 2);
        assert_eq!(header.packet_type, 1);
        assert_eq!(header.virtual_router_id, 1);
        assert_eq!(header.priority, 100);
        assert_eq!(header.address_count, 1);
    }

    #[test]
    fn rejects_wrong_packet_type_and_short_header() {
        assert!(matches!(
            parse_vrrp_header(&[0x22, 1, 100, 1, 0, 1, 0x12, 0x34]),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_vrrp_header(&[0x21, 1, 100, 1, 0, 1, 0x12]),
            Err(LayerError::InvalidLength)
        ));
    }
}
