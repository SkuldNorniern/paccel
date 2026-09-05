use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HsrpHeader {
    pub version: u8,
    pub opcode: u8,
    pub state: u8,
    pub group: u8,
    pub priority: u8,
}

pub fn parse_hsrp_header(payload: &[u8]) -> Result<HsrpHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    if header[0] != 0 || !matches!(header[1], 0..=2) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(HsrpHeader {
        version: header[0],
        opcode: header[1],
        state: header[2],
        group: header[6],
        priority: header[5],
    })
}

/// Probes an HSRP header by version and opcode.
#[must_use]
pub fn probe_hsrp(payload: &[u8]) -> ProbeResult<HsrpHeader> {
    let Some(head) = payload.get(..2) else {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    };
    if head[0] != 0 || !matches!(head[1], 0..=2) {
        return ProbeResult::NoMatch;
    }
    if payload.len() < HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_hsrp_header(payload) {
        Ok(value) => ProbeResult::Match(value),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("hsrp"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_hsrp_header;
    use crate::layer::LayerError;

    #[test]
    fn parses_active_hello() {
        let mut payload = [0; 20];
        payload[2] = 16;
        payload[5] = 90;
        payload[6] = 10;

        let header = parse_hsrp_header(&payload).expect("HSRP header should parse");

        assert_eq!(header.version, 0);
        assert_eq!(header.opcode, 0);
        assert_eq!(header.state, 16);
        assert_eq!(header.group, 10);
        assert_eq!(header.priority, 90);
    }

    #[test]
    fn rejects_wrong_version_and_short_header() {
        let mut payload = [0; 20];
        payload[0] = 1;
        assert!(matches!(
            parse_hsrp_header(&payload),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_hsrp_header(&payload[..19]),
            Err(LayerError::InvalidLength)
        ));
    }
}
