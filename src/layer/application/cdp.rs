use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdpHeader {
    pub version: u8,
    pub ttl: u8,
    pub checksum: u16,
}

pub fn parse_cdp_header(payload: &[u8]) -> Result<CdpHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    if !matches!(header[0], 1 | 2) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(CdpHeader {
        version: header[0],
        ttl: header[1],
        checksum: u16::from_be_bytes([header[2], header[3]]),
    })
}

/// Probes a CDP header by version.
#[must_use]
pub fn probe_cdp(payload: &[u8]) -> ProbeResult<CdpHeader> {
    let Some(head) = payload.get(..1) else {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    };
    if !matches!(head[0], 1 | 2) {
        return ProbeResult::NoMatch;
    }
    if payload.len() < HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_cdp_header(payload) {
        Ok(value) => ProbeResult::Match(value),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("cdp"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_cdp_header;
    use crate::layer::LayerError;

    #[test]
    fn parses_cdp_header() {
        let header = parse_cdp_header(&[1, 180, 0xc6, 0x5e]).expect("CDP header should parse");

        assert_eq!(header.version, 1);
        assert_eq!(header.ttl, 180);
        assert_eq!(header.checksum, 0xc65e);
    }

    #[test]
    fn rejects_bad_version_and_short_header() {
        assert!(matches!(
            parse_cdp_header(&[3, 180, 0xc6, 0x5e]),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_cdp_header(&[1, 180, 0xc6]),
            Err(LayerError::InvalidLength)
        ));
    }
}
