use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PimHeader {
    pub version: u8,
    pub message_type: u8,
}

pub fn parse_pim_header(payload: &[u8]) -> Result<PimHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let version = header[0] >> 4;
    if version != 2 {
        return Err(LayerError::InvalidHeader);
    }
    let message_type = header[0] & 0x0f;
    if message_type > 8 {
        return Err(LayerError::InvalidHeader);
    }

    Ok(PimHeader {
        version,
        message_type,
    })
}

/// Probes a PIM header by version and message type.
///
/// RFC 7761 sec 4.9: the version is 2 and the types stop at 8.
#[must_use]
pub fn probe_pim(payload: &[u8]) -> ProbeResult<PimHeader> {
    let Some(head) = payload.get(..1) else {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    };
    if head[0] >> 4 != 2 || head[0] & 0x0f > 8 {
        return ProbeResult::NoMatch;
    }
    if payload.len() < HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_pim_header(payload) {
        Ok(value) => ProbeResult::Match(value),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("pim"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_pim_header;
    use crate::layer::LayerError;

    #[test]
    fn parses_pim_hello_header() {
        let header =
            parse_pim_header(&[0x20, 0x00, 0x12, 0x34]).expect("PIM hello header should parse");

        assert_eq!(header.version, 2);
        assert_eq!(header.message_type, 0);
    }

    #[test]
    fn rejects_wrong_version_and_short_header() {
        assert!(matches!(
            parse_pim_header(&[0x10, 0x00, 0x12, 0x34]),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_pim_header(&[0x20, 0x00, 0x12]),
            Err(LayerError::InvalidLength)
        ));
    }
}
