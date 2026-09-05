use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RipHeader {
    pub command: u8,
    pub version: u8,
}

pub fn parse_rip_header(payload: &[u8]) -> Result<RipHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let command = header[0];
    if !(1..=5).contains(&command) {
        return Err(LayerError::InvalidHeader);
    }
    let version = header[1];
    if !matches!(version, 1 | 2) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(RipHeader { command, version })
}

/// Probes a RIP header by command and version.
///
/// RFC 2453 sec 4: commands 1 to 5, versions 1 and 2.
#[must_use]
pub fn probe_rip(payload: &[u8]) -> ProbeResult<RipHeader> {
    let Some(head) = payload.get(..2) else {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    };
    if !(1..=5).contains(&head[0]) || !matches!(head[1], 1 | 2) {
        return ProbeResult::NoMatch;
    }
    if payload.len() < HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_rip_header(payload) {
        Ok(value) => ProbeResult::Match(value),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("rip"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_rip_header;
    use crate::layer::LayerError;

    #[test]
    fn parses_rip_v1_request_header() {
        let header = parse_rip_header(&[1, 1, 0, 0]).expect("RIP request should parse");

        assert_eq!(header.command, 1);
        assert_eq!(header.version, 1);
    }

    #[test]
    fn rejects_invalid_command_version_and_short_header() {
        assert!(matches!(
            parse_rip_header(&[0, 1, 0, 0]),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_rip_header(&[1, 3, 0, 0]),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_rip_header(&[1, 1, 0]),
            Err(LayerError::InvalidLength)
        ));
    }
}
