use crate::layer::LayerError;

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
