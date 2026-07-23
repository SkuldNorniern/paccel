use crate::layer::LayerError;

const HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EigrpHeader {
    pub version: u8,
    pub opcode: u8,
    pub as_number: u16,
}

pub fn parse_eigrp_header(payload: &[u8]) -> Result<EigrpHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    if header[0] != 2 || !matches!(header[1], 1 | 3 | 4 | 5 | 10 | 11) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(EigrpHeader {
        version: header[0],
        opcode: header[1],
        as_number: u16::from_be_bytes([header[18], header[19]]),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_eigrp_header;
    use crate::layer::LayerError;

    #[test]
    fn parses_hello_header() {
        let mut payload = [0; 20];
        payload[0] = 2;
        payload[1] = 5;
        payload[18..20].copy_from_slice(&100u16.to_be_bytes());

        let header = parse_eigrp_header(&payload).expect("EIGRP header should parse");

        assert_eq!(header.version, 2);
        assert_eq!(header.opcode, 5);
        assert_eq!(header.as_number, 100);
    }

    #[test]
    fn rejects_unknown_opcode_and_short_header() {
        let mut payload = [0; 20];
        payload[0] = 2;
        payload[1] = 2;
        assert!(matches!(
            parse_eigrp_header(&payload),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_eigrp_header(&payload[..19]),
            Err(LayerError::InvalidLength)
        ));
    }
}
