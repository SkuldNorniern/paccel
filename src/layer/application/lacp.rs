use crate::layer::LayerError;

const HEADER_LEN: usize = 18;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LacpHeader {
    pub subtype: u8,
    pub version: u8,
    pub actor_port: u16,
}

pub fn parse_lacp_header(payload: &[u8]) -> Result<LacpHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    if header[0] != 1 || header[1] != 1 {
        return Err(LayerError::InvalidHeader);
    }

    Ok(LacpHeader {
        subtype: header[0],
        version: header[1],
        actor_port: u16::from_be_bytes([header[16], header[17]]),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_lacp_header;
    use crate::layer::LayerError;

    #[test]
    fn parses_actor_port() {
        let mut payload = [0; 18];
        payload[0] = 1;
        payload[1] = 1;
        payload[16..18].copy_from_slice(&18u16.to_be_bytes());

        let header = parse_lacp_header(&payload).expect("LACP header should parse");

        assert_eq!(header.subtype, 1);
        assert_eq!(header.version, 1);
        assert_eq!(header.actor_port, 18);
    }

    #[test]
    fn rejects_marker_subtype_and_short_header() {
        let mut marker = [0; 18];
        marker[0] = 2;
        marker[1] = 1;
        assert!(matches!(
            parse_lacp_header(&marker),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_lacp_header(&marker[..17]),
            Err(LayerError::InvalidLength)
        ));
    }
}
