use crate::layer::LayerError;

const PCP_HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcpHeader {
    pub version: u8,
    pub is_response: bool,
    pub opcode: u8,
    pub lifetime: u32,
}

pub fn parse_pcp_header(payload: &[u8]) -> Result<PcpHeader, LayerError> {
    if payload.len() < PCP_HEADER_LEN {
        return Err(LayerError::InvalidLength);
    }

    let version = payload[0];
    let response_and_opcode = payload[1];
    let opcode = response_and_opcode & 0x7f;
    if version != 2 || !matches!(opcode, 0..=2) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(PcpHeader {
        version,
        is_response: response_and_opcode & 0x80 != 0,
        opcode,
        lifetime: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
    })
}

#[cfg(test)]
mod tests {
    use super::{PcpHeader, parse_pcp_header};
    use crate::layer::LayerError;

    #[test]
    fn parses_announce_request() {
        let payload = [
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0x32,
            0x05,
        ];

        assert_eq!(
            parse_pcp_header(&payload).expect("announce request should parse"),
            PcpHeader {
                version: 2,
                is_response: false,
                opcode: 0,
                lifetime: 0,
            }
        );
    }

    #[test]
    fn rejects_wrong_version() {
        let mut payload = [0; 24];
        payload[0] = 1;
        assert!(matches!(
            parse_pcp_header(&payload),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_unknown_opcode() {
        let mut payload = [0; 24];
        payload[0] = 2;
        payload[1] = 3;
        assert!(matches!(
            parse_pcp_header(&payload),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_short_payload() {
        assert!(matches!(
            parse_pcp_header(&[2; 23]),
            Err(LayerError::InvalidLength)
        ));
    }
}
