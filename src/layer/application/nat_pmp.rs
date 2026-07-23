use crate::layer::LayerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatPmpMessage {
    pub version: u8,
    pub opcode: u8,
}

pub fn parse_nat_pmp(payload: &[u8]) -> Result<NatPmpMessage, LayerError> {
    if payload.len() < 2 {
        return Err(LayerError::InvalidLength);
    }

    let version = payload[0];
    let opcode = payload[1];
    if version != 0 || !matches!(opcode, 0 | 1 | 2 | 128 | 129 | 130) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(NatPmpMessage { version, opcode })
}

#[cfg(test)]
mod tests {
    use super::{NatPmpMessage, parse_nat_pmp};
    use crate::layer::LayerError;

    #[test]
    fn parses_external_address_and_map_udp_requests() {
        assert_eq!(
            parse_nat_pmp(&[0, 0]).expect("external address request should parse"),
            NatPmpMessage {
                version: 0,
                opcode: 0,
            }
        );
        assert_eq!(
            parse_nat_pmp(&[0, 1, 0, 0, 0xa2, 0xa9, 0, 0, 0, 0, 0x1c, 0x20])
                .expect("map UDP request should parse"),
            NatPmpMessage {
                version: 0,
                opcode: 1,
            }
        );
    }

    #[test]
    fn rejects_wrong_version() {
        assert!(matches!(
            parse_nat_pmp(&[2, 0]),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_unknown_opcode() {
        assert!(matches!(
            parse_nat_pmp(&[0, 3]),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_short_payload() {
        assert!(matches!(
            parse_nat_pmp(&[0]),
            Err(LayerError::InvalidLength)
        ));
    }
}
