use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

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

/// Probes a NAT-PMP message by version and opcode.
///
/// RFC 6886 sec 3: the version is 0. PCP shares port 5351 and uses version 2,
/// so the first byte is what separates them.
#[must_use]
pub fn probe_nat_pmp(payload: &[u8]) -> ProbeResult<NatPmpMessage> {
    let Some(head) = payload.get(..2) else {
        return ProbeResult::Incomplete {
            needed: Some(2),
            available: payload.len(),
        };
    };
    if head[0] != 0 || !matches!(head[1], 0 | 1 | 2 | 128 | 129 | 130) {
        return ProbeResult::NoMatch;
    }

    match parse_nat_pmp(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("nat-pmp"),
            0,
        )),
    }
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
