use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoapType {
    Confirmable,
    NonConfirmable,
    Acknowledgement,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoapMessage {
    pub version: u8,
    pub message_type: CoapType,
    pub code_class: u8,
    pub code_detail: u8,
    pub message_id: u16,
}

pub fn parse_coap_message(payload: &[u8]) -> Result<CoapMessage, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };

    let version = header[0] >> 6;
    if version != 1 {
        return Err(LayerError::InvalidHeader);
    }

    let message_type = match (header[0] >> 4) & 0b11 {
        0 => CoapType::Confirmable,
        1 => CoapType::NonConfirmable,
        2 => CoapType::Acknowledgement,
        3 => CoapType::Reset,
        _ => unreachable!(),
    };

    let token_length = header[0] & 0x0f;
    if token_length > 8 {
        return Err(LayerError::InvalidHeader);
    }
    if payload.len() < HEADER_LEN + token_length as usize {
        return Err(LayerError::InvalidLength);
    }

    let code_class = header[1] >> 5;
    let code_detail = header[1] & 0x1f;
    let message_id = u16::from_be_bytes([header[2], header[3]]);

    Ok(CoapMessage {
        version,
        message_type,
        code_class,
        code_detail,
        message_id,
    })
}

/// Probes a CoAP message by version and token length.
///
/// RFC 7252 sec 3: the version is always 1 and a token longer than 8 bytes is
/// not a CoAP message.
#[must_use]
pub fn probe_coap(payload: &[u8]) -> ProbeResult<CoapMessage> {
    let Some(first) = payload.first() else {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: 0,
        };
    };
    if first >> 6 != 1 || first & 0x0f > 8 {
        return ProbeResult::NoMatch;
    }
    let message_len = HEADER_LEN + usize::from(first & 0x0f);
    if payload.len() < message_len {
        return ProbeResult::Incomplete {
            needed: Some(message_len),
            available: payload.len(),
        };
    }

    match parse_coap_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("coap"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{CoapType, parse_coap_message};
    use crate::layer::LayerError;

    #[test]
    fn parses_confirmable_post() {
        let payload = [
            0x44, 0x02, 0x0c, 0x3c, 0xd1, 0x97, 0x96, 0xc1, 0xc1, 0x3c, 0xff, 0x00,
        ];
        let msg = parse_coap_message(&payload).expect("coap message should parse");
        assert_eq!(msg.version, 1);
        assert_eq!(msg.message_type, CoapType::Confirmable);
        assert_eq!(msg.code_class, 0);
        assert_eq!(msg.code_detail, 2);
        assert_eq!(msg.message_id, 0x0c3c);
    }

    #[test]
    fn rejects_wrong_version() {
        let payload = [0x04, 0x02, 0x0c, 0x3c];
        assert!(matches!(
            parse_coap_message(&payload),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_short_payload() {
        assert!(matches!(
            parse_coap_message(&[0x40, 0x01]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_token_length_overrun() {
        let payload = [0x48, 0x01, 0x00, 0x01, 0x00, 0x00];
        assert!(matches!(
            parse_coap_message(&payload),
            Err(LayerError::InvalidLength)
        ));
    }
}
