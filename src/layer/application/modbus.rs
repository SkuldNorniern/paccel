use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const MBAP_HEADER_LEN: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModbusMessage {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function_code: u8,
    pub is_exception: bool,
}

pub fn parse_modbus_message(payload: &[u8]) -> Result<ModbusMessage, LayerError> {
    let Some(header) = payload.get(..MBAP_HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };

    let transaction_id = u16::from_be_bytes([header[0], header[1]]);
    let protocol_id = u16::from_be_bytes([header[2], header[3]]);
    if protocol_id != 0 {
        return Err(LayerError::InvalidHeader);
    }

    let function_code = *payload
        .get(MBAP_HEADER_LEN)
        .ok_or(LayerError::InvalidLength)?;

    Ok(ModbusMessage {
        transaction_id,
        unit_id: header[6],
        function_code: function_code & 0x7f,
        is_exception: function_code & 0x80 != 0,
    })
}

/// Probes a Modbus/TCP message using the MBAP header's protocol ID field
/// (must be 0) as the structural signal - the only real check
/// `parse_modbus_message` itself makes before delegating to the caller.
#[must_use]
pub fn probe_modbus(payload: &[u8]) -> ProbeResult<ModbusMessage> {
    let Some(header) = payload.get(..MBAP_HEADER_LEN) else {
        return ProbeResult::Incomplete {
            needed: Some(MBAP_HEADER_LEN + 1),
            available: payload.len(),
        };
    };
    let protocol_id = u16::from_be_bytes([header[2], header[3]]);
    if protocol_id != 0 {
        return ProbeResult::NoMatch;
    }
    match parse_modbus_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(LayerError::InvalidLength) => ProbeResult::Incomplete {
            needed: Some(MBAP_HEADER_LEN + 1),
            available: payload.len(),
        },
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("modbus"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_modbus_message, probe_modbus};
    use crate::layer::{LayerError, ProbeResult};

    #[test]
    fn parses_read_input_registers_request() {
        let payload = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xff, 0x04, 0x08, 0xd2, 0x00, 0x02,
        ];
        let msg = parse_modbus_message(&payload).expect("modbus message should parse");
        assert_eq!(msg.transaction_id, 0);
        assert_eq!(msg.unit_id, 0xff);
        assert_eq!(msg.function_code, 4);
        assert!(!msg.is_exception);
    }

    #[test]
    fn detects_exception_response() {
        let payload = [0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x84, 0x02];
        let msg = parse_modbus_message(&payload).expect("exception should parse");
        assert_eq!(msg.function_code, 4);
        assert!(msg.is_exception);
    }

    #[test]
    fn rejects_nonzero_protocol_id() {
        let payload = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0xff, 0x04, 0x08, 0xd2, 0x00, 0x02,
        ];
        assert!(matches!(
            parse_modbus_message(&payload),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_short_payload() {
        assert!(matches!(
            parse_modbus_message(&[0x00; 5]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn probe_matches_a_real_request() {
        let payload = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xff, 0x04, 0x08, 0xd2, 0x00, 0x02,
        ];
        assert!(matches!(probe_modbus(&payload), ProbeResult::Match(_)));
    }

    #[test]
    fn probe_reports_incomplete_for_a_short_payload() {
        assert_eq!(
            probe_modbus(&[0x00; 5]),
            ProbeResult::Incomplete {
                needed: Some(8),
                available: 5,
            }
        );
    }

    #[test]
    fn probe_reports_no_match_for_nonzero_protocol_id() {
        let payload = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0xff, 0x04, 0x08, 0xd2, 0x00, 0x02,
        ];
        assert_eq!(probe_modbus(&payload), ProbeResult::NoMatch);
    }
}
