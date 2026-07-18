use crate::layer::LayerError;

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

#[cfg(test)]
mod tests {
    use super::parse_modbus_message;
    use crate::layer::LayerError;

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
}
