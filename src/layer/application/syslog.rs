use crate::layer::LayerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogMessage {
    pub facility: u8,
    pub severity: u8,
}

pub fn parse_syslog_message(payload: &[u8]) -> Result<SyslogMessage, LayerError> {
    if payload.first() != Some(&b'<') {
        return Err(LayerError::InvalidHeader);
    }

    let closing = payload
        .iter()
        .take(5)
        .position(|byte| *byte == b'>')
        .ok_or(LayerError::InvalidHeader)?;
    let digits = &payload[1..closing];
    if digits.is_empty() || digits.len() > 3 || !digits.iter().all(|byte| byte.is_ascii_digit()) {
        return Err(LayerError::InvalidHeader);
    }

    let pri = digits
        .iter()
        .fold(0_u16, |value, digit| value * 10 + u16::from(*digit - b'0'));
    if pri > 191 {
        return Err(LayerError::InvalidHeader);
    }
    let pri = u8::try_from(pri).map_err(|_| LayerError::InvalidHeader)?;

    Ok(SyslogMessage {
        facility: pri / 8,
        severity: pri % 8,
    })
}

#[cfg(test)]
mod tests {
    use super::{SyslogMessage, parse_syslog_message};
    use crate::layer::LayerError;

    #[test]
    fn parses_valid_pri() {
        assert_eq!(
            parse_syslog_message(b"<189>message").expect("syslog message should parse"),
            SyslogMessage {
                facility: 23,
                severity: 5,
            }
        );
    }

    #[test]
    fn rejects_pri_above_rfc_maximum() {
        assert!(matches!(
            parse_syslog_message(b"<192>message"),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_missing_angle_brackets() {
        assert!(matches!(
            parse_syslog_message(b"189 message"),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_syslog_message(b"<189 message"),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_non_digit_pri() {
        assert!(matches!(
            parse_syslog_message(b"<1x>message"),
            Err(LayerError::InvalidHeader)
        ));
    }
}
