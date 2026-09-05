use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessage {
    Request {
        method: String,
        uri: String,
        version: String,
        headers: Vec<(String, String)>,
        call_id: Option<String>,
    },
    Response {
        version: String,
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
        call_id: Option<String>,
    },
}

pub fn parse_sip(payload: &[u8]) -> Result<SipMessage, LayerError> {
    let start_line_end = find_crlf(payload).ok_or(LayerError::InvalidLength)?;
    let start_line = String::from_utf8_lossy(&payload[..start_line_end]);
    let mut headers = Vec::new();
    let mut offset = start_line_end + 2;

    while offset < payload.len() {
        let remaining = &payload[offset..];
        let Some(line_end) = find_crlf(remaining) else {
            break;
        };
        if line_end == 0 {
            break;
        }

        let line = String::from_utf8_lossy(&remaining[..line_end]);
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
        offset += line_end + 2;
    }

    if start_line.starts_with("SIP/2.0") {
        parse_response_start_line(&start_line, headers)
    } else {
        parse_request_start_line(&start_line, headers)
    }
}

fn parse_request_start_line(
    start_line: &str,
    headers: Vec<(String, String)>,
) -> Result<SipMessage, LayerError> {
    let mut fields = start_line.split_whitespace();
    let method = fields.next().ok_or(LayerError::InvalidHeader)?;
    let uri = fields.next().ok_or(LayerError::InvalidHeader)?;
    let version = fields.next().ok_or(LayerError::InvalidHeader)?;
    if fields.next().is_some()
        || !matches!(
            method,
            "INVITE"
                | "ACK"
                | "BYE"
                | "CANCEL"
                | "REGISTER"
                | "OPTIONS"
                | "PRACK"
                | "SUBSCRIBE"
                | "NOTIFY"
                | "PUBLISH"
                | "INFO"
                | "REFER"
                | "MESSAGE"
                | "UPDATE"
        )
        || version != "SIP/2.0"
    {
        return Err(LayerError::InvalidHeader);
    }

    let call_id = find_call_id(&headers);
    Ok(SipMessage::Request {
        method: method.to_string(),
        uri: uri.to_string(),
        version: version.to_string(),
        headers,
        call_id,
    })
}

fn parse_response_start_line(
    start_line: &str,
    headers: Vec<(String, String)>,
) -> Result<SipMessage, LayerError> {
    let mut fields = start_line.splitn(3, ' ');
    let version = fields.next().ok_or(LayerError::InvalidHeader)?;
    let status_text = fields.next().ok_or(LayerError::InvalidHeader)?;
    let reason = fields.next().unwrap_or_default();
    if version != "SIP/2.0"
        || status_text.len() != 3
        || !status_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LayerError::InvalidHeader);
    }
    let status = status_text
        .parse::<u16>()
        .map_err(|_| LayerError::InvalidHeader)?;
    let call_id = find_call_id(&headers);

    Ok(SipMessage::Response {
        version: version.to_string(),
        status,
        reason: reason.to_string(),
        headers,
        call_id,
    })
}

fn find_call_id(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Call-ID"))
        .map(|(_, value)| value.clone())
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

/// Probes a SIP message by its start line.
///
/// RFC 3261 sec 7: a response opens with `SIP/2.0` and a request ends its start
/// line with it. Requiring the version keeps SIP apart from the other
/// HTTP-shaped text protocols.
#[must_use]
pub fn probe_sip(payload: &[u8]) -> ProbeResult<SipMessage> {
    let Some(start_line_end) = find_crlf(payload) else {
        return ProbeResult::Incomplete {
            needed: None,
            available: payload.len(),
        };
    };
    let start_line = &payload[..start_line_end];
    let is_response = start_line.starts_with(b"SIP/2.0");
    let is_request = start_line.ends_with(b"SIP/2.0");
    if !is_response && !is_request {
        return ProbeResult::NoMatch;
    }

    match parse_sip(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("sip"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{SipMessage, parse_sip};

    #[test]
    fn parses_invite_request() {
        let payload = b"INVITE sip:test@10.0.2.15:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.2.15\r\nCall-ID: call-123\r\nContent-Length: 0\r\n\r\n";
        let message = parse_sip(payload).expect("valid SIP request");

        assert!(matches!(message, SipMessage::Request { .. }));
        if let SipMessage::Request {
            method,
            uri,
            version,
            headers,
            call_id,
        } = message
        {
            assert_eq!(method, "INVITE");
            assert_eq!(uri, "sip:test@10.0.2.15:5060");
            assert_eq!(version, "SIP/2.0");
            assert_eq!(call_id.as_deref(), Some("call-123"));
            assert_eq!(headers.len(), 3);
        }
    }

    #[test]
    fn parses_trying_response() {
        let payload = b"SIP/2.0 100 Trying\r\nCall-ID: call-123\r\nContent-Length: 0\r\n\r\n";
        let message = parse_sip(payload).expect("valid SIP response");

        assert!(matches!(message, SipMessage::Response { .. }));
        if let SipMessage::Response { status, reason, .. } = message {
            assert_eq!(status, 100);
            assert_eq!(reason, "Trying");
        }
    }

    #[test]
    fn rejects_non_sip_payload() {
        assert!(parse_sip(b"HELLO world\r\n\r\n").is_err());
    }
}
