use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsdpMessage {
    Request {
        method: String,
        target: String,
        version: String,
        headers: Vec<(String, String)>,
    },
    Response {
        version: String,
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
    },
}

pub fn parse_ssdp(payload: &[u8]) -> Result<SsdpMessage, LayerError> {
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

    if start_line.starts_with("HTTP/") {
        parse_response_start_line(&start_line, headers)
    } else {
        parse_request_start_line(&start_line, headers)
    }
}

fn parse_request_start_line(
    start_line: &str,
    headers: Vec<(String, String)>,
) -> Result<SsdpMessage, LayerError> {
    let mut fields = start_line.split_whitespace();
    let method = fields.next().ok_or(LayerError::InvalidHeader)?;
    let target = fields.next().ok_or(LayerError::InvalidHeader)?;
    let version = fields.next().ok_or(LayerError::InvalidHeader)?;
    if fields.next().is_some()
        || !matches!(method, "NOTIFY" | "M-SEARCH")
        || !version.starts_with("HTTP/1.")
    {
        return Err(LayerError::InvalidHeader);
    }

    Ok(SsdpMessage::Request {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        headers,
    })
}

fn parse_response_start_line(
    start_line: &str,
    headers: Vec<(String, String)>,
) -> Result<SsdpMessage, LayerError> {
    let mut fields = start_line.splitn(3, ' ');
    let version = fields.next().ok_or(LayerError::InvalidHeader)?;
    let status_text = fields.next().ok_or(LayerError::InvalidHeader)?;
    let reason = fields.next().unwrap_or_default();
    if status_text.len() != 3 || !status_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LayerError::InvalidHeader);
    }
    let status = status_text
        .parse::<u16>()
        .map_err(|_| LayerError::InvalidHeader)?;

    Ok(SsdpMessage::Response {
        version: version.to_string(),
        status,
        reason: reason.to_string(),
        headers,
    })
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

/// Probes an SSDP message by its start line.
///
/// UPnP Device Architecture sec 1: SSDP is HTTP over UDP, limited to NOTIFY and
/// M-SEARCH requests and HTTP responses. SIP is excluded by its version string,
/// which SSDP never carries.
#[must_use]
pub fn probe_ssdp(payload: &[u8]) -> ProbeResult<SsdpMessage> {
    let Some(start_line_end) = find_crlf(payload) else {
        return ProbeResult::Incomplete {
            needed: None,
            available: payload.len(),
        };
    };
    let start_line = &payload[..start_line_end];
    let looks_like_ssdp = start_line.starts_with(b"NOTIFY ")
        || start_line.starts_with(b"M-SEARCH ")
        || start_line.starts_with(b"HTTP/");
    if !looks_like_ssdp || start_line.ends_with(b"SIP/2.0") {
        return ProbeResult::NoMatch;
    }

    match parse_ssdp(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("ssdp"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{SsdpMessage, parse_ssdp};
    use crate::layer::LayerError;

    #[test]
    fn parses_msearch_request() {
        let payload = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
            ST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n";
        let message = parse_ssdp(payload).expect("M-SEARCH should parse");

        assert_eq!(
            message,
            SsdpMessage::Request {
                method: "M-SEARCH".to_string(),
                target: "*".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![
                    ("HOST".to_string(), "239.255.255.250:1900".to_string()),
                    ("ST".to_string(), "ssdp:all".to_string()),
                    ("MAN".to_string(), "\"ssdp:discover\"".to_string()),
                    ("MX".to_string(), "2".to_string()),
                ],
            }
        );
    }

    #[test]
    fn parses_response() {
        let message = parse_ssdp(b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n")
            .expect("response should parse");

        assert_eq!(
            message,
            SsdpMessage::Response {
                version: "HTTP/1.1".to_string(),
                status: 200,
                reason: "OK".to_string(),
                headers: vec![("ST".to_string(), "upnp:rootdevice".to_string())],
            }
        );
    }

    #[test]
    fn rejects_unknown_request_method() {
        assert!(matches!(
            parse_ssdp(b"GET * HTTP/1.1\r\n\r\n"),
            Err(LayerError::InvalidHeader)
        ));
    }
}
