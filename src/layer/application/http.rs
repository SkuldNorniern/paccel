use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HTTP_METHODS: [&[u8]; 9] = [
    b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMessage {
    Request {
        method: String,
        target: String,
        version: String,
        headers: Vec<(String, String)>,
        host: Option<String>,
    },
    Response {
        version: String,
        status: u16,
        reason: String,
        headers: Vec<(String, String)>,
    },
}

pub fn parse_http(payload: &[u8]) -> Result<HttpMessage, LayerError> {
    let first = next_line(payload).ok_or(LayerError::InvalidLength)?;
    let start_line = String::from_utf8_lossy(&payload[..first.text]);
    let mut headers = Vec::new();
    let mut offset = first.next;

    while offset < payload.len() {
        let remaining = &payload[offset..];
        let Some(line) = next_line(remaining) else {
            break;
        };
        if line.text == 0 {
            break;
        }

        let text = String::from_utf8_lossy(&remaining[..line.text]);
        if let Some((name, value)) = text.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
        offset += line.next;
    }

    if start_line.starts_with("HTTP/") {
        parse_response_start_line(&start_line, headers)
    } else {
        parse_request_start_line(&start_line, headers)
    }
}

/// Probes HTTP while distinguishing an unknown start line from incomplete headers.
#[must_use]
pub fn probe_http(payload: &[u8]) -> ProbeResult<HttpMessage> {
    let request_signature = HTTP_METHODS.iter().any(|method| {
        payload.starts_with(method)
            && payload
                .get(method.len())
                .is_some_and(u8::is_ascii_whitespace)
    });
    if !request_signature && !payload.starts_with(b"HTTP/") {
        let needed = HTTP_METHODS
            .iter()
            .filter(|method| method.starts_with(payload))
            .filter_map(|method| method.len().checked_add(1))
            .chain(b"HTTP/".starts_with(payload).then_some(5))
            .min();
        return needed.map_or(ProbeResult::NoMatch, |needed| ProbeResult::Incomplete {
            needed: Some(needed),
            available: payload.len(),
        });
    }
    if !has_header_terminator(payload) {
        return ProbeResult::Incomplete {
            needed: None,
            available: payload.len(),
        };
    }

    match parse_http(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("http"),
            0,
        )),
    }
}

fn parse_request_start_line(
    start_line: &str,
    headers: Vec<(String, String)>,
) -> Result<HttpMessage, LayerError> {
    let mut fields = start_line.split_whitespace();
    let method = fields.next().ok_or(LayerError::InvalidHeader)?;
    let target = fields.next().ok_or(LayerError::InvalidHeader)?;
    let version = fields.next().ok_or(LayerError::InvalidHeader)?;
    if fields.next().is_some()
        || !matches!(
            method,
            "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
        )
        || !version.starts_with("HTTP/1.")
    {
        return Err(LayerError::InvalidHeader);
    }

    let host = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Host"))
        .map(|(_, value)| value.clone());

    Ok(HttpMessage::Request {
        method: method.to_string(),
        target: target.to_string(),
        version: version.to_string(),
        headers,
        host,
    })
}

fn parse_response_start_line(
    start_line: &str,
    headers: Vec<(String, String)>,
) -> Result<HttpMessage, LayerError> {
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

    Ok(HttpMessage::Response {
        version: version.to_string(),
        status,
        reason: reason.to_string(),
        headers,
    })
}

/// Where one line ends and the next begins.
struct Line {
    /// Length of the line's text, without its terminator.
    text: usize,
    /// Offset the following line starts at.
    next: usize,
}

fn next_line(data: &[u8]) -> Option<Line> {
    let lf = data.iter().position(|byte| *byte == b'\n')?;
    let text = if lf > 0 && data[lf - 1] == b'\r' {
        lf - 1
    } else {
        lf
    };

    Some(Line { text, next: lf + 1 })
}

/// Whether the header section is terminated: a line with no text.
fn has_header_terminator(payload: &[u8]) -> bool {
    let mut offset = 0;
    while offset < payload.len() {
        let Some(line) = next_line(&payload[offset..]) else {
            return false;
        };
        if line.text == 0 {
            return true;
        }
        offset += line.next;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::{HttpMessage, parse_http, probe_http};
    use crate::layer::ProbeResult;

    const REQUEST: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

    /// RFC 9112 sec 2.2: "Although the line terminator for the start-line and
    /// fields is the sequence CRLF, a recipient MAY recognize a single LF as a
    /// line terminator and ignore any preceding CR."
    #[test]
    fn a_request_terminated_with_bare_lf_is_recognised() {
        let request = b"GET /index.html HTTP/1.1\nHost: example.com\n\n";

        let message = parse_http(request).expect("a bare-LF request is still a request");

        assert!(
            matches!(
                &message,
                HttpMessage::Request { target, host, .. }
                    if target == "/index.html" && host.as_deref() == Some("example.com")
            ),
            "got {message:?}"
        );
    }

    #[test]
    fn probe_matches_a_real_request() {
        assert!(matches!(probe_http(REQUEST), ProbeResult::Match(_)));
    }

    #[test]
    fn probe_reports_no_match_for_an_unknown_start_line() {
        assert_eq!(
            probe_http(b"HELLO / HTTP/1.1\r\n\r\n"),
            ProbeResult::NoMatch
        );
    }

    #[test]
    fn probe_reports_incomplete_for_unterminated_headers() {
        let truncated = &REQUEST[..REQUEST.len() - 2];
        assert_eq!(
            probe_http(truncated),
            ProbeResult::Incomplete {
                needed: None,
                available: truncated.len(),
            }
        );
    }

    #[test]
    fn probe_reports_malformed_after_a_known_method() {
        assert!(matches!(
            probe_http(b"GET\r\n\r\n"),
            ProbeResult::Malformed(_)
        ));
    }
}
