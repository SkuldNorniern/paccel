use crate::layer::LayerError;

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

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}
