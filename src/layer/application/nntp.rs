use crate::layer::{Layer, LayerError, ParseError, ProbeResult, looks_like_text_line};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NntpMessage {
    Response { code: u16, text: String },
    Command { verb: String, args: String },
}

pub fn parse_nntp(payload: &[u8]) -> Result<NntpMessage, LayerError> {
    let line_end = find_line_end(payload).unwrap_or(payload.len());
    if line_end == 0 {
        return Err(LayerError::InvalidLength);
    }
    // Lossy, not refused: the encoding of the free-text part of a line says
    // nothing about whether this is the protocol. See
    // [`crate::layer::looks_like_text_line`].
    let line = &String::from_utf8_lossy(&payload[..line_end]);

    if let Some(code) = parse_response_code(line) {
        let text = line.get(3..).unwrap_or("").trim_start().to_string();
        return Ok(NntpMessage::Response { code, text });
    }

    let mut fields = line.splitn(2, ' ');
    let verb = fields.next().unwrap_or("");
    if verb.is_empty() || verb.len() > 14 || !verb.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(LayerError::InvalidHeader);
    }
    let args = fields.next().unwrap_or("").trim().to_string();

    Ok(NntpMessage::Command {
        verb: verb.to_ascii_uppercase(),
        args,
    })
}

/// Probes an NNTP line. No magic bytes exist for NNTP - command/response
/// lines are ASCII text, so binary bytes are a real NoMatch signal.
/// `parse_nntp` treats a buffer with no line terminator as a complete line
/// (tested, intentional - see `parses_command_without_trailing_crlf`), so
/// this doesn't invent an Incomplete case beyond an empty buffer.
#[must_use]
pub fn probe_nntp(payload: &[u8]) -> ProbeResult<NntpMessage> {
    if payload.is_empty() {
        return ProbeResult::Incomplete {
            needed: None,
            available: 0,
        };
    }
    let line_end = find_line_end(payload).unwrap_or(payload.len());
    if line_end > 0 && !looks_like_text_line(&payload[..line_end]) {
        return ProbeResult::NoMatch;
    }
    match parse_nntp(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("nntp"),
            0,
        )),
    }
}

fn parse_response_code(line: &str) -> Option<u16> {
    let code_str = line.get(..3)?;
    if !code_str.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    match line.as_bytes().get(3) {
        Some(b' ') | None => code_str.parse().ok(),
        _ => None,
    }
}

fn find_line_end(payload: &[u8]) -> Option<usize> {
    payload.iter().position(|byte| *byte == b'\n').map(|pos| {
        if pos > 0 && payload[pos - 1] == b'\r' {
            pos - 1
        } else {
            pos
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{NntpMessage, parse_nntp, probe_nntp};
    use crate::layer::{LayerError, ProbeResult};

    #[test]
    fn parses_greeting_response() {
        let payload = b"200 Leafnode NNTP Daemon, version 1.11.7.rc1\r\n";
        let msg = parse_nntp(payload).expect("greeting should parse");
        assert_eq!(
            msg,
            NntpMessage::Response {
                code: 200,
                text: "Leafnode NNTP Daemon, version 1.11.7.rc1".to_string(),
            }
        );
    }

    #[test]
    fn parses_group_command() {
        let payload = b"GROUP alt.test\r\n";
        let msg = parse_nntp(payload).expect("command should parse");
        assert_eq!(
            msg,
            NntpMessage::Command {
                verb: "GROUP".to_string(),
                args: "alt.test".to_string(),
            }
        );
    }

    #[test]
    fn parses_command_without_trailing_crlf() {
        let payload = b"QUIT";
        let msg = parse_nntp(payload).expect("command should parse");
        assert_eq!(
            msg,
            NntpMessage::Command {
                verb: "QUIT".to_string(),
                args: String::new(),
            }
        );
    }

    #[test]
    fn rejects_non_alphabetic_verb() {
        assert!(matches!(
            parse_nntp(b"1x2 nope\r\n"),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_empty_line() {
        assert!(matches!(
            parse_nntp(b"\r\n"),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn probe_matches_a_response() {
        assert!(matches!(
            probe_nntp(b"200 Leafnode NNTP Daemon\r\n"),
            ProbeResult::Match(_)
        ));
    }

    #[test]
    fn probe_reports_incomplete_for_an_empty_buffer() {
        assert_eq!(
            probe_nntp(b""),
            ProbeResult::Incomplete {
                needed: None,
                available: 0,
            }
        );
    }

    #[test]
    fn probe_reports_no_match_for_binary_data() {
        assert_eq!(
            probe_nntp(&[0xff, 0x00, 0x01, 0x02, b'\n']),
            ProbeResult::NoMatch
        );
    }

    #[test]
    fn probe_reports_malformed_for_a_bad_verb() {
        assert!(matches!(
            probe_nntp(b"1x2 nope\r\n"),
            ProbeResult::Malformed(_)
        ));
    }
}
