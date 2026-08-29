use std::str::from_utf8;

use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpMessage {
    Response { code: u16, text: String },
    Command { verb: String, args: String },
}

pub fn parse_smtp(payload: &[u8]) -> Result<SmtpMessage, LayerError> {
    let line_end = find_line_end(payload).unwrap_or(payload.len());
    if line_end == 0 {
        return Err(LayerError::InvalidLength);
    }
    let line = from_utf8(&payload[..line_end]).map_err(|_| LayerError::InvalidHeader)?;

    if let Some(code) = parse_response_code(line) {
        let text = line.get(4..).unwrap_or("").trim_start().to_string();
        return Ok(SmtpMessage::Response { code, text });
    }

    let mut fields = line.splitn(2, ' ');
    let verb = fields.next().unwrap_or("");
    if verb.is_empty() || verb.len() > 14 || !verb.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(LayerError::InvalidHeader);
    }
    let args = fields.next().unwrap_or("").trim().to_string();

    Ok(SmtpMessage::Command {
        verb: verb.to_ascii_uppercase(),
        args,
    })
}

/// Probes an SMTP line. No magic bytes exist for SMTP - lines are ASCII
/// text, so binary bytes are a real NoMatch signal. `parse_smtp` treats a
/// buffer with no line terminator as a complete line (same fallback as
/// FTP/NNTP/IMAP's sibling probes), so this doesn't invent an Incomplete
/// case beyond an empty buffer.
#[must_use]
pub fn probe_smtp(payload: &[u8]) -> ProbeResult<SmtpMessage> {
    if payload.is_empty() {
        return ProbeResult::Incomplete {
            needed: None,
            available: 0,
        };
    }
    let line_end = find_line_end(payload).unwrap_or(payload.len());
    if line_end > 0 && from_utf8(&payload[..line_end]).is_err() {
        return ProbeResult::NoMatch;
    }
    match parse_smtp(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("smtp"),
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
        Some(b' ' | b'-') | None => code_str.parse().ok(),
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
    use super::{SmtpMessage, parse_smtp, probe_smtp};
    use crate::layer::{LayerError, ProbeResult};

    #[test]
    fn parses_multiline_greeting_response() {
        let payload = b"220-mail.example ESMTP ready\r\n220 mail.example ready\r\n";
        let msg = parse_smtp(payload).expect("greeting should parse");
        assert_eq!(
            msg,
            SmtpMessage::Response {
                code: 220,
                text: "mail.example ESMTP ready".to_string(),
            }
        );
    }

    #[test]
    fn parses_ehlo_command() {
        let payload = b"EHLO client.example\r\n";
        let msg = parse_smtp(payload).expect("command should parse");
        assert_eq!(
            msg,
            SmtpMessage::Command {
                verb: "EHLO".to_string(),
                args: "client.example".to_string(),
            }
        );
    }

    #[test]
    fn rejects_non_alphabetic_verb() {
        assert!(matches!(
            parse_smtp(b"1x2 nope\r\n"),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_empty_line() {
        assert!(matches!(
            parse_smtp(b"\r\n"),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn probe_matches_a_greeting_response() {
        assert!(matches!(
            probe_smtp(b"220 mail.example ready\r\n"),
            ProbeResult::Match(_)
        ));
    }

    #[test]
    fn probe_reports_incomplete_for_an_empty_buffer() {
        assert_eq!(
            probe_smtp(b""),
            ProbeResult::Incomplete {
                needed: None,
                available: 0,
            }
        );
    }

    #[test]
    fn probe_reports_no_match_for_binary_data() {
        assert_eq!(
            probe_smtp(&[0xff, 0x00, 0x01, 0x02, b'\n']),
            ProbeResult::NoMatch
        );
    }

    #[test]
    fn probe_reports_malformed_for_a_bad_verb() {
        assert!(matches!(
            probe_smtp(b"1x2 nope\r\n"),
            ProbeResult::Malformed(_)
        ));
    }
}
