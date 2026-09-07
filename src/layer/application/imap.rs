use crate::layer::{Layer, LayerError, ParseError, ProbeResult, looks_like_text_line};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapMessage {
    Untagged { text: String },
    Tagged { tag: String, text: String },
}

pub fn parse_imap_message(payload: &[u8]) -> Result<ImapMessage, LayerError> {
    let line_end = find_line_end(payload).unwrap_or(payload.len());
    if line_end == 0 {
        return Err(LayerError::InvalidLength);
    }
    // Lossy, not refused: the encoding of the free-text part of a line says
    // nothing about whether this is the protocol. See
    // [`crate::layer::looks_like_text_line`].
    let line = &String::from_utf8_lossy(&payload[..line_end]);

    if let Some(text) = line.strip_prefix("* ") {
        return Ok(ImapMessage::Untagged {
            text: text.to_string(),
        });
    }

    let mut fields = line.splitn(2, ' ');
    let tag = fields.next().unwrap_or("");
    if tag.is_empty() || tag.len() > 14 || !tag.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(LayerError::InvalidHeader);
    }
    let text = fields.next().ok_or(LayerError::InvalidHeader)?;
    if text.is_empty() {
        return Err(LayerError::InvalidHeader);
    }

    Ok(ImapMessage::Tagged {
        tag: tag.to_string(),
        text: text.to_string(),
    })
}

/// Probes an IMAP line. No magic bytes exist for IMAP - lines are ASCII
/// text, so binary bytes are a real NoMatch signal. `parse_imap_message`
/// treats a buffer with no line terminator as a complete line (same
/// fallback as FTP/NNTP's sibling probes), so this doesn't invent an
/// Incomplete case beyond an empty buffer.
#[must_use]
pub fn probe_imap(payload: &[u8]) -> ProbeResult<ImapMessage> {
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
    match parse_imap_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("imap"),
            0,
        )),
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
    use super::{ImapMessage, parse_imap_message, probe_imap};
    use crate::layer::{LayerError, ProbeResult};

    #[test]
    fn parses_untagged_greeting() {
        assert_eq!(
            parse_imap_message(b"* OK IMAP4rev1 ready\r\n").expect("greeting should parse"),
            ImapMessage::Untagged {
                text: "OK IMAP4rev1 ready".to_string(),
            }
        );
    }

    #[test]
    fn parses_tagged_command() {
        assert_eq!(
            parse_imap_message(b"A001 LOGIN user password\r\n").expect("command should parse"),
            ImapMessage::Tagged {
                tag: "A001".to_string(),
                text: "LOGIN user password".to_string(),
            }
        );
    }

    #[test]
    fn rejects_empty_line() {
        assert!(matches!(
            parse_imap_message(b"\r\n"),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn probe_matches_an_untagged_greeting() {
        assert!(matches!(
            probe_imap(b"* OK IMAP4rev1 ready\r\n"),
            ProbeResult::Match(_)
        ));
    }

    #[test]
    fn probe_reports_incomplete_for_an_empty_buffer() {
        assert_eq!(
            probe_imap(b""),
            ProbeResult::Incomplete {
                needed: None,
                available: 0,
            }
        );
    }

    #[test]
    fn probe_reports_no_match_for_binary_data() {
        assert_eq!(
            probe_imap(&[0xff, 0x00, 0x01, 0x02, b'\n']),
            ProbeResult::NoMatch
        );
    }

    #[test]
    fn probe_reports_malformed_for_a_tag_with_no_text() {
        assert!(matches!(probe_imap(b"A001\r\n"), ProbeResult::Malformed(_)));
    }
}
