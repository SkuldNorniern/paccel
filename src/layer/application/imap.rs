use std::str::from_utf8;

use crate::layer::LayerError;

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
    let line = from_utf8(&payload[..line_end]).map_err(|_| LayerError::InvalidHeader)?;

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
    use super::{ImapMessage, parse_imap_message};
    use crate::layer::LayerError;

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
}
