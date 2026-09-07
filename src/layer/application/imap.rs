use crate::layer::{Layer, LayerError, ParseError, ProbeResult, looks_like_text_line};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImapMessage {
    Untagged { text: String },
    Tagged { tag: String, text: String },
}

/// No length is given in RFC 3501; this bound exists so a line of arbitrary
/// text is not read as a tagged command, and is generous next to the four or
/// five characters clients actually use.
const MAX_TAG_LEN: usize = 32;

/// RFC 3501 sec 9: `tag = 1*<any ASTRING-CHAR except "+">`, where the
/// exclusions are `atom-specials` - `(`, `)`, `{`, space, controls, the list
/// wildcards `%` and `*`, and the quoted-specials `"` and `\`.
///
/// Alphanumerics alone would be the common case, not the rule: `.`, `-` and
/// `_` all appear in tags real clients send, and refusing them loses the line.
fn is_tag_char(byte: u8) -> bool {
    !matches!(
        byte,
        b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | b'+' | 0x00..=0x1f | 0x7f
    )
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
    if tag.is_empty() || tag.len() > MAX_TAG_LEN || !tag.bytes().all(is_tag_char) {
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

    /// RFC 3501 sec 9 defines a tag as any ASTRING-CHAR except `+`, which is
    /// far wider than the alphanumerics clients most often use.
    #[test]
    fn a_tag_may_hold_more_than_alphanumerics() {
        for tag in ["A001", "a.1", "tag-2", "x_9", "A1:B", "[2]"] {
            let line = format!("{tag} OK done\r\n");
            let message = parse_imap_message(line.as_bytes());
            assert!(message.is_ok(), "{tag} was refused: {message:?}");
        }
    }

    /// The exclusions are still exclusions, or a line of prose would read as a
    /// tagged command.
    #[test]
    fn the_characters_a_tag_may_not_hold_are_still_refused() {
        for tag in ["a+b", "a(b", "a)b", "a{b", "a%b", "a*b", "a\"b"] {
            let line = format!("{tag} OK done\r\n");
            assert!(
                parse_imap_message(line.as_bytes()).is_err(),
                "{tag} was accepted"
            );
        }
    }

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
