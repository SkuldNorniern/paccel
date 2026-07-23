use std::str::from_utf8;

use crate::layer::LayerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpMessage {
    Response { code: u16, text: String },
    Command { verb: String, args: String },
}

pub fn parse_ftp(payload: &[u8]) -> Result<FtpMessage, LayerError> {
    let line_end = find_line_end(payload).unwrap_or(payload.len());
    if line_end == 0 {
        return Err(LayerError::InvalidLength);
    }
    let line = from_utf8(&payload[..line_end]).map_err(|_| LayerError::InvalidHeader)?;

    if let Some(code) = parse_response_code(line) {
        let text = line.get(4..).unwrap_or("").trim_start().to_string();
        return Ok(FtpMessage::Response { code, text });
    }

    let mut fields = line.splitn(2, ' ');
    let verb = fields.next().unwrap_or("");
    if verb.is_empty() || verb.len() > 14 || !verb.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(LayerError::InvalidHeader);
    }
    let args = fields.next().unwrap_or("").trim().to_string();

    Ok(FtpMessage::Command {
        verb: verb.to_ascii_uppercase(),
        args,
    })
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
    use super::{FtpMessage, parse_ftp};
    use crate::layer::LayerError;

    #[test]
    fn parses_greeting_response() {
        let payload = b"220 FTP server ready.\r\n";
        let msg = parse_ftp(payload).expect("greeting should parse");
        assert_eq!(
            msg,
            FtpMessage::Response {
                code: 220,
                text: "FTP server ready.".to_string(),
            }
        );
    }

    #[test]
    fn parses_user_command() {
        let payload = b"USER anonymous\r\n";
        let msg = parse_ftp(payload).expect("command should parse");
        assert_eq!(
            msg,
            FtpMessage::Command {
                verb: "USER".to_string(),
                args: "anonymous".to_string(),
            }
        );
    }

    #[test]
    fn rejects_non_alphabetic_verb() {
        assert!(matches!(
            parse_ftp(b"1x2 nope\r\n"),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_empty_line() {
        assert!(matches!(parse_ftp(b"\r\n"), Err(LayerError::InvalidLength)));
    }
}
