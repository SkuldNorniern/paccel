use crate::layer::LayerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TftpMessage {
    ReadRequest { filename: String, mode: String },
    WriteRequest { filename: String, mode: String },
    Data { block: u16, data_len: usize },
    Ack { block: u16 },
    Error { code: u16, message: String },
    OptionAck,
}

pub fn parse_tftp_message(payload: &[u8]) -> Result<TftpMessage, LayerError> {
    let Some(opcode_bytes) = payload.get(..2) else {
        return Err(LayerError::InvalidLength);
    };
    let opcode = u16::from_be_bytes([opcode_bytes[0], opcode_bytes[1]]);

    match opcode {
        1 => Ok(parse_request(payload, true)),
        2 => Ok(parse_request(payload, false)),
        3 => {
            let block = parse_block(payload)?;
            Ok(TftpMessage::Data {
                block,
                data_len: payload.len() - 4,
            })
        }
        4 => {
            if payload.len() != 4 {
                return Err(LayerError::InvalidLength);
            }
            Ok(TftpMessage::Ack {
                block: parse_block(payload)?,
            })
        }
        5 => {
            let code = parse_block(payload)?;
            let (message, _) = parse_null_terminated_string(payload, 4);
            Ok(TftpMessage::Error { code, message })
        }
        6 => Ok(TftpMessage::OptionAck),
        _ => Err(LayerError::InvalidHeader),
    }
}

fn parse_request(payload: &[u8], read: bool) -> TftpMessage {
    let (filename, offset) = parse_null_terminated_string(payload, 2);
    let (mode, _) = parse_null_terminated_string(payload, offset);
    if read {
        TftpMessage::ReadRequest { filename, mode }
    } else {
        TftpMessage::WriteRequest { filename, mode }
    }
}

fn parse_block(payload: &[u8]) -> Result<u16, LayerError> {
    let Some(bytes) = payload.get(2..4) else {
        return Err(LayerError::InvalidLength);
    };
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse_null_terminated_string(payload: &[u8], offset: usize) -> (String, usize) {
    let Some(remaining) = payload.get(offset..) else {
        return (String::new(), payload.len());
    };
    let string_len = remaining
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(remaining.len());
    let next_offset = offset
        .saturating_add(string_len)
        .saturating_add(usize::from(string_len < remaining.len()));
    (
        String::from_utf8_lossy(&remaining[..string_len]).into_owned(),
        next_offset,
    )
}

#[cfg(test)]
mod tests {
    use super::{TftpMessage, parse_tftp_message};
    use crate::layer::LayerError;

    #[test]
    fn parses_read_request() {
        let payload = b"\0\x01rfc1350.txt\0octet\0";
        assert_eq!(
            parse_tftp_message(payload).expect("RRQ should parse"),
            TftpMessage::ReadRequest {
                filename: "rfc1350.txt".to_owned(),
                mode: "octet".to_owned(),
            }
        );
    }

    #[test]
    fn parses_write_request() {
        let payload = b"\0\x02upload.bin\0netascii\0";
        assert_eq!(
            parse_tftp_message(payload).expect("WRQ should parse"),
            TftpMessage::WriteRequest {
                filename: "upload.bin".to_owned(),
                mode: "netascii".to_owned(),
            }
        );
    }

    #[test]
    fn parses_ack() {
        assert_eq!(
            parse_tftp_message(&[0, 4, 0, 7]).expect("ACK should parse"),
            TftpMessage::Ack { block: 7 }
        );
    }

    #[test]
    fn parses_full_data_block_without_copying_data() {
        let mut payload = vec![0, 3, 0, 1];
        payload.extend_from_slice(&[0x42; 512]);
        assert_eq!(
            parse_tftp_message(&payload).expect("DATA should parse"),
            TftpMessage::Data {
                block: 1,
                data_len: 512,
            }
        );
    }

    #[test]
    fn parses_error() {
        let payload = b"\0\x05\0\x01File not found\0";
        assert_eq!(
            parse_tftp_message(payload).expect("ERROR should parse"),
            TftpMessage::Error {
                code: 1,
                message: "File not found".to_owned(),
            }
        );
    }

    #[test]
    fn parses_option_ack() {
        let payload = b"\0\x06blksize\x001024\0timeout\x005\0";
        assert_eq!(
            parse_tftp_message(payload).expect("OACK should parse"),
            TftpMessage::OptionAck
        );
    }

    #[test]
    fn rejects_too_short_payload() {
        assert!(matches!(
            parse_tftp_message(&[0]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_unknown_opcode() {
        assert!(matches!(
            parse_tftp_message(&[0, 9]),
            Err(LayerError::InvalidHeader)
        ));
    }
}
