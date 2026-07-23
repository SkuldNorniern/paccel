use crate::layer::LayerError;

const DIRECT_TCP_PREFIX_LEN: usize = 4;
const SMB2_HEADER_LEN: usize = 64;
const SMB2_PROTOCOL_ID: [u8; 4] = [0xfe, b'S', b'M', b'B'];
const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2Header {
    pub command: u16,
    pub is_response: bool,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
}

pub fn parse_smb2_message(payload: &[u8]) -> Result<Smb2Header, LayerError> {
    let Some(prefix) = payload.get(..DIRECT_TCP_PREFIX_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    if prefix[0] != 0x00 {
        return Err(LayerError::InvalidHeader);
    }

    let Some(header) = payload.get(DIRECT_TCP_PREFIX_LEN..DIRECT_TCP_PREFIX_LEN + SMB2_HEADER_LEN)
    else {
        return Err(LayerError::InvalidLength);
    };
    if header[..4] != SMB2_PROTOCOL_ID {
        return Err(LayerError::InvalidHeader);
    }

    let command = u16::from_le_bytes([header[12], header[13]]);
    let flags = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let message_id = u64::from_le_bytes([
        header[24], header[25], header[26], header[27], header[28], header[29], header[30],
        header[31],
    ]);
    let tree_id = u32::from_le_bytes([header[36], header[37], header[38], header[39]]);
    let session_id = u64::from_le_bytes([
        header[40], header[41], header[42], header[43], header[44], header[45], header[46],
        header[47],
    ]);

    Ok(Smb2Header {
        command,
        is_response: flags & SMB2_FLAGS_SERVER_TO_REDIR != 0,
        message_id,
        tree_id,
        session_id,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_smb2_message;
    use crate::layer::LayerError;

    fn negotiate_message() -> [u8; 68] {
        let mut payload = [0; 68];
        payload[3] = 64;
        payload[4..8].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        payload[8..10].copy_from_slice(&64u16.to_le_bytes());
        payload[16..18].copy_from_slice(&0u16.to_le_bytes());
        payload[20..24].copy_from_slice(&1u32.to_le_bytes());
        payload[28..36].copy_from_slice(&7u64.to_le_bytes());
        payload[40..44].copy_from_slice(&9u32.to_le_bytes());
        payload[44..52].copy_from_slice(&11u64.to_le_bytes());
        payload
    }

    #[test]
    fn parses_negotiate_response() {
        let header = parse_smb2_message(&negotiate_message()).expect("SMB2 response should parse");

        assert_eq!(header.command, 0);
        assert!(header.is_response);
        assert_eq!(header.message_id, 7);
        assert_eq!(header.tree_id, 9);
        assert_eq!(header.session_id, 11);
    }

    #[test]
    fn rejects_wrong_protocol_id_and_short_message() {
        let mut payload = negotiate_message();
        payload[4] = 0xff;
        assert!(matches!(
            parse_smb2_message(&payload),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_smb2_message(&[0x00; 67]),
            Err(LayerError::InvalidLength)
        ));
    }
}
