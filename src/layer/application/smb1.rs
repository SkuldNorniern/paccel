use crate::layer::LayerError;

const DIRECT_TCP_PREFIX_LEN: usize = 4;
const SMB1_HEADER_LEN: usize = 32;
const SMB1_PROTOCOL_ID: [u8; 4] = [0xff, b'S', b'M', b'B'];
const SMB_FLAGS_REPLY: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb1Header {
    pub command: u8,
    pub is_response: bool,
    pub tid: u16,
    pub pid: u16,
    pub uid: u16,
    pub mid: u16,
}

pub fn parse_smb1_message(payload: &[u8]) -> Result<Smb1Header, LayerError> {
    let Some(prefix) = payload.get(..DIRECT_TCP_PREFIX_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    if prefix[0] != 0x00 {
        return Err(LayerError::InvalidHeader);
    }

    let Some(header) = payload.get(DIRECT_TCP_PREFIX_LEN..DIRECT_TCP_PREFIX_LEN + SMB1_HEADER_LEN)
    else {
        return Err(LayerError::InvalidLength);
    };
    if header[..4] != SMB1_PROTOCOL_ID {
        return Err(LayerError::InvalidHeader);
    }

    Ok(Smb1Header {
        command: header[4],
        is_response: header[9] & SMB_FLAGS_REPLY != 0,
        tid: u16::from_le_bytes([header[24], header[25]]),
        pid: u16::from_le_bytes([header[26], header[27]]),
        uid: u16::from_le_bytes([header[28], header[29]]),
        mid: u16::from_le_bytes([header[30], header[31]]),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_smb1_message;
    use crate::layer::LayerError;

    fn negotiate_message() -> [u8; 36] {
        let mut payload = [0; 36];
        payload[3] = 32;
        payload[4..8].copy_from_slice(&[0xff, b'S', b'M', b'B']);
        payload[8] = 0x72;
        payload[13] = 0x80;
        payload[28..30].copy_from_slice(&2u16.to_le_bytes());
        payload[30..32].copy_from_slice(&3u16.to_le_bytes());
        payload[32..34].copy_from_slice(&4u16.to_le_bytes());
        payload[34..36].copy_from_slice(&5u16.to_le_bytes());
        payload
    }

    #[test]
    fn parses_negotiate_response() {
        let header = parse_smb1_message(&negotiate_message()).expect("SMB1 response should parse");

        assert_eq!(header.command, 0x72);
        assert!(header.is_response);
        assert_eq!(header.tid, 2);
        assert_eq!(header.pid, 3);
        assert_eq!(header.uid, 4);
        assert_eq!(header.mid, 5);
    }

    #[test]
    fn rejects_wrong_protocol_id_and_short_message() {
        let mut payload = negotiate_message();
        payload[4] = 0xfe;
        assert!(matches!(
            parse_smb1_message(&payload),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_smb1_message(&[0x00; 35]),
            Err(LayerError::InvalidLength)
        ));
    }
}
