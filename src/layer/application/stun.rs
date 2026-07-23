use crate::layer::LayerError;

const HEADER_LEN: usize = 20;
const MAGIC_COOKIE: u32 = 0x2112_a442;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StunMessage {
    pub message_type: u16,
    pub message_length: u16,
    pub magic_cookie: u32,
    pub transaction_id: [u8; 12],
}

pub fn parse_stun_message(payload: &[u8]) -> Result<StunMessage, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };

    let message_type = u16::from_be_bytes([header[0], header[1]]);
    if message_type & 0xc000 != 0 {
        return Err(LayerError::InvalidHeader);
    }

    let message_length = u16::from_be_bytes([header[2], header[3]]);
    let magic_cookie = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if magic_cookie != MAGIC_COOKIE {
        return Err(LayerError::InvalidHeader);
    }

    let transaction_id = header[8..20]
        .try_into()
        .map_err(|_| LayerError::InvalidLength)?;

    Ok(StunMessage {
        message_type,
        message_length,
        magic_cookie,
        transaction_id,
    })
}
