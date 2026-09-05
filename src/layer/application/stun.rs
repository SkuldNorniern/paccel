use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

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

/// Probes a STUN message by its magic cookie.
///
/// RFC 5389 sec 6: the two most significant bits are zero and bytes 4..8 hold a
/// fixed cookie. Together those are what let STUN share a port with RTP, RTCP
/// and QUIC without guessing.
#[must_use]
pub fn probe_stun(payload: &[u8]) -> ProbeResult<StunMessage> {
    const COOKIE_END: usize = 8;
    let Some(head) = payload.get(..COOKIE_END) else {
        return ProbeResult::Incomplete {
            needed: Some(COOKIE_END),
            available: payload.len(),
        };
    };
    if head[0] >> 6 != 0 {
        return ProbeResult::NoMatch;
    }
    if u32::from_be_bytes([head[4], head[5], head[6], head[7]]) != MAGIC_COOKIE {
        return ProbeResult::NoMatch;
    }
    if payload.len() < HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_stun_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("stun"),
            0,
        )),
    }
}
