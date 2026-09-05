use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const COMMON_HEADER_LEN: usize = 8;
const CALL_HEADER_LEN: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcMessage {
    Call {
        xid: u32,
        rpc_version: u32,
        program: u32,
        program_version: u32,
        procedure: u32,
    },
    Reply {
        xid: u32,
    },
}

pub fn parse_rpc_message(payload: &[u8]) -> Result<RpcMessage, LayerError> {
    let Some(header) = payload.get(..COMMON_HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let xid = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let message_type = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

    match message_type {
        0 => parse_rpc_call(payload, xid),
        1 => Ok(RpcMessage::Reply { xid }),
        _ => Err(LayerError::InvalidHeader),
    }
}

fn parse_rpc_call(payload: &[u8], xid: u32) -> Result<RpcMessage, LayerError> {
    let Some(header) = payload.get(..CALL_HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let rpc_version = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    if rpc_version != 2 {
        return Err(LayerError::InvalidHeader);
    }

    Ok(RpcMessage::Call {
        xid,
        rpc_version,
        program: u32::from_be_bytes([header[12], header[13], header[14], header[15]]),
        program_version: u32::from_be_bytes([header[16], header[17], header[18], header[19]]),
        procedure: u32::from_be_bytes([header[20], header[21], header[22], header[23]]),
    })
}

/// Probes an ONC RPC message by its message type.
///
/// RFC 5531 sec 9: the type following the xid is 0 for a call and 1 for a
/// reply, which is the only fixed field the common header has.
#[must_use]
pub fn probe_rpc(payload: &[u8]) -> ProbeResult<RpcMessage> {
    let Some(header) = payload.get(..COMMON_HEADER_LEN) else {
        return ProbeResult::Incomplete {
            needed: Some(COMMON_HEADER_LEN),
            available: payload.len(),
        };
    };
    let message_type = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if !matches!(message_type, 0 | 1) {
        return ProbeResult::NoMatch;
    }
    if message_type == 0 && payload.len() < CALL_HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(CALL_HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_rpc_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("rpc"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{RpcMessage, parse_rpc_message};
    use crate::layer::LayerError;

    const CALL: [u8; 24] = [
        0x7b, 0x55, 0x8a, 0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86,
        0xa3, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn parses_rpc_call_header() {
        let message = parse_rpc_message(&CALL).expect("RPC call should parse");

        assert_eq!(
            message,
            RpcMessage::Call {
                xid: 0x7b55_8aeb,
                rpc_version: 2,
                program: 100_003,
                program_version: 3,
                procedure: 1,
            }
        );
    }

    #[test]
    fn rejects_unknown_message_type_and_short_payload() {
        let mut invalid = CALL;
        invalid[7] = 2;
        assert!(matches!(
            parse_rpc_message(&invalid),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_rpc_message(&CALL[..7]),
            Err(LayerError::InvalidLength)
        ));
    }
}
