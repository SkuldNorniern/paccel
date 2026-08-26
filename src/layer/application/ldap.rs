use crate::layer::LayerError;

const SEQUENCE_TAG: u8 = 0x30;
const INTEGER_TAG: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapProtocolOp {
    BindRequest,
    BindResponse,
    UnbindRequest,
    SearchRequest,
    SearchResultEntry,
    SearchResultDone,
    SearchResultReference,
    ModifyRequest,
    ModifyResponse,
    AddRequest,
    AddResponse,
    DelRequest,
    DelResponse,
    ModifyDnRequest,
    ModifyDnResponse,
    CompareRequest,
    CompareResponse,
    AbandonRequest,
    ExtendedRequest,
    ExtendedResponse,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LdapMessage {
    pub message_id: u32,
    pub protocol_op: LdapProtocolOp,
}

pub fn parse_ldap_message(payload: &[u8]) -> Result<LdapMessage, LayerError> {
    if payload.first() != Some(&SEQUENCE_TAG) {
        return Err(LayerError::InvalidHeader);
    }
    let (_, mut offset) = read_ber_length(payload, 1)?;

    if payload.get(offset) != Some(&INTEGER_TAG) {
        return Err(LayerError::InvalidHeader);
    }
    offset += 1;
    let (id_len, id_offset) = read_ber_length(payload, offset)?;
    let id_end = id_offset
        .checked_add(id_len)
        .ok_or(LayerError::InvalidLength)?;
    let id_bytes = payload
        .get(id_offset..id_end)
        .ok_or(LayerError::InvalidLength)?;
    if id_len == 0 || id_len > 4 {
        return Err(LayerError::InvalidHeader);
    }
    let mut message_id: u32 = 0;
    for byte in id_bytes {
        message_id = (message_id << 8) | u32::from(*byte);
    }
    offset = id_end;

    let op_tag = *payload.get(offset).ok_or(LayerError::InvalidLength)?;
    let opnum = op_tag & 0x1f;
    let protocol_op = match opnum {
        0 => LdapProtocolOp::BindRequest,
        1 => LdapProtocolOp::BindResponse,
        2 => LdapProtocolOp::UnbindRequest,
        3 => LdapProtocolOp::SearchRequest,
        4 => LdapProtocolOp::SearchResultEntry,
        5 => LdapProtocolOp::SearchResultDone,
        6 => LdapProtocolOp::ModifyRequest,
        7 => LdapProtocolOp::ModifyResponse,
        8 => LdapProtocolOp::AddRequest,
        9 => LdapProtocolOp::AddResponse,
        10 => LdapProtocolOp::DelRequest,
        11 => LdapProtocolOp::DelResponse,
        12 => LdapProtocolOp::ModifyDnRequest,
        13 => LdapProtocolOp::ModifyDnResponse,
        14 => LdapProtocolOp::CompareRequest,
        15 => LdapProtocolOp::CompareResponse,
        16 => LdapProtocolOp::AbandonRequest,
        19 => LdapProtocolOp::SearchResultReference,
        23 => LdapProtocolOp::ExtendedRequest,
        24 => LdapProtocolOp::ExtendedResponse,
        other => LdapProtocolOp::Other(other),
    };

    Ok(LdapMessage {
        message_id,
        protocol_op,
    })
}

/// Decodes a BER/DER length field at `offset`. Returns `(length, offset_after_length_field)`.
/// Indefinite-length encoding (0x80) is rejected — not used by LDAP's DER encoding.
fn read_ber_length(bytes: &[u8], offset: usize) -> Result<(usize, usize), LayerError> {
    let first = *bytes.get(offset).ok_or(LayerError::InvalidLength)?;
    if first & 0x80 == 0 {
        return Ok((first as usize, offset + 1));
    }
    let num_octets = usize::from(first & 0x7f);
    if num_octets == 0 || num_octets > size_of::<usize>() {
        return Err(LayerError::InvalidHeader);
    }
    let length_bytes = bytes
        .get(offset + 1..offset + 1 + num_octets)
        .ok_or(LayerError::InvalidLength)?;
    let mut length: usize = 0;
    for byte in length_bytes {
        length = (length << 8) | usize::from(*byte);
    }
    Ok((length, offset + 1 + num_octets))
}

#[cfg(test)]
mod tests {
    use super::{LdapProtocolOp, parse_ldap_message};
    use crate::layer::LayerError;

    #[test]
    fn parses_bind_request() {
        let payload = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];
        let msg = parse_ldap_message(&payload).expect("bind request should parse");
        assert_eq!(msg.message_id, 1);
        assert_eq!(msg.protocol_op, LdapProtocolOp::BindRequest);
    }

    #[test]
    fn parses_multi_byte_message_id() {
        let payload = [0x30, 0x06, 0x02, 0x02, 0x01, 0x2c, 0x42, 0x00];
        let msg = parse_ldap_message(&payload).expect("unbind request should parse");
        assert_eq!(msg.message_id, 0x012c);
        assert_eq!(msg.protocol_op, LdapProtocolOp::UnbindRequest);
    }

    #[test]
    fn rejects_non_sequence() {
        assert!(matches!(
            parse_ldap_message(&[0x02, 0x01, 0x01]),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(matches!(
            parse_ldap_message(&[0x30, 0x0c, 0x02, 0x01]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_indefinite_length() {
        assert!(matches!(
            parse_ldap_message(&[0x30, 0x80]),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_message_id_length_near_usize_max_without_overflow() {
        let payload = [
            0x30, 0x0c, 0x02, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        assert!(matches!(
            parse_ldap_message(&payload),
            Err(LayerError::InvalidLength)
        ));
    }
}
