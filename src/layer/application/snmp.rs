use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpPduType {
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    TrapV1,
    GetBulkRequest,
    InformRequest,
    TrapV2,
    Report,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpMessage {
    V1 {
        community: String,
        pdu_type: Option<SnmpPduType>,
        request_id: Option<i64>,
    },
    V2c {
        community: String,
        pdu_type: Option<SnmpPduType>,
        request_id: Option<i64>,
    },
    V3 {
        msg_id: u64,
        msg_max_size: u64,
        msg_flags: u8,
        reportable: bool,
        encrypted: bool,
        authenticated: bool,
        msg_security_model: u64,
        pdu_type: Option<SnmpPduType>,
        request_id: Option<i64>,
    },
}

#[derive(Debug, Clone, Copy)]
struct BerTlv<'a> {
    tag: u8,
    content: &'a [u8],
    consumed: usize,
}

fn read_ber_tlv(data: &[u8]) -> Option<BerTlv<'_>> {
    let (&tag, length_data) = data.split_first()?;
    let (&length_byte, after_length_byte) = length_data.split_first()?;
    let (content_length, content_offset) = if length_byte & 0x80 == 0 {
        (usize::from(length_byte), 2)
    } else {
        let length_bytes = usize::from(length_byte & 0x7f);
        if !(1..=4).contains(&length_bytes) {
            return None;
        }
        let encoded_length = after_length_byte.get(..length_bytes)?;
        let length = encoded_length
            .iter()
            .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
        (length, 2 + length_bytes)
    };
    let consumed = content_offset.checked_add(content_length)?;
    let content = data.get(content_offset..consumed)?;
    Some(BerTlv {
        tag,
        content,
        consumed,
    })
}

fn take_ber_tlv<'a>(data: &mut &'a [u8]) -> Option<BerTlv<'a>> {
    let tlv = read_ber_tlv(data)?;
    *data = data.get(tlv.consumed..)?;
    Some(tlv)
}

fn decode_ber_u64(content: &[u8]) -> u64 {
    if content.len() > 8 {
        return u64::MAX;
    }
    content
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

fn decode_ber_i64(content: &[u8]) -> i64 {
    let bytes = if content.len() > 8 {
        &content[content.len() - 8..]
    } else {
        content
    };
    if bytes.is_empty() {
        return 0;
    }
    let fill = if bytes[0] & 0x80 == 0 { 0 } else { 0xff };
    let mut encoded = [fill; 8];
    encoded[8 - bytes.len()..].copy_from_slice(bytes);
    i64::from_be_bytes(encoded)
}

fn pdu_type(tag: u8) -> Option<SnmpPduType> {
    match tag {
        0xa0 => Some(SnmpPduType::GetRequest),
        0xa1 => Some(SnmpPduType::GetNextRequest),
        0xa2 => Some(SnmpPduType::GetResponse),
        0xa3 => Some(SnmpPduType::SetRequest),
        0xa4 => Some(SnmpPduType::TrapV1),
        0xa5 => Some(SnmpPduType::GetBulkRequest),
        0xa6 => Some(SnmpPduType::InformRequest),
        0xa7 => Some(SnmpPduType::TrapV2),
        0xa8 => Some(SnmpPduType::Report),
        _ => None,
    }
}

fn parse_pdu(data: &[u8]) -> (Option<SnmpPduType>, Option<i64>) {
    let Some(pdu) = read_ber_tlv(data) else {
        return (None, None);
    };
    let Some(kind) = pdu_type(pdu.tag) else {
        return (None, None);
    };
    if kind == SnmpPduType::TrapV1 {
        return (Some(kind), None);
    }
    let request_id = read_ber_tlv(pdu.content)
        .filter(|tlv| tlv.tag == TAG_INTEGER)
        .map(|tlv| decode_ber_i64(tlv.content));
    (Some(kind), request_id)
}

fn parse_community_message(data: &[u8]) -> (String, Option<SnmpPduType>, Option<i64>) {
    let mut remaining = data;
    let Some(community) = take_ber_tlv(&mut remaining) else {
        return (String::new(), None, None);
    };
    if community.tag != TAG_OCTET_STRING {
        return (String::new(), None, None);
    }
    let community = String::from_utf8_lossy(community.content).into_owned();
    let (pdu_type, request_id) = parse_pdu(remaining);
    (community, pdu_type, request_id)
}

fn parse_v1(data: &[u8]) -> SnmpMessage {
    let (community, pdu_type, request_id) = parse_community_message(data);
    SnmpMessage::V1 {
        community,
        pdu_type,
        request_id,
    }
}

fn parse_v2c(data: &[u8]) -> SnmpMessage {
    let (community, pdu_type, request_id) = parse_community_message(data);
    SnmpMessage::V2c {
        community,
        pdu_type,
        request_id,
    }
}

fn parse_v3_global_data(data: &[u8]) -> Option<(u64, u64, u8, u64, &[u8])> {
    let mut remaining = data;
    let global = take_ber_tlv(&mut remaining)?;
    if global.tag != TAG_SEQUENCE {
        return None;
    }
    let mut fields = global.content;
    let msg_id = take_ber_tlv(&mut fields)?;
    let msg_max_size = take_ber_tlv(&mut fields)?;
    let msg_flags = take_ber_tlv(&mut fields)?;
    let security_model = take_ber_tlv(&mut fields)?;
    if msg_id.tag != TAG_INTEGER
        || msg_max_size.tag != TAG_INTEGER
        || msg_flags.tag != TAG_OCTET_STRING
        || security_model.tag != TAG_INTEGER
    {
        return None;
    }
    Some((
        decode_ber_u64(msg_id.content),
        decode_ber_u64(msg_max_size.content),
        msg_flags.content.first().copied().unwrap_or(0),
        decode_ber_u64(security_model.content),
        remaining,
    ))
}

fn parse_scoped_pdu(data: &[u8]) -> (Option<SnmpPduType>, Option<i64>) {
    let Some(msg_data) = read_ber_tlv(data) else {
        return (None, None);
    };
    if msg_data.tag != TAG_SEQUENCE {
        return (None, None);
    }
    let mut scoped = msg_data.content;
    for _ in 0..2 {
        let Some(context) = take_ber_tlv(&mut scoped) else {
            return (None, None);
        };
        if context.tag != TAG_OCTET_STRING {
            return (None, None);
        }
    }
    parse_pdu(scoped)
}

fn parse_v3(data: &[u8]) -> SnmpMessage {
    let Some((msg_id, msg_max_size, msg_flags, msg_security_model, mut remaining)) =
        parse_v3_global_data(data)
    else {
        return SnmpMessage::V3 {
            msg_id: 0,
            msg_max_size: 0,
            msg_flags: 0,
            reportable: false,
            encrypted: false,
            authenticated: false,
            msg_security_model: 0,
            pdu_type: None,
            request_id: None,
        };
    };
    let pdu = take_ber_tlv(&mut remaining)
        .filter(|security| security.tag == TAG_OCTET_STRING)
        .map_or((None, None), |_| parse_scoped_pdu(remaining));
    SnmpMessage::V3 {
        msg_id,
        msg_max_size,
        msg_flags,
        reportable: msg_flags & 0x04 != 0,
        encrypted: msg_flags & 0x02 != 0,
        authenticated: msg_flags & 0x01 != 0,
        msg_security_model,
        pdu_type: pdu.0,
        request_id: pdu.1,
    }
}

pub fn parse_snmp_message(payload: &[u8]) -> Result<SnmpMessage, LayerError> {
    match payload.first() {
        None => return Err(LayerError::InvalidLength),
        Some(&TAG_SEQUENCE) => {}
        Some(_) => return Err(LayerError::InvalidHeader),
    }
    let outer = read_ber_tlv(payload).ok_or(LayerError::InvalidLength)?;
    let version = read_ber_tlv(outer.content).ok_or(LayerError::InvalidLength)?;
    if version.tag != TAG_INTEGER {
        return Err(LayerError::InvalidHeader);
    }
    let remaining = outer
        .content
        .get(version.consumed..)
        .ok_or(LayerError::InvalidLength)?;
    match decode_ber_u64(version.content) {
        0 => Ok(parse_v1(remaining)),
        1 => Ok(parse_v2c(remaining)),
        3 => Ok(parse_v3(remaining)),
        _ => Err(LayerError::InvalidHeader),
    }
}

/// Probes an SNMP message by its BER framing and version.
///
/// RFC 3416 sec 3: the message is a SEQUENCE whose first element is the
/// version, one of 0, 1 or 3.
#[must_use]
pub fn probe_snmp(payload: &[u8]) -> ProbeResult<SnmpMessage> {
    match payload.first() {
        None => {
            return ProbeResult::Incomplete {
                needed: Some(2),
                available: 0,
            };
        }
        Some(&TAG_SEQUENCE) => {}
        Some(_) => return ProbeResult::NoMatch,
    }
    let Some(outer) = read_ber_tlv(payload) else {
        return ProbeResult::Incomplete {
            needed: None,
            available: payload.len(),
        };
    };
    let Some(version) = read_ber_tlv(outer.content) else {
        return ProbeResult::Incomplete {
            needed: None,
            available: payload.len(),
        };
    };
    if version.tag != TAG_INTEGER || !matches!(decode_ber_u64(version.content), 0 | 1 | 3) {
        return ProbeResult::NoMatch;
    }

    match parse_snmp_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("snmp"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{SnmpMessage, SnmpPduType, parse_snmp_message, read_ber_tlv};
    use crate::layer::LayerError;

    const V3_FRAME_ONE_PAYLOAD: [u8; 77] = [
        0x30, 0x4b, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x30, 0xf6, 0xf3, 0xd4, 0x02, 0x03,
        0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00,
        0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x21, 0x04,
        0x0d, 0x80, 0x00, 0x1f, 0x88, 0x80, 0x59, 0xdc, 0x48, 0x61, 0x45, 0xa2, 0x63, 0x22, 0x04,
        0x00, 0xa0, 0x0e, 0x02, 0x04, 0x7d, 0x0e, 0x08, 0x2e, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x30, 0x00,
    ];

    #[test]
    fn reads_short_form_tlv() {
        let tlv = read_ber_tlv(&[0x04, 0x03, b's', b'n', b'm']).expect("valid TLV");
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.content, b"snm");
        assert_eq!(tlv.consumed, 5);
    }

    #[test]
    fn reads_two_byte_long_form_tlv() {
        let mut encoded = vec![0x04, 0x82, 0x01, 0x2c];
        encoded.extend_from_slice(&[0x5a; 300]);
        let tlv = read_ber_tlv(&encoded).expect("valid long-form TLV");
        assert_eq!(tlv.content.len(), 300);
        assert_eq!(tlv.consumed, 304);
    }

    #[test]
    fn rejects_truncated_tlv() {
        assert!(read_ber_tlv(&[0x04, 0x04, 1, 2]).is_none());
        assert!(read_ber_tlv(&[0x04, 0x82, 0x01]).is_none());
    }

    #[test]
    fn parses_v3_fixture_payload() {
        let message = parse_snmp_message(&V3_FRAME_ONE_PAYLOAD).expect("SNMPv3 should parse");
        assert_eq!(
            message,
            SnmpMessage::V3 {
                msg_id: 821_490_644,
                msg_max_size: 65_507,
                msg_flags: 0x04,
                reportable: true,
                encrypted: false,
                authenticated: false,
                msg_security_model: 3,
                pdu_type: Some(SnmpPduType::GetRequest),
                request_id: Some(2_098_071_598),
            }
        );
    }

    #[test]
    fn parses_minimal_v2c_get_request() {
        let payload = [
            0x30, 0x18, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x0b, 0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];
        assert_eq!(
            parse_snmp_message(&payload).expect("SNMPv2c should parse"),
            SnmpMessage::V2c {
                community: "public".to_owned(),
                pdu_type: Some(SnmpPduType::GetRequest),
                request_id: Some(42),
            }
        );
    }

    #[test]
    fn rejects_non_snmp_payload() {
        assert!(matches!(
            parse_snmp_message(&[0xde, 0xad, 0xbe, 0xef]),
            Err(LayerError::InvalidHeader)
        ));
    }
}
