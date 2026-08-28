use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const DATA_LINK_HEADER_LEN: usize = 10;
const DATA_LINK_FIELDS_LEN: usize = 5;
const DATA_CHUNK_LEN: usize = 16;
const CRC_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dnp3FunctionCode {
    Reset,
    Test,
    ConfirmedUserData,
    UnconfirmedUserData,
    RequestLinkStatus,
    Ack,
    LinkStatus,
    Unknown(u8),
}

impl From<u8> for Dnp3FunctionCode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Reset,
            0x02 => Self::Test,
            0x03 => Self::ConfirmedUserData,
            0x04 => Self::UnconfirmedUserData,
            0x09 => Self::RequestLinkStatus,
            0x0b => Self::Ack,
            0x0f => Self::LinkStatus,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dnp3AppFunctionCode {
    Confirm,
    Read,
    Write,
    Select,
    Operate,
    DirectOperate,
    DirectOperateNoResponse,
    ImmediateFreeze,
    ImmediateFreezeNoResponse,
    FreezeAndClear,
    ColdRestart,
    WarmRestart,
    DisableUnsolicited,
    EnableUnsolicited,
    Response,
    UnsolicitedResponse,
    Unknown(u8),
}

impl From<u8> for Dnp3AppFunctionCode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Confirm,
            0x01 => Self::Read,
            0x02 => Self::Write,
            0x03 => Self::Select,
            0x04 => Self::Operate,
            0x05 => Self::DirectOperate,
            0x06 => Self::DirectOperateNoResponse,
            0x07 => Self::ImmediateFreeze,
            0x08 => Self::ImmediateFreezeNoResponse,
            0x09 => Self::FreezeAndClear,
            0x0d => Self::ColdRestart,
            0x0e => Self::WarmRestart,
            0x14 => Self::DisableUnsolicited,
            0x15 => Self::EnableUnsolicited,
            0x81 => Self::Response,
            0x82 => Self::UnsolicitedResponse,
            value => Self::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dnp3Transport {
    pub fin: bool,
    pub fir: bool,
    pub sequence: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dnp3Application {
    pub fir: bool,
    pub fin: bool,
    pub confirm: bool,
    pub unsolicited: bool,
    pub sequence: u8,
    pub function: Dnp3AppFunctionCode,
    pub internal_indications: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnp3Message {
    pub length: u8,
    pub direction: bool,
    pub primary: bool,
    pub frame_count_bit: bool,
    pub frame_count_valid: bool,
    pub link_function: Dnp3FunctionCode,
    pub destination: u16,
    pub source: u16,
    pub transport: Option<Dnp3Transport>,
    pub application: Option<Dnp3Application>,
}

/// Parses DNP3 data-link and transport layers plus the fixed application header.
///
/// Object headers and point data depend on group, variation, and qualifier, so
/// they remain opaque. Header and chunk CRCs are skipped but not validated.
pub fn parse_dnp3_message(payload: &[u8]) -> Result<Dnp3Message, LayerError> {
    if payload.len() < DATA_LINK_HEADER_LEN {
        return Err(LayerError::InvalidLength);
    }
    if payload[..2] != [0x05, 0x64] {
        return Err(LayerError::InvalidHeader);
    }

    let length = payload[2];
    let control = payload[3];
    let user_data_len = usize::from(length).saturating_sub(DATA_LINK_FIELDS_LEN);
    let user_data = dechunk_user_data(&payload[DATA_LINK_HEADER_LEN..], user_data_len);
    if user_data.len() < user_data_len {
        return Err(LayerError::InvalidLength);
    }
    let Some(&transport_control) = user_data.first() else {
        return Err(LayerError::InvalidLength);
    };

    Ok(Dnp3Message {
        length,
        direction: control & 0x80 != 0,
        primary: control & 0x40 != 0,
        frame_count_bit: control & 0x20 != 0,
        frame_count_valid: control & 0x10 != 0,
        link_function: Dnp3FunctionCode::from(control & 0x0f),
        destination: u16::from_le_bytes([payload[4], payload[5]]),
        source: u16::from_le_bytes([payload[6], payload[7]]),
        transport: Some(parse_transport_control(transport_control)),
        application: parse_application(&user_data[1..]),
    })
}

/// Parses DNP3 while distinguishing bad magic from incomplete data.
#[must_use]
pub fn probe_dnp3(payload: &[u8]) -> ProbeResult<Dnp3Message> {
    if payload.len() < DATA_LINK_HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(DATA_LINK_HEADER_LEN),
            available: payload.len(),
        };
    }
    match parse_dnp3_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(LayerError::InvalidHeader) => ProbeResult::NoMatch,
        Err(LayerError::InvalidLength) => ProbeResult::Incomplete {
            needed: None,
            available: payload.len(),
        },
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("dnp3"),
            0,
        )),
    }
}

fn dechunk_user_data(payload: &[u8], expected_len: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(expected_len.min(payload.len()));
    let mut offset = 0;

    while data.len() < expected_len && offset < payload.len() {
        let block_len = DATA_CHUNK_LEN.min(expected_len - data.len());
        let available_len = block_len.min(payload.len() - offset);
        data.extend_from_slice(&payload[offset..offset + available_len]);
        offset += available_len;
        if available_len < block_len || payload.len().saturating_sub(offset) < CRC_LEN {
            break;
        }
        offset += CRC_LEN;
    }

    data
}

fn parse_transport_control(control: u8) -> Dnp3Transport {
    Dnp3Transport {
        fin: control & 0x80 != 0,
        fir: control & 0x40 != 0,
        sequence: control & 0x3f,
    }
}

fn parse_application(payload: &[u8]) -> Option<Dnp3Application> {
    let (&control, rest) = payload.split_first()?;
    let (&function, rest) = rest.split_first()?;
    let function = Dnp3AppFunctionCode::from(function);
    let internal_indications = matches!(
        function,
        Dnp3AppFunctionCode::Response | Dnp3AppFunctionCode::UnsolicitedResponse
    )
    .then(|| {
        rest.get(..2)
            .map(|iin| u16::from_le_bytes([iin[0], iin[1]]))
    })
    .flatten();

    Some(Dnp3Application {
        fir: control & 0x80 != 0,
        fin: control & 0x40 != 0,
        confirm: control & 0x20 != 0,
        unsolicited: control & 0x10 != 0,
        sequence: control & 0x0f,
        function,
        internal_indications,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DATA_LINK_HEADER_LEN, Dnp3AppFunctionCode, Dnp3FunctionCode, dechunk_user_data,
        parse_dnp3_message, probe_dnp3,
    };
    use crate::layer::{LayerError, ProbeResult};

    const FRAME_FOUR_PAYLOAD: [u8; 18] = [
        0x05, 0x64, 0x0b, 0xc4, 0x03, 0x00, 0x04, 0x00, 0xef, 0x7a, 0xc1, 0xc1, 0x01, 0x3c, 0x02,
        0x06, 0xb5, 0x76,
    ];

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn parses_fixture_frame_four_payload() {
        let message = parse_dnp3_message(&FRAME_FOUR_PAYLOAD).expect("DNP3 should parse");

        assert_eq!(message.length, 11);
        assert!(message.direction);
        assert!(message.primary);
        assert!(!message.frame_count_bit);
        assert!(!message.frame_count_valid);
        assert_eq!(message.link_function, Dnp3FunctionCode::UnconfirmedUserData);
        assert_eq!(message.destination, 3);
        assert_eq!(message.source, 4);

        let transport = message.transport.expect("transport header");
        assert!(transport.fin);
        assert!(transport.fir);
        assert_eq!(transport.sequence, 1);

        let application = message.application.expect("application header");
        assert!(application.fir);
        assert!(application.fin);
        assert!(!application.confirm);
        assert!(!application.unsolicited);
        assert_eq!(application.sequence, 1);
        assert_eq!(application.function, Dnp3AppFunctionCode::Read);
        assert_eq!(application.internal_indications, None);
    }

    #[test]
    fn rejects_invalid_sync_bytes() {
        let mut payload = FRAME_FOUR_PAYLOAD;
        payload[0] = 0xff;
        assert!(matches!(
            parse_dnp3_message(&payload),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_payload_shorter_than_data_link_header() {
        assert!(matches!(
            parse_dnp3_message(&FRAME_FOUR_PAYLOAD[..9]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_user_data_shorter_than_declared_length() {
        // Full 10-byte header (length byte declares 6 user-data bytes) but
        // only 3 bytes of user data follow - must not be treated as complete.
        assert!(matches!(
            parse_dnp3_message(&FRAME_FOUR_PAYLOAD[..13]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn probe_matches_a_real_frame() {
        assert!(matches!(
            probe_dnp3(&FRAME_FOUR_PAYLOAD),
            ProbeResult::Match(_)
        ));
    }

    #[test]
    fn probe_reports_no_match_for_bad_sync_bytes() {
        let mut payload = FRAME_FOUR_PAYLOAD;
        payload[0] = 0xff;
        // Bad magic is NoMatch; short input is Incomplete.
        assert_eq!(probe_dnp3(&payload), ProbeResult::NoMatch);
    }

    #[test]
    fn probe_reports_incomplete_for_a_short_buffer() {
        assert_eq!(
            probe_dnp3(&FRAME_FOUR_PAYLOAD[..9]),
            ProbeResult::Incomplete {
                needed: Some(DATA_LINK_HEADER_LEN),
                available: 9,
            }
        );
    }

    #[test]
    fn dechunks_multiple_data_blocks() {
        let expected: Vec<u8> = (0..20).collect();
        let mut chunked = Vec::new();
        chunked.extend_from_slice(&expected[..16]);
        chunked.extend_from_slice(&[0xaa, 0xbb]);
        chunked.extend_from_slice(&expected[16..]);
        chunked.extend_from_slice(&[0xcc, 0xdd]);

        assert_eq!(dechunk_user_data(&chunked, expected.len()), expected);

        let mut frame = vec![0x05, 0x64, 25, 0xc4, 3, 0, 4, 0, 0, 0];
        frame.extend_from_slice(&chunked);
        let message = parse_dnp3_message(&frame).expect("multi-chunk DNP3 should parse");
        assert!(message.transport.is_some());
        assert!(message.application.is_some());
    }
}
