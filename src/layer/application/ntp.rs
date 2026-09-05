use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const NTP_HEADER_LEN: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpMessage {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: u32,
    pub reference_ts: u64,
    pub origin_ts: u64,
    pub receive_ts: u64,
    pub transmit_ts: u64,
}

pub fn parse_ntp_message(payload: &[u8]) -> Result<NtpMessage, LayerError> {
    if payload.len() < NTP_HEADER_LEN {
        return Err(LayerError::InvalidLength);
    }

    let first = payload[0];
    Ok(NtpMessage {
        leap: first >> 6,
        version: (first >> 3) & 0x07,
        mode: first & 0x07,
        stratum: payload[1],
        poll: payload[2] as i8,
        precision: payload[3] as i8,
        root_delay: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        root_dispersion: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        reference_id: u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]),
        reference_ts: u64::from_be_bytes(payload[16..24].try_into().expect("fixed NTP field")),
        origin_ts: u64::from_be_bytes(payload[24..32].try_into().expect("fixed NTP field")),
        receive_ts: u64::from_be_bytes(payload[32..40].try_into().expect("fixed NTP field")),
        transmit_ts: u64::from_be_bytes(payload[40..48].try_into().expect("fixed NTP field")),
    })
}

/// Probes an NTP message by version and stratum.
///
/// RFC 5905 sec 7.3: versions 1 to 4 are defined and the stratum stops at 16.
/// Every mode value is legal, so it carries no signal here.
#[must_use]
pub fn probe_ntp(payload: &[u8]) -> ProbeResult<NtpMessage> {
    let Some(head) = payload.get(..2) else {
        return ProbeResult::Incomplete {
            needed: Some(NTP_HEADER_LEN),
            available: payload.len(),
        };
    };
    if !matches!((head[0] >> 3) & 0x07, 1..=4) || head[1] > 16 {
        return ProbeResult::NoMatch;
    }
    if payload.len() < NTP_HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(NTP_HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_ntp_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("ntp"),
            0,
        )),
    }
}
