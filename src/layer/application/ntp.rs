use crate::layer::LayerError;

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
