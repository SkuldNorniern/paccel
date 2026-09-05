use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const FIXED_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcpHeader {
    pub version: u8,
    pub padding: bool,
    pub report_count: u8,
    pub packet_type: u8,
    pub length: u16,
    pub ssrc: u32,
}

pub fn parse_rtcp(payload: &[u8]) -> Result<RtcpHeader, LayerError> {
    if payload.len() < FIXED_HEADER_LEN {
        return Err(LayerError::InvalidLength);
    }

    let version = payload[0] >> 6;
    if version != 2 {
        return Err(LayerError::InvalidHeader);
    }

    let packet_type = payload[1];
    if !matches!(packet_type, 200..=204) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(RtcpHeader {
        version,
        padding: payload[0] & 0x20 != 0,
        report_count: payload[0] & 0x1f,
        packet_type,
        length: u16::from_be_bytes([payload[2], payload[3]]),
        ssrc: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
    })
}

/// Probes an RTCP packet by version and packet type.
///
/// RFC 3550 sec 6.1: the type is drawn from a small assigned range, which is
/// also how RFC 5761 sec 4 keeps RTCP apart from RTP on a shared port.
#[must_use]
pub fn probe_rtcp(payload: &[u8]) -> ProbeResult<RtcpHeader> {
    let Some(head) = payload.get(..2) else {
        return ProbeResult::Incomplete {
            needed: Some(FIXED_HEADER_LEN),
            available: payload.len(),
        };
    };
    if head[0] >> 6 != 2 || !matches!(head[1], 200..=204) {
        return ProbeResult::NoMatch;
    }
    if payload.len() < FIXED_HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(FIXED_HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_rtcp(payload) {
        Ok(header) => ProbeResult::Match(header),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("rtcp"),
            0,
        )),
    }
}
