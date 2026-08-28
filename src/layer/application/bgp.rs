use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HEADER_LEN: usize = 19;
const MARKER_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpMessageType {
    Open,
    Update,
    Notification,
    Keepalive,
    RouteRefresh,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgpMessage {
    pub message_type: BgpMessageType,
    pub length: u16,
}

pub fn parse_bgp_message(payload: &[u8]) -> Result<BgpMessage, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    if header[..MARKER_LEN].iter().any(|byte| *byte != 0xff) {
        return Err(LayerError::InvalidHeader);
    }

    let length = u16::from_be_bytes([header[16], header[17]]);
    if (length as usize) < HEADER_LEN {
        return Err(LayerError::InvalidHeader);
    }

    let message_type = match header[18] {
        1 => BgpMessageType::Open,
        2 => BgpMessageType::Update,
        3 => BgpMessageType::Notification,
        4 => BgpMessageType::Keepalive,
        5 => BgpMessageType::RouteRefresh,
        _ => return Err(LayerError::InvalidHeader),
    };

    Ok(BgpMessage {
        message_type,
        length,
    })
}

/// Probes a BGP message using the marker and complete fixed header.
#[must_use]
pub fn probe_bgp(payload: &[u8]) -> ProbeResult<BgpMessage> {
    if payload.len() < HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    }
    if payload[..MARKER_LEN].iter().any(|byte| *byte != 0xff) {
        return ProbeResult::NoMatch;
    }

    match parse_bgp_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("bgp"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{BgpMessageType, parse_bgp_message, probe_bgp};
    use crate::layer::{LayerError, ProbeResult};

    fn header(msg_type: u8, length: u16) -> Vec<u8> {
        let mut bytes = vec![0xff; MARKER_LEN];
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.push(msg_type);
        bytes
    }

    use super::{HEADER_LEN, MARKER_LEN};

    #[test]
    fn parses_keepalive() {
        let bytes = header(4, 19);
        let msg = parse_bgp_message(&bytes).expect("keepalive should parse");
        assert_eq!(msg.message_type, BgpMessageType::Keepalive);
        assert_eq!(msg.length, 19);
    }

    #[test]
    fn parses_open() {
        let bytes = header(1, 29);
        let msg = parse_bgp_message(&bytes).expect("open should parse");
        assert_eq!(msg.message_type, BgpMessageType::Open);
    }

    #[test]
    fn rejects_bad_marker() {
        let mut bytes = header(4, 19);
        bytes[0] = 0x00;
        assert!(matches!(
            parse_bgp_message(&bytes),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_unknown_type() {
        let bytes = header(9, 19);
        assert!(matches!(
            parse_bgp_message(&bytes),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_short_payload() {
        assert!(matches!(
            parse_bgp_message(&[0xff; 10]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn probe_matches_a_keepalive() {
        assert!(matches!(probe_bgp(&header(4, 19)), ProbeResult::Match(_)));
    }

    #[test]
    fn probe_reports_no_match_for_a_bad_marker() {
        let mut bytes = header(4, 19);
        bytes[0] = 0;
        assert_eq!(probe_bgp(&bytes), ProbeResult::NoMatch);
    }

    #[test]
    fn probe_reports_incomplete_for_a_truncated_header() {
        let bytes = header(4, 19);
        assert_eq!(
            probe_bgp(&bytes[..18]),
            ProbeResult::Incomplete {
                needed: Some(HEADER_LEN),
                available: 18,
            }
        );
    }

    #[test]
    fn probe_reports_malformed_for_an_invalid_message_type() {
        assert!(matches!(
            probe_bgp(&header(9, 19)),
            ProbeResult::Malformed(_)
        ));
    }
}
