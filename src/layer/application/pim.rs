use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const HEADER_LEN: usize = 4;
/// The highest type IANA assigns; the field itself is four bits.
const MAX_MESSAGE_TYPE: u8 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PimHeader {
    pub version: u8,
    pub message_type: u8,
}

pub fn parse_pim_header(payload: &[u8]) -> Result<PimHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let version = header[0] >> 4;
    if version != 2 {
        return Err(LayerError::InvalidHeader);
    }
    // IANA assigns 0 to 12: RFC 7761 defines 0-8, RFC 3973 adds State Refresh,
    // RFC 5015 DF Election, RFC 6754 ECMP Redirect and RFC 8364 PFM.
    let message_type = header[0] & 0x0f;
    if message_type > MAX_MESSAGE_TYPE {
        return Err(LayerError::InvalidHeader);
    }

    Ok(PimHeader {
        version,
        message_type,
    })
}

/// Probes a PIM header by version and message type.
///
/// RFC 7761 sec 4.9: the version is 2 and the types stop at 8.
#[must_use]
pub fn probe_pim(payload: &[u8]) -> ProbeResult<PimHeader> {
    let Some(head) = payload.get(..1) else {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    };
    if head[0] >> 4 != 2 || head[0] & 0x0f > MAX_MESSAGE_TYPE {
        return ProbeResult::NoMatch;
    }
    if payload.len() < HEADER_LEN {
        return ProbeResult::Incomplete {
            needed: Some(HEADER_LEN),
            available: payload.len(),
        };
    }

    match parse_pim_header(payload) {
        Ok(value) => ProbeResult::Match(value),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("pim"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_pim_header;
    use crate::layer::LayerError;

    /// IANA assigns PIM types past the eight of RFC 7761: State Refresh
    /// (RFC 3973), DF Election (RFC 5015 BIDIR-PIM), ECMP Redirect (RFC 6754)
    /// and PFM (RFC 8364) are all deployed.
    #[test]
    fn parses_the_types_added_after_rfc_7761() {
        for message_type in 9..=12u8 {
            let header = [0x20 | message_type, 0x00, 0x00, 0x00];
            let parsed = parse_pim_header(&header);
            assert!(parsed.is_ok(), "type {message_type} was refused");
            assert_eq!(parsed.expect("checked").message_type, message_type);
        }
        assert!(
            parse_pim_header(&[0x2d, 0, 0, 0]).is_err(),
            "13 is unassigned"
        );
    }

    #[test]
    fn parses_pim_hello_header() {
        let header =
            parse_pim_header(&[0x20, 0x00, 0x12, 0x34]).expect("PIM hello header should parse");

        assert_eq!(header.version, 2);
        assert_eq!(header.message_type, 0);
    }

    #[test]
    fn rejects_wrong_version_and_short_header() {
        assert!(matches!(
            parse_pim_header(&[0x10, 0x00, 0x12, 0x34]),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_pim_header(&[0x20, 0x00, 0x12]),
            Err(LayerError::InvalidLength)
        ));
    }
}
