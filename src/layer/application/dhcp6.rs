use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const DHCP6_FIXED_MESSAGE_LEN: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp6Message {
    pub msg_type: u8,
    pub transaction_id: u32,
    pub options: Vec<Dhcp6Option>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp6Option {
    pub code: u16,
    pub data: Vec<u8>,
}

pub fn parse_dhcp6_message(payload: &[u8]) -> Result<Dhcp6Message, LayerError> {
    if payload.len() < DHCP6_FIXED_MESSAGE_LEN {
        return Err(LayerError::InvalidLength);
    }

    let mut options = Vec::new();
    let mut offset = DHCP6_FIXED_MESSAGE_LEN;
    while offset < payload.len() {
        let Some(code_bytes) = payload.get(offset..offset + 2) else {
            break;
        };
        let code = u16::from_be_bytes([code_bytes[0], code_bytes[1]]);
        offset += 2;

        let Some(length_bytes) = payload.get(offset..offset + 2) else {
            break;
        };
        let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]);
        offset += 2;
        let option_end = offset + usize::from(length);
        let Some(data) = payload.get(offset..option_end) else {
            break;
        };

        options.push(Dhcp6Option {
            code,
            data: data.to_vec(),
        });
        offset = option_end;
    }

    // Relay types 12 and 13 use different framing; this passive parser still
    // reads their first four bytes as client/server framing.
    Ok(Dhcp6Message {
        msg_type: payload[0],
        transaction_id: u32::from_be_bytes([0, payload[1], payload[2], payload[3]]),
        options,
    })
}

/// Probes a DHCPv6 message by its message type.
///
/// RFC 8415 sec 7.3 assigns 1 to 13; anything else is not DHCPv6.
#[must_use]
pub fn probe_dhcp6(payload: &[u8]) -> ProbeResult<Dhcp6Message> {
    let Some(&message_type) = payload.first() else {
        return ProbeResult::Incomplete {
            needed: Some(DHCP6_FIXED_MESSAGE_LEN),
            available: 0,
        };
    };
    // RFC 8415 sec 7.3 defines 1 to 13; IANA carries the registry on to 35
    // with leasequery (RFC 5007), DHCPv4-over-DHCPv6 (RFC 7341) and failover
    // (RFC 8156).
    if !matches!(message_type, 1..=35) {
        return ProbeResult::NoMatch;
    }
    if payload.len() < DHCP6_FIXED_MESSAGE_LEN {
        return ProbeResult::Incomplete {
            needed: Some(DHCP6_FIXED_MESSAGE_LEN),
            available: payload.len(),
        };
    }

    match parse_dhcp6_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("dhcp6"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{Dhcp6Option, parse_dhcp6_message, probe_dhcp6};
    use crate::layer::LayerError;
    use crate::layer::ProbeResult;

    /// The registry runs past RFC 8415's thirteen: leasequery (RFC 5007) and
    /// DHCPv4-over-DHCPv6 (RFC 7341) are both in use.
    #[test]
    fn probes_the_message_types_added_after_rfc_8415() {
        for message_type in [14u8, 20, 35] {
            let message = [message_type, 0x00, 0x00, 0x01];
            assert!(
                probe_dhcp6(&message).is_match(),
                "type {message_type} was refused"
            );
        }
        assert!(matches!(probe_dhcp6(&[36, 0, 0, 1]), ProbeResult::NoMatch));
    }

    #[test]
    fn parses_minimal_solicit() {
        let payload = [
            1, 0x10, 0x08, 0x74, 0, 1, 0, 14, 0, 1, 0, 1, 0x2a, 0x2b, 0x2c, 0x2d, 0, 1, 2, 3, 4, 5,
        ];

        let message = parse_dhcp6_message(&payload).expect("DHCPv6 message should parse");
        assert_eq!(message.msg_type, 1);
        assert_eq!(message.transaction_id, 0x10_0874);
        assert_eq!(
            message.options,
            vec![Dhcp6Option {
                code: 1,
                data: vec![0, 1, 0, 1, 0x2a, 0x2b, 0x2c, 0x2d, 0, 1, 2, 3, 4, 5],
            }]
        );
    }

    #[test]
    fn keeps_options_before_truncated_trailing_option() {
        let payload = [1, 0x10, 0x08, 0x74, 0, 8, 0, 2, 0, 0, 0, 6, 0, 4, 0, 23];

        let message = parse_dhcp6_message(&payload).expect("trailing truncation is lenient");
        assert_eq!(
            message.options,
            vec![Dhcp6Option {
                code: 8,
                data: vec![0, 0],
            }]
        );
    }

    #[test]
    fn rejects_payload_shorter_than_fixed_header() {
        assert!(matches!(
            parse_dhcp6_message(&[1, 0x10, 0x08]),
            Err(LayerError::InvalidLength)
        ));
    }
}
