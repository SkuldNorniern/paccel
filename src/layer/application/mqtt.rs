use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MqttPacketType {
    Connect,
    ConnAck,
    Publish,
    PubAck,
    PubRec,
    PubRel,
    PubComp,
    Subscribe,
    SubAck,
    Unsubscribe,
    UnsubAck,
    PingReq,
    PingResp,
    Disconnect,
    /// MQTT 5.0 sec 3.15, for enhanced authentication.
    Auth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MqttMessage {
    pub packet_type: MqttPacketType,
    pub flags: u8,
    pub remaining_length: u32,
}

pub fn parse_mqtt_message(payload: &[u8]) -> Result<MqttMessage, LayerError> {
    let first = *payload.first().ok_or(LayerError::InvalidLength)?;
    let packet_type = match first >> 4 {
        1 => MqttPacketType::Connect,
        2 => MqttPacketType::ConnAck,
        3 => MqttPacketType::Publish,
        4 => MqttPacketType::PubAck,
        5 => MqttPacketType::PubRec,
        6 => MqttPacketType::PubRel,
        7 => MqttPacketType::PubComp,
        8 => MqttPacketType::Subscribe,
        9 => MqttPacketType::SubAck,
        10 => MqttPacketType::Unsubscribe,
        11 => MqttPacketType::UnsubAck,
        12 => MqttPacketType::PingReq,
        13 => MqttPacketType::PingResp,
        14 => MqttPacketType::Disconnect,
        15 => MqttPacketType::Auth,
        _ => return Err(LayerError::InvalidHeader),
    };
    let flags = first & 0x0f;
    let remaining_length = decode_remaining_length(&payload[1..])?;

    Ok(MqttMessage {
        packet_type,
        flags,
        remaining_length,
    })
}

/// Probes MQTT using its packet type and remaining-length framing.
#[must_use]
pub fn probe_mqtt(payload: &[u8]) -> ProbeResult<MqttMessage> {
    let Some(&first) = payload.first() else {
        return ProbeResult::Incomplete {
            needed: Some(1),
            available: 0,
        };
    };
    // MQTT 5.0 sec 2.1.2 adds AUTH as 15; only 0 is reserved.
    if !(1..=15).contains(&(first >> 4)) {
        return ProbeResult::NoMatch;
    }

    let mut remaining_length = 0usize;
    let mut multiplier = 1usize;
    let mut encoded_len = None;
    for (offset, &byte) in payload[1..].iter().take(4).enumerate() {
        let Some(component) = usize::from(byte & 0x7f).checked_mul(multiplier) else {
            return malformed_mqtt_probe(LayerError::InvalidLength);
        };
        let Some(value) = remaining_length.checked_add(component) else {
            return malformed_mqtt_probe(LayerError::InvalidLength);
        };
        remaining_length = value;
        if byte & 0x80 == 0 {
            encoded_len = Some(offset + 1);
            break;
        }
        let Some(next_multiplier) = multiplier.checked_mul(128) else {
            return malformed_mqtt_probe(LayerError::InvalidLength);
        };
        multiplier = next_multiplier;
    }

    let Some(encoded_len) = encoded_len else {
        return if payload.len() < 5 {
            ProbeResult::Incomplete {
                needed: None,
                available: payload.len(),
            }
        } else {
            malformed_mqtt_probe(LayerError::InvalidHeader)
        };
    };
    let Some(needed) = 1usize
        .checked_add(encoded_len)
        .and_then(|header_len| header_len.checked_add(remaining_length))
    else {
        return malformed_mqtt_probe(LayerError::InvalidLength);
    };
    if needed > payload.len() {
        return ProbeResult::Incomplete {
            needed: Some(needed),
            available: payload.len(),
        };
    }

    match parse_mqtt_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => malformed_mqtt_probe(error),
    }
}

fn malformed_mqtt_probe(error: LayerError) -> ProbeResult<MqttMessage> {
    ProbeResult::Malformed(ParseError::from_layer_error(
        &error,
        Layer::Application,
        Some("mqtt"),
        0,
    ))
}

fn decode_remaining_length(bytes: &[u8]) -> Result<u32, LayerError> {
    let mut value: u32 = 0;
    let mut multiplier: u32 = 1;
    for &byte in bytes.iter().take(4) {
        value += u32::from(byte & 0x7f) * multiplier;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        multiplier *= 128;
    }
    Err(LayerError::InvalidHeader)
}

#[cfg(test)]
mod tests {
    use super::{MqttPacketType, parse_mqtt_message, probe_mqtt};
    use crate::layer::{LayerError, ProbeResult};

    const PUBLISH: [u8; 4] = [0x30, 0x02, 0xab, 0xcd];

    /// MQTT 5.0 sec 2.1.2 Table 2-1 adds AUTH as packet type 15, used for
    /// enhanced authentication. Only 0 is reserved.
    #[test]
    fn parses_an_mqtt5_auth_packet() {
        let packet = [0xf0, 0x00];
        let message = parse_mqtt_message(&packet).expect("auth is a valid type");
        assert_eq!(message.packet_type, MqttPacketType::Auth);
        assert!(probe_mqtt(&packet).is_match());
    }

    #[test]
    fn parses_connect() {
        let payload = [0x10, 0x25, 0x00, 0x06, b'M', b'Q', b'I', b's', b'd', b'p'];
        let msg = parse_mqtt_message(&payload).expect("connect should parse");
        assert_eq!(msg.packet_type, MqttPacketType::Connect);
        assert_eq!(msg.flags, 0);
        assert_eq!(msg.remaining_length, 37);
    }

    #[test]
    fn parses_pingreq_with_zero_length() {
        let payload = [0xc0, 0x00];
        let msg = parse_mqtt_message(&payload).expect("pingreq should parse");
        assert_eq!(msg.packet_type, MqttPacketType::PingReq);
        assert_eq!(msg.remaining_length, 0);
    }

    #[test]
    fn parses_multi_byte_remaining_length() {
        let payload = [0x30, 0xc1, 0x02];
        let msg = parse_mqtt_message(&payload).expect("publish should parse");
        assert_eq!(msg.packet_type, MqttPacketType::Publish);
        assert_eq!(msg.remaining_length, 321);
    }

    #[test]
    fn rejects_unknown_packet_type() {
        assert!(matches!(
            parse_mqtt_message(&[0x00, 0x00]),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_empty_payload() {
        assert!(matches!(
            parse_mqtt_message(&[]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_unterminated_remaining_length() {
        assert!(matches!(
            parse_mqtt_message(&[0x10, 0x80, 0x80, 0x80, 0x80]),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn probe_matches_a_complete_publish() {
        assert!(matches!(probe_mqtt(&PUBLISH), ProbeResult::Match(_)));
    }

    #[test]
    fn probe_reports_no_match_for_a_reserved_packet_type() {
        assert_eq!(probe_mqtt(&[0x00, 0x00]), ProbeResult::NoMatch);
    }

    #[test]
    fn probe_reports_incomplete_for_a_truncated_packet() {
        assert_eq!(
            probe_mqtt(&PUBLISH[..3]),
            ProbeResult::Incomplete {
                needed: Some(PUBLISH.len()),
                available: 3,
            }
        );
    }

    #[test]
    fn probe_reports_malformed_for_an_overlong_remaining_length() {
        assert!(matches!(
            probe_mqtt(&[0x10, 0x80, 0x80, 0x80, 0x80]),
            ProbeResult::Malformed(_)
        ));
    }
}
