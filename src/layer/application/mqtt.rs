use crate::layer::LayerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    use super::{MqttPacketType, parse_mqtt_message};
    use crate::layer::LayerError;

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
}
