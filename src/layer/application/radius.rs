use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const RADIUS_FIXED_MESSAGE_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadiusMessage {
    pub code: u8,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadiusAttribute {
    pub attribute_type: u8,
    pub data: Vec<u8>,
}

pub fn parse_radius_message(payload: &[u8]) -> Result<RadiusMessage, LayerError> {
    if payload.len() < RADIUS_FIXED_MESSAGE_LEN {
        return Err(LayerError::InvalidLength);
    }

    let length = u16::from_be_bytes([payload[2], payload[3]]);
    let message_end = usize::from(length).min(payload.len());
    let bounded_payload = &payload[..message_end];

    let mut authenticator = [0; 16];
    authenticator.copy_from_slice(&payload[4..RADIUS_FIXED_MESSAGE_LEN]);

    let mut attributes = Vec::new();
    let mut offset = RADIUS_FIXED_MESSAGE_LEN;
    while offset < message_end {
        let Some(&attribute_type) = bounded_payload.get(offset) else {
            break;
        };
        offset += 1;

        let Some(&attribute_length) = bounded_payload.get(offset) else {
            break;
        };
        if attribute_length < 2 {
            break;
        }
        offset += 1;

        let attribute_end = offset + usize::from(attribute_length - 2);
        let Some(data) = bounded_payload.get(offset..attribute_end) else {
            break;
        };

        attributes.push(RadiusAttribute {
            attribute_type,
            data: data.to_vec(),
        });
        offset = attribute_end;
    }

    Ok(RadiusMessage {
        code: payload[0],
        identifier: payload[1],
        length,
        authenticator,
        attributes,
    })
}

/// Probes a RADIUS message by code and length.
///
/// RFC 2865 sec 3: the length field covers the whole message and is at least
/// 20, which is a far stronger check than the port alone.
#[must_use]
pub fn probe_radius(payload: &[u8]) -> ProbeResult<RadiusMessage> {
    let Some(head) = payload.get(..4) else {
        return ProbeResult::Incomplete {
            needed: Some(RADIUS_FIXED_MESSAGE_LEN),
            available: payload.len(),
        };
    };
    if !matches!(head[0], 1..=13 | 40..=45) {
        return ProbeResult::NoMatch;
    }
    let length = usize::from(u16::from_be_bytes([head[2], head[3]]));
    if length < RADIUS_FIXED_MESSAGE_LEN {
        return ProbeResult::NoMatch;
    }
    if payload.len() < length {
        return ProbeResult::Incomplete {
            needed: Some(length),
            available: payload.len(),
        };
    }

    match parse_radius_message(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("radius"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_radius_message;
    use crate::layer::LayerError;

    const FRAME_ONE_PAYLOAD: [u8; 87] = [
        0x01, 0x67, 0x00, 0x57, 0x40, 0xb6, 0x64, 0xdb, 0xf5, 0xd6, 0x81, 0xb2, 0xad, 0xbd, 0x17,
        0x69, 0x51, 0x51, 0x18, 0xc8, 0x01, 0x07, 0x73, 0x74, 0x65, 0x76, 0x65, 0x02, 0x12, 0xdb,
        0xc6, 0xc4, 0xb7, 0x58, 0xbe, 0x14, 0xf0, 0x05, 0xb3, 0x87, 0x7c, 0x9e, 0x2f, 0xb6, 0x01,
        0x04, 0x06, 0xc0, 0xa8, 0x00, 0x1c, 0x05, 0x06, 0x00, 0x00, 0x00, 0x7b, 0x50, 0x12, 0x5f,
        0x0f, 0x86, 0x47, 0xe8, 0xc8, 0x9b, 0xd8, 0x81, 0x36, 0x42, 0x68, 0xfc, 0xd0, 0x45, 0x32,
        0x4f, 0x0c, 0x02, 0x66, 0x00, 0x0a, 0x01, 0x73, 0x74, 0x65, 0x76, 0x65,
    ];

    #[test]
    fn parses_fixture_frame_one() {
        let message =
            parse_radius_message(&FRAME_ONE_PAYLOAD).expect("RADIUS message should parse");

        assert_eq!(message.code, 1);
        assert_eq!(message.identifier, 103);
        assert_eq!(message.length, 87);
        assert_eq!(
            message.authenticator,
            [
                0x40, 0xb6, 0x64, 0xdb, 0xf5, 0xd6, 0x81, 0xb2, 0xad, 0xbd, 0x17, 0x69, 0x51, 0x51,
                0x18, 0xc8,
            ]
        );
        assert_eq!(message.attributes[0].attribute_type, 1);
        assert_eq!(message.attributes[0].data, b"steve");
        assert_eq!(message.attributes[1].attribute_type, 2);
        assert_eq!(message.attributes[1].data.len(), 16);
    }

    #[test]
    fn rejects_payload_shorter_than_fixed_header() {
        assert!(matches!(
            parse_radius_message(&[0; 19]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn keeps_attributes_before_invalid_attribute_length() {
        for invalid_length in [0, 1] {
            let mut payload = vec![1, 7, 0, 29];
            payload.extend_from_slice(&[0; 16]);
            payload.extend_from_slice(&[1, 5, b'b', b'o', b'b']);
            payload.extend_from_slice(&[2, invalid_length, 0, 0]);

            let message = parse_radius_message(&payload).expect("invalid trailing AVP is lenient");
            assert_eq!(message.attributes.len(), 1);
            assert_eq!(message.attributes[0].attribute_type, 1);
            assert_eq!(message.attributes[0].data, b"bob");
        }
    }
}
