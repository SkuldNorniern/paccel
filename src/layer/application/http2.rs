pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FRAME_TYPE_DATA: u8 = 0x0;
pub const FRAME_TYPE_HEADERS: u8 = 0x1;
pub const FRAME_TYPE_PRIORITY: u8 = 0x2;
pub const FRAME_TYPE_RST_STREAM: u8 = 0x3;
pub const FRAME_TYPE_SETTINGS: u8 = 0x4;
pub const FRAME_TYPE_PUSH_PROMISE: u8 = 0x5;
pub const FRAME_TYPE_PING: u8 = 0x6;
pub const FRAME_TYPE_GOAWAY: u8 = 0x7;
pub const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;
pub const FRAME_TYPE_CONTINUATION: u8 = 0x9;

const FRAME_HEADER_LENGTH: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2FrameHeader {
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    pub stream_id: u32,
}

pub fn parse_http2_frames(payload: &[u8]) -> Vec<Http2FrameHeader> {
    let mut frames = Vec::new();
    let mut offset = if payload.starts_with(CONNECTION_PREFACE) {
        CONNECTION_PREFACE.len()
    } else {
        0
    };

    while let Some(header_end) = offset.checked_add(FRAME_HEADER_LENGTH) {
        let Some(
            [
                length_high,
                length_mid,
                length_low,
                frame_type,
                flags,
                stream_0,
                stream_1,
                stream_2,
                stream_3,
            ],
        ) = payload.get(offset..header_end)
        else {
            break;
        };

        let length = u32::from_be_bytes([0, *length_high, *length_mid, *length_low]);
        let Some(frame_end) = usize::try_from(length)
            .ok()
            .and_then(|body_length| header_end.checked_add(body_length))
        else {
            break;
        };
        if payload.get(header_end..frame_end).is_none() {
            break;
        }

        frames.push(Http2FrameHeader {
            length,
            frame_type: *frame_type,
            flags: *flags,
            stream_id: u32::from_be_bytes([*stream_0, *stream_1, *stream_2, *stream_3])
                & 0x7fff_ffff,
        });
        offset = frame_end;
    }

    frames
}

pub fn looks_like_http2(payload: &[u8]) -> bool {
    payload.starts_with(CONNECTION_PREFACE)
        || parse_http2_frames(payload)
            .first()
            .is_some_and(|frame| frame.frame_type == FRAME_TYPE_SETTINGS && frame.stream_id == 0)
}

#[cfg(test)]
mod tests {
    use super::{
        CONNECTION_PREFACE, FRAME_HEADER_LENGTH, FRAME_TYPE_DATA, FRAME_TYPE_GOAWAY,
        FRAME_TYPE_HEADERS, FRAME_TYPE_SETTINGS, FRAME_TYPE_WINDOW_UPDATE, Http2FrameHeader,
        looks_like_http2, parse_http2_frames,
    };

    const CLIENT_PREFACE_AND_FRAMES: &str = "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a0000120400000000000003000000640004000100000002000000000000040800000000003e7f00010000250105000000018286418b089d5c0b8170dc0bc0781f04856272d141ff7a8825b650c3cb882b8353032a2f2a";
    const SERVER_SETTINGS: &str = "00002a04000000000000010000100000020000000000040000ffff000500004000000800000000000300000064000600010000";
    const SETTINGS_ACK_AND_RESPONSE: &str = "00000004010000000000001e010400000001885f87497ca58ae819aa408df2b4a6aa62d95d86a92b24a84f84ac64216800000f00010000000168656c6c6f2066726f6d206832630a";
    const GOAWAY: &str = "000011070000000000000000000000000073687574646f776e00";

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn parses_client_preface_and_frames() {
        let payload = from_hex(CLIENT_PREFACE_AND_FRAMES);

        assert_eq!(
            parse_http2_frames(&payload),
            vec![
                Http2FrameHeader {
                    length: 18,
                    frame_type: FRAME_TYPE_SETTINGS,
                    flags: 0x00,
                    stream_id: 0,
                },
                Http2FrameHeader {
                    length: 4,
                    frame_type: FRAME_TYPE_WINDOW_UPDATE,
                    flags: 0x00,
                    stream_id: 0,
                },
                Http2FrameHeader {
                    length: 37,
                    frame_type: FRAME_TYPE_HEADERS,
                    flags: 0x05,
                    stream_id: 1,
                },
            ]
        );
        assert!(looks_like_http2(&payload));
    }

    #[test]
    fn parses_server_initial_settings() {
        let payload = from_hex(SERVER_SETTINGS);

        assert_eq!(
            parse_http2_frames(&payload),
            vec![Http2FrameHeader {
                length: 42,
                frame_type: FRAME_TYPE_SETTINGS,
                flags: 0x00,
                stream_id: 0,
            }]
        );
        assert!(looks_like_http2(&payload));
    }

    #[test]
    fn parses_settings_ack_headers_and_data() {
        let payload = from_hex(SETTINGS_ACK_AND_RESPONSE);

        assert_eq!(
            parse_http2_frames(&payload),
            vec![
                Http2FrameHeader {
                    length: 0,
                    frame_type: FRAME_TYPE_SETTINGS,
                    flags: 0x01,
                    stream_id: 0,
                },
                Http2FrameHeader {
                    length: 30,
                    frame_type: FRAME_TYPE_HEADERS,
                    flags: 0x04,
                    stream_id: 1,
                },
                Http2FrameHeader {
                    length: 15,
                    frame_type: FRAME_TYPE_DATA,
                    flags: 0x01,
                    stream_id: 1,
                },
            ]
        );
    }

    #[test]
    fn parses_goaway() {
        let payload = from_hex(GOAWAY);

        assert_eq!(
            parse_http2_frames(&payload),
            vec![Http2FrameHeader {
                length: 17,
                frame_type: FRAME_TYPE_GOAWAY,
                flags: 0x00,
                stream_id: 0,
            }]
        );
    }

    #[test]
    fn drops_truncated_frame() {
        let payload = from_hex(CLIENT_PREFACE_AND_FRAMES);
        let without_preface = payload
            .get(CONNECTION_PREFACE.len()..)
            .expect("capture contains the connection preface");
        let truncated = without_preface
            .get(..FRAME_HEADER_LENGTH + 1)
            .expect("capture contains a frame header and a trailing byte");

        assert!(parse_http2_frames(truncated).is_empty());
    }
}
