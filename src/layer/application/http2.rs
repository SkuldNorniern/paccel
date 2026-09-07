use crate::layer::{Layer, ParseError, ParseErrorKind, ProbeResult};

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

/// The header of every whole frame in the stream.
///
/// Framing comes from [`iter_http2_frames`], so this and the typed walk cannot
/// disagree about where one frame ends and the next begins.
#[must_use]
pub fn parse_http2_frames(payload: &[u8]) -> Vec<Http2FrameHeader> {
    iter_http2_frames(payload)
        .map(|frame| frame.header)
        .collect()
}

/// Frame flags, per RFC 9113 sec 6. A flag bit means different things on
/// different frame types, which is why they are read per type below rather
/// than exposed as one set.
const FLAG_END_STREAM: u8 = 0x01;
const FLAG_ACK: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

const PRIORITY_LEN: usize = 5;
const SETTING_ENTRY_LEN: usize = 6;

/// A stream's priority, from a PRIORITY frame or a HEADERS frame carrying one.
///
/// RFC 9113 sec 5.3.2 deprecates this scheme, but it is still on the wire and a
/// capture has to represent what was sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Priority {
    pub stream_dependency: u32,
    pub exclusive: bool,
    /// The wire value. RFC 9113 sec 6.3 defines the actual weight as this plus
    /// one, so it is not adjusted here.
    pub weight: u8,
}

impl Http2Priority {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let field = bytes.get(..PRIORITY_LEN)?;
        let dependency = u32::from_be_bytes([field[0], field[1], field[2], field[3]]);
        Some(Http2Priority {
            stream_dependency: dependency & 0x7fff_ffff,
            exclusive: dependency & 0x8000_0000 != 0,
            weight: field[4],
        })
    }
}

/// The settings carried by one SETTINGS frame, read on demand.
///
/// RFC 9113 sec 6.5.1: each entry is a 16-bit identifier and a 32-bit value.
/// Unknown identifiers are yielded rather than skipped, because a capture
/// should show what was actually negotiated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Settings<'a> {
    entries: &'a [u8],
}

impl<'a> Http2Settings<'a> {
    /// The raw entry bytes, a multiple of six.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.entries
    }

    /// How many settings the frame carries.
    #[must_use]
    pub fn len(self) -> usize {
        self.entries.len() / SETTING_ENTRY_LEN
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.entries.is_empty()
    }

    /// The value for `identifier`, if the frame set it. A frame may set the
    /// same identifier twice; the last one wins, as it does on the wire.
    #[must_use]
    pub fn get(self, identifier: u16) -> Option<u32> {
        self.into_iter().fold(None, |found, (candidate, value)| {
            if candidate == identifier {
                Some(value)
            } else {
                found
            }
        })
    }
}

impl<'a> IntoIterator for Http2Settings<'a> {
    type Item = (u16, u32);
    type IntoIter = Http2SettingsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Http2SettingsIter {
            entries: self.entries,
        }
    }
}

/// Yields each `(identifier, value)` of a SETTINGS frame.
#[derive(Clone, Copy, Debug)]
pub struct Http2SettingsIter<'a> {
    entries: &'a [u8],
}

impl Iterator for Http2SettingsIter<'_> {
    type Item = (u16, u32);

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.get(..SETTING_ENTRY_LEN)?;
        self.entries = &self.entries[SETTING_ENTRY_LEN..];
        Some((
            u16::from_be_bytes([entry[0], entry[1]]),
            u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.entries.len() / SETTING_ENTRY_LEN;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Http2SettingsIter<'_> {}

/// A frame body, decoded according to its type.
///
/// Borrows the buffer rather than copying: a HEADERS block can be large, and a
/// caller that only wants the frame types should not pay to copy every one.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2FrameBody<'a> {
    /// RFC 9113 sec 6.1. `data` has any padding already removed.
    Data { data: &'a [u8], end_stream: bool },
    /// RFC 9113 sec 6.2. `block` is a HPACK fragment, not yet decoded.
    Headers {
        block: &'a [u8],
        end_stream: bool,
        end_headers: bool,
        priority: Option<Http2Priority>,
    },
    /// RFC 9113 sec 6.3.
    Priority(Http2Priority),
    /// RFC 9113 sec 6.4.
    RstStream { error_code: u32 },
    /// RFC 9113 sec 6.5. An ACK carries no entries.
    Settings {
        settings: Http2Settings<'a>,
        ack: bool,
    },
    /// RFC 9113 sec 6.6.
    PushPromise {
        promised_stream_id: u32,
        block: &'a [u8],
        end_headers: bool,
    },
    /// RFC 9113 sec 6.7.
    Ping { opaque: [u8; 8], ack: bool },
    /// RFC 9113 sec 6.8.
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: &'a [u8],
    },
    /// RFC 9113 sec 6.9. The increment is 31 bits; a zero one is a protocol
    /// error the caller can act on.
    WindowUpdate { increment: u32 },
    /// RFC 9113 sec 6.10.
    Continuation { block: &'a [u8], end_headers: bool },
    /// RFC 9113 sec 4.1 requires an unknown type be ignored rather than
    /// refused, so the body is handed over undecoded.
    Unknown { data: &'a [u8] },
    /// The frame header was well formed but its body does not fit the type.
    Malformed(ParseError),
}

/// One frame: its header, and its body decoded for the header's type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http2Frame<'a> {
    pub header: Http2FrameHeader,
    pub body: Http2FrameBody<'a>,
}

/// Walks the frames in an HTTP/2 stream without allocating.
///
/// Stops at the first frame that has not fully arrived, leaving it in
/// [`Self::remainder`] so a caller reassembling a stream knows where to resume.
/// A malformed *body* does not stop the walk - the frame's own length says
/// where the next one starts, so one bad frame does not cost the rest.
#[derive(Clone, Debug)]
pub struct Http2FrameIter<'a> {
    rest: &'a [u8],
}

impl<'a> Http2FrameIter<'a> {
    /// Skips the client connection preface if the stream opens with one.
    #[must_use]
    pub fn new(payload: &'a [u8]) -> Self {
        let rest = payload.strip_prefix(CONNECTION_PREFACE).unwrap_or(payload);
        Http2FrameIter { rest }
    }

    /// The bytes not yet consumed: a partial frame, or empty.
    #[must_use]
    pub fn remainder(&self) -> &'a [u8] {
        self.rest
    }
}

impl<'a> Iterator for Http2FrameIter<'a> {
    type Item = Http2Frame<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header_bytes = self.rest.get(..FRAME_HEADER_LENGTH)?;
        let length = u32::from_be_bytes([0, header_bytes[0], header_bytes[1], header_bytes[2]]);
        let body_length = usize::try_from(length).ok()?;
        let frame_end = FRAME_HEADER_LENGTH.checked_add(body_length)?;
        let body_bytes = self.rest.get(FRAME_HEADER_LENGTH..frame_end)?;

        let header = Http2FrameHeader {
            length,
            frame_type: header_bytes[3],
            flags: header_bytes[4],
            stream_id: u32::from_be_bytes([
                header_bytes[5],
                header_bytes[6],
                header_bytes[7],
                header_bytes[8],
            ]) & 0x7fff_ffff,
        };
        self.rest = &self.rest[frame_end..];

        Some(Http2Frame {
            header,
            body: decode_body(header, body_bytes),
        })
    }
}

/// Walks the frames of an HTTP/2 stream, decoding each body for its type.
#[must_use]
pub fn iter_http2_frames(payload: &[u8]) -> Http2FrameIter<'_> {
    Http2FrameIter::new(payload)
}

fn malformed(kind: ParseErrorKind) -> Http2FrameBody<'static> {
    Http2FrameBody::Malformed(ParseError::new(Layer::Application, Some("http2"), 0, kind))
}

/// Strips the pad length byte and the padding it names.
///
/// RFC 9113 sec 6.1: a pad length that meets or exceeds what is left of the
/// frame is a protocol error, not a frame with no data.
fn strip_padding(body: &[u8], padded: bool) -> Result<&[u8], Http2FrameBody<'static>> {
    if !padded {
        return Ok(body);
    }
    let Some((&pad_length, rest)) = body.split_first() else {
        return Err(malformed(ParseErrorKind::Incomplete {
            needed: Some(1),
            available: 0,
        }));
    };
    let pad_length = usize::from(pad_length);
    if pad_length > rest.len() {
        return Err(malformed(ParseErrorKind::InvalidLength));
    }
    Ok(&rest[..rest.len() - pad_length])
}

/// RFC 9113 sec 6: each frame type is either connection-wide or belongs to a
/// stream, and a frame on the wrong one is a protocol error.
fn stream_id_in_scope(header: Http2FrameHeader) -> bool {
    match header.frame_type {
        FRAME_TYPE_DATA
        | FRAME_TYPE_HEADERS
        | FRAME_TYPE_PRIORITY
        | FRAME_TYPE_RST_STREAM
        | FRAME_TYPE_PUSH_PROMISE
        | FRAME_TYPE_CONTINUATION => header.stream_id != 0,
        FRAME_TYPE_SETTINGS | FRAME_TYPE_PING | FRAME_TYPE_GOAWAY => header.stream_id == 0,
        // WINDOW_UPDATE is valid on either, per sec 6.9. An unknown type is
        // ignored per sec 4.1, so it has no scope to be wrong about.
        _ => true,
    }
}

fn decode_body(header: Http2FrameHeader, body: &[u8]) -> Http2FrameBody<'_> {
    if !stream_id_in_scope(header) {
        return malformed(ParseErrorKind::InvalidValue);
    }
    match header.frame_type {
        FRAME_TYPE_DATA => decode_data(header, body),
        FRAME_TYPE_HEADERS => decode_headers(header, body),
        // RFC 9113 sec 6.3: the payload is exactly five bytes.
        FRAME_TYPE_PRIORITY if body.len() != PRIORITY_LEN => {
            malformed(ParseErrorKind::InvalidLength)
        }
        FRAME_TYPE_PRIORITY => Http2Priority::parse(body).map_or_else(
            || malformed(ParseErrorKind::InvalidLength),
            Http2FrameBody::Priority,
        ),
        FRAME_TYPE_RST_STREAM => match body {
            [a, b, c, d] => Http2FrameBody::RstStream {
                error_code: u32::from_be_bytes([*a, *b, *c, *d]),
            },
            _ => malformed(ParseErrorKind::InvalidLength),
        },
        FRAME_TYPE_SETTINGS => decode_settings(header, body),
        FRAME_TYPE_PUSH_PROMISE => decode_push_promise(header, body),
        FRAME_TYPE_PING => match <[u8; 8]>::try_from(body) {
            Ok(opaque) => Http2FrameBody::Ping {
                opaque,
                ack: header.flags & FLAG_ACK != 0,
            },
            Err(_) => malformed(ParseErrorKind::InvalidLength),
        },
        FRAME_TYPE_GOAWAY => decode_goaway(body),
        FRAME_TYPE_WINDOW_UPDATE => match body {
            [a, b, c, d] => Http2FrameBody::WindowUpdate {
                increment: u32::from_be_bytes([*a, *b, *c, *d]) & 0x7fff_ffff,
            },
            _ => malformed(ParseErrorKind::InvalidLength),
        },
        FRAME_TYPE_CONTINUATION => Http2FrameBody::Continuation {
            block: body,
            end_headers: header.flags & FLAG_END_HEADERS != 0,
        },
        _ => Http2FrameBody::Unknown { data: body },
    }
}

fn decode_data(header: Http2FrameHeader, body: &[u8]) -> Http2FrameBody<'_> {
    match strip_padding(body, header.flags & FLAG_PADDED != 0) {
        Ok(data) => Http2FrameBody::Data {
            data,
            end_stream: header.flags & FLAG_END_STREAM != 0,
        },
        Err(error) => error,
    }
}

fn decode_headers(header: Http2FrameHeader, body: &[u8]) -> Http2FrameBody<'_> {
    let unpadded = match strip_padding(body, header.flags & FLAG_PADDED != 0) {
        Ok(unpadded) => unpadded,
        Err(error) => return error,
    };

    let (priority, block) = if header.flags & FLAG_PRIORITY == 0 {
        (None, unpadded)
    } else {
        let Some(priority) = Http2Priority::parse(unpadded) else {
            return malformed(ParseErrorKind::InvalidLength);
        };
        (Some(priority), &unpadded[PRIORITY_LEN..])
    };

    Http2FrameBody::Headers {
        block,
        end_stream: header.flags & FLAG_END_STREAM != 0,
        end_headers: header.flags & FLAG_END_HEADERS != 0,
        priority,
    }
}

fn decode_settings(header: Http2FrameHeader, body: &[u8]) -> Http2FrameBody<'_> {
    let ack = header.flags & FLAG_ACK != 0;
    // RFC 9113 sec 6.5: an ACK carries no entries, and any other length is a
    // frame size error rather than a frame with settings in it.
    if ack && !body.is_empty() {
        return malformed(ParseErrorKind::InvalidLength);
    }
    if !body.len().is_multiple_of(SETTING_ENTRY_LEN) {
        return malformed(ParseErrorKind::InvalidLength);
    }
    Http2FrameBody::Settings {
        settings: Http2Settings { entries: body },
        ack,
    }
}

fn decode_push_promise(header: Http2FrameHeader, body: &[u8]) -> Http2FrameBody<'_> {
    let unpadded = match strip_padding(body, header.flags & FLAG_PADDED != 0) {
        Ok(unpadded) => unpadded,
        Err(error) => return error,
    };
    let Some(promised) = unpadded.get(..4) else {
        return malformed(ParseErrorKind::InvalidLength);
    };

    Http2FrameBody::PushPromise {
        promised_stream_id: u32::from_be_bytes([
            promised[0],
            promised[1],
            promised[2],
            promised[3],
        ]) & 0x7fff_ffff,
        block: &unpadded[4..],
        end_headers: header.flags & FLAG_END_HEADERS != 0,
    }
}

fn decode_goaway(body: &[u8]) -> Http2FrameBody<'_> {
    let Some(fixed) = body.get(..8) else {
        return malformed(ParseErrorKind::Incomplete {
            needed: Some(8),
            available: body.len(),
        });
    };
    Http2FrameBody::GoAway {
        last_stream_id: u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]) & 0x7fff_ffff,
        error_code: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
        debug_data: &body[8..],
    }
}

/// Whether the stream opens as HTTP/2: the client preface, or the SETTINGS
/// frame RFC 9113 sec 3.4 requires both peers to send first.
#[must_use]
pub fn looks_like_http2(payload: &[u8]) -> bool {
    payload.starts_with(CONNECTION_PREFACE)
        || iter_http2_frames(payload).next().is_some_and(|frame| {
            frame.header.frame_type == FRAME_TYPE_SETTINGS && frame.header.stream_id == 0
        })
}

/// Probes HTTP/2 by the client connection preface, or by a server's opening
/// SETTINGS frame when the capture joined after the preface.
///
/// RFC 9113 sec 3.4: the preface is fixed bytes, and both peers must open with
/// a SETTINGS frame on stream 0. A payload that is a prefix of the preface is
/// incomplete, not a mismatch - the rest may be in the next segment.
#[must_use]
pub fn probe_http2(payload: &[u8]) -> ProbeResult<Vec<Http2FrameHeader>> {
    if payload.starts_with(CONNECTION_PREFACE) {
        let frames = parse_http2_frames(payload);
        if frames.is_empty() {
            return ProbeResult::Incomplete {
                needed: Some(CONNECTION_PREFACE.len() + FRAME_HEADER_LENGTH),
                available: payload.len(),
            };
        }
        return ProbeResult::Match(frames);
    }
    if payload.len() < CONNECTION_PREFACE.len() && CONNECTION_PREFACE.starts_with(payload) {
        return ProbeResult::Incomplete {
            needed: Some(CONNECTION_PREFACE.len()),
            available: payload.len(),
        };
    }

    if payload.len() < FRAME_HEADER_LENGTH {
        return ProbeResult::Incomplete {
            needed: Some(FRAME_HEADER_LENGTH),
            available: payload.len(),
        };
    }
    let frames = parse_http2_frames(payload);
    match frames.first() {
        Some(frame) if frame.frame_type == FRAME_TYPE_SETTINGS && frame.stream_id == 0 => {
            ProbeResult::Match(frames)
        }
        _ => ProbeResult::NoMatch,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{
        CONNECTION_PREFACE, FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, FLAG_PADDED,
        FLAG_PRIORITY, FRAME_HEADER_LENGTH, FRAME_TYPE_DATA, FRAME_TYPE_GOAWAY, FRAME_TYPE_HEADERS,
        FRAME_TYPE_PING, FRAME_TYPE_PRIORITY, FRAME_TYPE_RST_STREAM, FRAME_TYPE_SETTINGS,
        FRAME_TYPE_WINDOW_UPDATE, Http2FrameBody, Http2FrameHeader, Http2Priority,
        iter_http2_frames, looks_like_http2, parse_http2_frames,
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

    fn frame(frame_type: u8, flags: u8, stream_id: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let length = u32::try_from(body.len()).expect("short body");
        bytes.extend(&length.to_be_bytes()[1..]);
        bytes.push(frame_type);
        bytes.push(flags);
        bytes.extend(stream_id.to_be_bytes());
        bytes.extend(body);
        bytes
    }

    /// RFC 9113 sec 6.3: a PRIORITY payload is exactly five bytes. Taking the
    /// first five of a longer one accepts a frame the peer must reject.
    #[test]
    fn a_priority_frame_is_exactly_five_bytes() {
        let five = frame(FRAME_TYPE_PRIORITY, 0, 1, &[0, 0, 0, 7, 201]);
        assert!(matches!(
            iter_http2_frames(&five).next().expect("one frame").body,
            Http2FrameBody::Priority(_)
        ));

        for length in [4usize, 6, 10] {
            let odd = frame(FRAME_TYPE_PRIORITY, 0, 1, &vec![0u8; length]);
            assert!(
                matches!(
                    iter_http2_frames(&odd).next().expect("one frame").body,
                    Http2FrameBody::Malformed(_)
                ),
                "a {length}-byte priority payload was accepted"
            );
        }
    }

    /// RFC 9113 sec 6: connection-wide frames belong on stream 0 and
    /// stream frames do not.
    #[test]
    fn a_frame_on_the_wrong_stream_is_malformed() {
        let wrong: [(u8, u32, &[u8]); 6] = [
            (FRAME_TYPE_DATA, 0, b"x"),
            (FRAME_TYPE_HEADERS, 0, b"x"),
            (FRAME_TYPE_RST_STREAM, 0, &[0, 0, 0, 0]),
            (FRAME_TYPE_SETTINGS, 1, &[]),
            (FRAME_TYPE_PING, 1, &[0; 8]),
            (FRAME_TYPE_GOAWAY, 1, &[0; 8]),
        ];
        for (frame_type, stream_id, body) in wrong {
            let stream = frame(frame_type, 0, stream_id, body);
            assert!(
                matches!(
                    iter_http2_frames(&stream).next().expect("one frame").body,
                    Http2FrameBody::Malformed(_)
                ),
                "type {frame_type:#x} on stream {stream_id} was accepted"
            );
        }
    }

    /// RFC 9113 sec 6.9: WINDOW_UPDATE is valid on the connection and on a
    /// stream, so neither is a scope error.
    #[test]
    fn a_window_update_is_valid_on_either_scope() {
        for stream_id in [0u32, 1] {
            let stream = frame(FRAME_TYPE_WINDOW_UPDATE, 0, stream_id, &7u32.to_be_bytes());
            assert_eq!(
                iter_http2_frames(&stream).next().expect("one frame").body,
                Http2FrameBody::WindowUpdate { increment: 7 }
            );
        }
    }

    #[test]
    fn decodes_a_settings_frame() {
        let mut body = Vec::new();
        body.extend(3u16.to_be_bytes());
        body.extend(100u32.to_be_bytes());
        body.extend(4u16.to_be_bytes());
        body.extend(65_535u32.to_be_bytes());
        let stream = frame(FRAME_TYPE_SETTINGS, 0, 0, &body);

        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        assert_eq!(frames.len(), 1);
        let Http2FrameBody::Settings { settings, ack } = frames[0].body else {
            panic!("expected settings, got {:?}", frames[0].body);
        };
        assert!(!ack);
        assert_eq!(settings.len(), 2);
        assert_eq!(settings.get(3), Some(100));
        assert_eq!(settings.get(4), Some(65_535));
        assert_eq!(settings.get(99), None, "an unset identifier is absent");
        assert_eq!(
            settings.into_iter().collect::<Vec<_>>(),
            vec![(3, 100), (4, 65_535)]
        );
    }

    /// RFC 9113 sec 6.5: a SETTINGS ACK carries no entries, so a non-empty one
    /// is a frame size error rather than settings to apply.
    #[test]
    fn a_settings_ack_carrying_entries_is_malformed() {
        let mut body = Vec::new();
        body.extend(3u16.to_be_bytes());
        body.extend(100u32.to_be_bytes());
        let stream = frame(FRAME_TYPE_SETTINGS, FLAG_ACK, 0, &body);

        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        assert!(matches!(frames[0].body, Http2FrameBody::Malformed(_)));
    }

    #[test]
    fn a_settings_frame_of_a_partial_entry_is_malformed() {
        let stream = frame(FRAME_TYPE_SETTINGS, 0, 0, &[0, 3, 0, 0]);
        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        assert!(matches!(frames[0].body, Http2FrameBody::Malformed(_)));
    }

    /// RFC 9113 sec 6.1: the pad length byte and the padding it names are not
    /// part of the data.
    #[test]
    fn padding_is_removed_from_a_data_frame() {
        let mut body = vec![4];
        body.extend(b"hello");
        body.extend([0, 0, 0, 0]);
        let stream = frame(FRAME_TYPE_DATA, FLAG_PADDED | FLAG_END_STREAM, 1, &body);

        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        let Http2FrameBody::Data { data, end_stream } = frames[0].body else {
            panic!("expected data, got {:?}", frames[0].body);
        };
        assert_eq!(data, b"hello");
        assert!(end_stream);
    }

    /// A pad length that eats past the end of the frame is a protocol error,
    /// not an empty frame. Reading it as a length would underflow.
    #[test]
    fn padding_longer_than_the_frame_is_malformed() {
        let stream = frame(FRAME_TYPE_DATA, FLAG_PADDED, 1, &[200, 1, 2, 3]);
        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        assert!(
            matches!(frames[0].body, Http2FrameBody::Malformed(_)),
            "got {:?}",
            frames[0].body
        );
    }

    #[test]
    fn a_headers_frame_carries_its_priority_and_block() {
        let mut body = vec![2];
        body.extend(0x8000_0007u32.to_be_bytes());
        body.push(201);
        body.extend(b"hpack");
        body.extend([0, 0]);
        let stream = frame(
            FRAME_TYPE_HEADERS,
            FLAG_PADDED | FLAG_PRIORITY | FLAG_END_HEADERS,
            5,
            &body,
        );

        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        let Http2FrameBody::Headers {
            block,
            end_headers,
            priority,
            ..
        } = frames[0].body
        else {
            panic!("expected headers, got {:?}", frames[0].body);
        };
        assert_eq!(block, b"hpack", "padding and priority both come off");
        assert!(end_headers);
        assert_eq!(
            priority,
            Some(Http2Priority {
                stream_dependency: 7,
                exclusive: true,
                weight: 201,
            })
        );
    }

    #[test]
    fn decodes_goaway_with_debug_data() {
        let mut body = Vec::new();
        body.extend(9u32.to_be_bytes());
        body.extend(2u32.to_be_bytes());
        body.extend(b"shutdown");
        let stream = frame(FRAME_TYPE_GOAWAY, 0, 0, &body);

        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        let Http2FrameBody::GoAway {
            last_stream_id,
            error_code,
            debug_data,
        } = frames[0].body
        else {
            panic!("expected goaway, got {:?}", frames[0].body);
        };
        assert_eq!(last_stream_id, 9);
        assert_eq!(error_code, 2);
        assert_eq!(debug_data, b"shutdown");
    }

    /// RFC 9113 sec 6.9 reserves the top bit of the increment.
    #[test]
    fn a_window_update_ignores_the_reserved_bit() {
        let stream = frame(
            FRAME_TYPE_WINDOW_UPDATE,
            0,
            1,
            &0xffff_ffffu32.to_be_bytes(),
        );
        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        assert_eq!(
            frames[0].body,
            Http2FrameBody::WindowUpdate {
                increment: 0x7fff_ffff
            }
        );
    }

    /// RFC 9113 sec 4.1: an unknown frame type must be ignored, not refused.
    #[test]
    fn an_unknown_frame_type_is_handed_over_undecoded() {
        let stream = frame(0xef, 0, 1, b"whatever");
        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        assert_eq!(
            frames[0].body,
            Http2FrameBody::Unknown { data: b"whatever" }
        );
    }

    /// A stream cut mid-frame leaves the partial frame in the remainder, so a
    /// caller reassembling TCP knows where to resume rather than losing it.
    #[test]
    fn a_partial_trailing_frame_is_left_in_the_remainder() {
        let mut stream = frame(FRAME_TYPE_PING, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let tail = frame(FRAME_TYPE_DATA, 0, 1, b"cut here");
        let cut = tail.len() - 3;
        stream.extend(&tail[..cut]);

        let mut frames = iter_http2_frames(&stream);
        assert!(matches!(
            frames.next().expect("the ping is whole").body,
            Http2FrameBody::Ping { ack: false, .. }
        ));
        assert!(frames.next().is_none(), "the cut frame is not yielded");
        assert_eq!(
            frames.remainder(),
            &tail[..cut],
            "the partial frame is kept for the caller to resume with"
        );
    }

    /// One bad body must not cost the frames after it: the header's own length
    /// says where the next frame starts.
    #[test]
    fn a_malformed_body_does_not_stop_the_walk() {
        let mut stream = frame(FRAME_TYPE_PING, 0, 0, &[1, 2, 3]);
        stream.extend(frame(FRAME_TYPE_WINDOW_UPDATE, 0, 1, &7u32.to_be_bytes()));

        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        assert_eq!(frames.len(), 2);
        assert!(matches!(frames[0].body, Http2FrameBody::Malformed(_)));
        assert_eq!(
            frames[1].body,
            Http2FrameBody::WindowUpdate { increment: 7 }
        );
    }

    #[test]
    fn the_iterator_skips_the_connection_preface() {
        let mut stream = CONNECTION_PREFACE.to_vec();
        stream.extend(frame(FRAME_TYPE_SETTINGS, 0, 0, &[]));

        let frames: Vec<_> = iter_http2_frames(&stream).collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].header.frame_type, FRAME_TYPE_SETTINGS);
    }

    /// The typed walk and the header-only one must agree on framing, or one of
    /// them is reading the stream wrongly.
    #[test]
    fn the_iterator_agrees_with_the_header_walk() {
        let payload = from_hex(CLIENT_PREFACE_AND_FRAMES);
        let headers: Vec<_> = iter_http2_frames(&payload)
            .map(|frame| frame.header)
            .collect();
        assert_eq!(headers, parse_http2_frames(&payload));
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
