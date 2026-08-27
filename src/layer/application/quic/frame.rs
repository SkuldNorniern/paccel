use crate::layer::LayerError;

use super::decode_varint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicFrame<'a> {
    Padding {
        count: usize,
    },
    Ping,
    Ack {
        largest_acknowledged: u64,
        ack_delay: u64,
        ack_ranges: Vec<(u64, u64)>,
        ecn_counts: Option<(u64, u64, u64)>,
    },
    ResetStream {
        stream_id: u64,
        application_error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: u64,
        application_error_code: u64,
    },
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    NewToken {
        token: &'a [u8],
    },
    Stream {
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: &'a [u8],
    },
    MaxData {
        maximum_data: u64,
    },
    MaxStreamData {
        stream_id: u64,
        maximum_stream_data: u64,
    },
    MaxStreams {
        bidirectional: bool,
        maximum_streams: u64,
    },
    DataBlocked {
        maximum_data: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        maximum_stream_data: u64,
    },
    StreamsBlocked {
        bidirectional: bool,
        maximum_streams: u64,
    },
    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: &'a [u8],
        stateless_reset_token: &'a [u8; 16],
    },
    RetireConnectionId {
        sequence_number: u64,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason_phrase: &'a [u8],
    },
    HandshakeDone,
    Datagram {
        data: &'a [u8],
    },
    Unknown {
        frame_type: u64,
    },
}

/// Iterates the frames in a decrypted QUIC packet payload (RFC 9000 sec 19).
///
/// Yields `Err` and then stops (subsequent `.next()` calls return `None`) the
/// moment it hits a frame it cannot parse. This differs from
/// `extract_crypto_stream`, whose purpose-specific frame walk silently
/// truncates and returns the CRYPTO bytes assembled before the malformed frame.
pub struct QuicFrameIter<'a> {
    remaining: &'a [u8],
    poisoned: bool,
}

impl<'a> Iterator for QuicFrameIter<'a> {
    type Item = Result<QuicFrame<'a>, LayerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned || self.remaining.is_empty() {
            return None;
        }

        match parse_frame(self.remaining) {
            Ok((frame, consumed)) => {
                let Some(remaining) = self.remaining.get(consumed..) else {
                    self.poisoned = true;
                    return Some(Err(LayerError::InvalidLength));
                };
                self.remaining = remaining;
                Some(Ok(frame))
            }
            Err(error) => {
                self.poisoned = true;
                self.remaining = &[];
                Some(Err(error))
            }
        }
    }
}

pub fn iter_quic_frames(payload: &[u8]) -> QuicFrameIter<'_> {
    QuicFrameIter {
        remaining: payload,
        poisoned: false,
    }
}

struct FrameCursor<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> FrameCursor<'a> {
    fn after_type(payload: &'a [u8], type_size: usize) -> Self {
        Self {
            payload,
            offset: type_size,
        }
    }

    fn consumed(&self) -> usize {
        self.offset
    }

    fn read_varint(&mut self) -> Result<u64, LayerError> {
        let remaining = self
            .payload
            .get(self.offset..)
            .ok_or(LayerError::InvalidLength)?;
        let (value, size) = decode_varint(remaining).ok_or(LayerError::InvalidLength)?;
        self.offset = self
            .offset
            .checked_add(size)
            .ok_or(LayerError::InvalidLength)?;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, LayerError> {
        let value = *self
            .payload
            .get(self.offset)
            .ok_or(LayerError::InvalidLength)?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or(LayerError::InvalidLength)?;
        Ok(value)
    }

    fn read_bytes(&mut self, length: u64) -> Result<&'a [u8], LayerError> {
        let length = usize::try_from(length).map_err(|_| LayerError::InvalidLength)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(LayerError::InvalidLength)?;
        let bytes = self
            .payload
            .get(self.offset..end)
            .ok_or(LayerError::InvalidLength)?;
        self.offset = end;
        Ok(bytes)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], LayerError> {
        self.read_bytes(u64::try_from(N).map_err(|_| LayerError::InvalidLength)?)?
            .try_into()
            .map_err(|_| LayerError::InvalidLength)
    }

    fn read_array_ref<const N: usize>(&mut self) -> Result<&'a [u8; N], LayerError> {
        self.read_bytes(u64::try_from(N).map_err(|_| LayerError::InvalidLength)?)?
            .try_into()
            .map_err(|_| LayerError::InvalidLength)
    }

    fn read_remaining(&mut self) -> Result<&'a [u8], LayerError> {
        let remaining = self
            .payload
            .get(self.offset..)
            .ok_or(LayerError::InvalidLength)?;
        self.offset = self.payload.len();
        Ok(remaining)
    }
}

fn parse_frame(payload: &[u8]) -> Result<(QuicFrame<'_>, usize), LayerError> {
    let (frame_type, type_size) = decode_varint(payload).ok_or(LayerError::InvalidLength)?;
    let mut cursor = FrameCursor::after_type(payload, type_size);
    let frame = match frame_type {
        0x00 => parse_padding(&mut cursor)?,
        0x01 => QuicFrame::Ping,
        0x02 | 0x03 => parse_ack(&mut cursor, frame_type == 0x03)?,
        0x04 => parse_reset_stream(&mut cursor)?,
        0x05 => parse_stop_sending(&mut cursor)?,
        0x06 => parse_crypto(&mut cursor)?,
        0x07 => parse_new_token(&mut cursor)?,
        0x08..=0x0f => parse_stream(&mut cursor, frame_type)?,
        0x10 => QuicFrame::MaxData {
            maximum_data: cursor.read_varint()?,
        },
        0x11 => QuicFrame::MaxStreamData {
            stream_id: cursor.read_varint()?,
            maximum_stream_data: cursor.read_varint()?,
        },
        0x12 | 0x13 => parse_max_streams(&mut cursor, frame_type)?,
        0x14 => QuicFrame::DataBlocked {
            maximum_data: cursor.read_varint()?,
        },
        0x15 => QuicFrame::StreamDataBlocked {
            stream_id: cursor.read_varint()?,
            maximum_stream_data: cursor.read_varint()?,
        },
        0x16 | 0x17 => parse_streams_blocked(&mut cursor, frame_type)?,
        0x18 => parse_new_connection_id(&mut cursor)?,
        0x19 => QuicFrame::RetireConnectionId {
            sequence_number: cursor.read_varint()?,
        },
        // PATH_CHALLENGE/PATH_RESPONSE's fixed 8-byte raw Data layout is
        // standard/stable QUIC knowledge, not independently RFC-text-fetch-verified
        // this session due to the same tooling truncation issue.
        0x1a => QuicFrame::PathChallenge {
            data: cursor.read_array()?,
        },
        0x1b => QuicFrame::PathResponse {
            data: cursor.read_array()?,
        },
        // The CONNECTION_CLOSE QUIC/application-layer field layouts are
        // standard/stable QUIC knowledge, not independently RFC-text-fetch-verified
        // this session due to the same tooling truncation issue.
        0x1c | 0x1d => parse_connection_close(&mut cursor, frame_type == 0x1c)?,
        0x1e => QuicFrame::HandshakeDone,
        0x30 | 0x31 => parse_datagram(&mut cursor, frame_type == 0x31)?,
        _ => QuicFrame::Unknown { frame_type },
    };
    Ok((frame, cursor.consumed()))
}

fn parse_padding(cursor: &mut FrameCursor<'_>) -> Result<QuicFrame<'static>, LayerError> {
    let mut count = 1usize;
    while cursor
        .payload
        .get(cursor.offset)
        .is_some_and(|byte| *byte == 0)
    {
        cursor.offset = cursor
            .offset
            .checked_add(1)
            .ok_or(LayerError::InvalidLength)?;
        count = count.checked_add(1).ok_or(LayerError::InvalidLength)?;
    }
    Ok(QuicFrame::Padding { count })
}

fn parse_ack<'a>(cursor: &mut FrameCursor<'a>, has_ecn: bool) -> Result<QuicFrame<'a>, LayerError> {
    let largest_acknowledged = cursor.read_varint()?;
    let ack_delay = cursor.read_varint()?;
    let ack_range_count = cursor.read_varint()?;
    let first_ack_range = cursor.read_varint()?;

    let mut largest = largest_acknowledged;
    let mut smallest = largest
        .checked_sub(first_ack_range)
        .ok_or(LayerError::MalformedPacket)?;
    let mut ack_ranges = vec![(smallest, largest)];

    for _ in 0..ack_range_count {
        let gap = cursor.read_varint()?;
        let ack_range_length = cursor.read_varint()?;
        largest = smallest
            .checked_sub(gap)
            .and_then(|value| value.checked_sub(2))
            .ok_or(LayerError::MalformedPacket)?;
        smallest = largest
            .checked_sub(ack_range_length)
            .ok_or(LayerError::MalformedPacket)?;
        ack_ranges.push((smallest, largest));
    }

    let ecn_counts = if has_ecn {
        Some((
            cursor.read_varint()?,
            cursor.read_varint()?,
            cursor.read_varint()?,
        ))
    } else {
        None
    };
    Ok(QuicFrame::Ack {
        largest_acknowledged,
        ack_delay,
        ack_ranges,
        ecn_counts,
    })
}

fn parse_reset_stream(cursor: &mut FrameCursor<'_>) -> Result<QuicFrame<'static>, LayerError> {
    Ok(QuicFrame::ResetStream {
        stream_id: cursor.read_varint()?,
        application_error_code: cursor.read_varint()?,
        final_size: cursor.read_varint()?,
    })
}

fn parse_stop_sending(cursor: &mut FrameCursor<'_>) -> Result<QuicFrame<'static>, LayerError> {
    Ok(QuicFrame::StopSending {
        stream_id: cursor.read_varint()?,
        application_error_code: cursor.read_varint()?,
    })
}

fn parse_crypto<'a>(cursor: &mut FrameCursor<'a>) -> Result<QuicFrame<'a>, LayerError> {
    let offset = cursor.read_varint()?;
    let length = cursor.read_varint()?;
    let data = cursor.read_bytes(length)?;
    Ok(QuicFrame::Crypto { offset, data })
}

fn parse_new_token<'a>(cursor: &mut FrameCursor<'a>) -> Result<QuicFrame<'a>, LayerError> {
    let length = cursor.read_varint()?;
    let token = cursor.read_bytes(length)?;
    Ok(QuicFrame::NewToken { token })
}

fn parse_stream<'a>(
    cursor: &mut FrameCursor<'a>,
    frame_type: u64,
) -> Result<QuicFrame<'a>, LayerError> {
    let stream_id = cursor.read_varint()?;
    let offset = if frame_type & 0x04 != 0 {
        cursor.read_varint()?
    } else {
        0
    };
    let data = if frame_type & 0x02 != 0 {
        let length = cursor.read_varint()?;
        cursor.read_bytes(length)?
    } else {
        cursor.read_remaining()?
    };
    Ok(QuicFrame::Stream {
        stream_id,
        offset,
        fin: frame_type & 0x01 != 0,
        data,
    })
}

fn parse_max_streams(
    cursor: &mut FrameCursor<'_>,
    frame_type: u64,
) -> Result<QuicFrame<'static>, LayerError> {
    // The bidi-vs-uni bit convention - 0x12/even=bidi - is standard/stable QUIC
    // knowledge, not independently RFC-text-fetch-verified this session due to a
    // tooling limitation truncating that specific RFC subsection across every
    // source tried.
    Ok(QuicFrame::MaxStreams {
        bidirectional: frame_type == 0x12,
        maximum_streams: cursor.read_varint()?,
    })
}

fn parse_streams_blocked(
    cursor: &mut FrameCursor<'_>,
    frame_type: u64,
) -> Result<QuicFrame<'static>, LayerError> {
    // The bidi-vs-uni bit convention - 0x16/even=bidi - is standard/stable QUIC
    // knowledge, not independently RFC-text-fetch-verified this session due to a
    // tooling limitation truncating that specific RFC subsection across every
    // source tried.
    Ok(QuicFrame::StreamsBlocked {
        bidirectional: frame_type == 0x16,
        maximum_streams: cursor.read_varint()?,
    })
}

fn parse_new_connection_id<'a>(cursor: &mut FrameCursor<'a>) -> Result<QuicFrame<'a>, LayerError> {
    let sequence_number = cursor.read_varint()?;
    let retire_prior_to = cursor.read_varint()?;
    let connection_id_length = u64::from(cursor.read_u8()?);
    let connection_id = cursor.read_bytes(connection_id_length)?;
    let stateless_reset_token = cursor.read_array_ref()?;
    Ok(QuicFrame::NewConnectionId {
        sequence_number,
        retire_prior_to,
        connection_id,
        stateless_reset_token,
    })
}

fn parse_connection_close<'a>(
    cursor: &mut FrameCursor<'a>,
    transport_close: bool,
) -> Result<QuicFrame<'a>, LayerError> {
    let error_code = cursor.read_varint()?;
    let frame_type = if transport_close {
        Some(cursor.read_varint()?)
    } else {
        None
    };
    let reason_phrase_length = cursor.read_varint()?;
    let reason_phrase = cursor.read_bytes(reason_phrase_length)?;
    Ok(QuicFrame::ConnectionClose {
        error_code,
        frame_type,
        reason_phrase,
    })
}

fn parse_datagram<'a>(
    cursor: &mut FrameCursor<'a>,
    has_length: bool,
) -> Result<QuicFrame<'a>, LayerError> {
    let data = if has_length {
        let length = cursor.read_varint()?;
        cursor.read_bytes(length)?
    } else {
        cursor.read_remaining()?
    };
    Ok(QuicFrame::Datagram { data })
}

#[cfg(test)]
mod tests {
    use super::{QuicFrame, iter_quic_frames};
    use crate::layer::LayerError;

    fn parsed_frames(payload: &[u8]) -> Vec<QuicFrame<'_>> {
        iter_quic_frames(payload)
            .collect::<Result<Vec<_>, _>>()
            .expect("synthetic frames should parse")
    }

    #[test]
    fn parses_padding_ping_handshake_done_and_unknown() {
        let payload = [0x00, 0x00, 0x00, 0x01, 0x1e, 0x1f];

        assert_eq!(
            parsed_frames(&payload),
            vec![
                QuicFrame::Padding { count: 3 },
                QuicFrame::Ping,
                QuicFrame::HandshakeDone,
                QuicFrame::Unknown { frame_type: 0x1f },
            ]
        );
    }

    #[test]
    fn parses_ack_ranges_and_ack_ecn_counts() {
        let payload = [
            // ACK: largest=20, delay=5, one extra range, first range length=2.
            0x02, 20, 5, 1, 2, 1, 3,
            // ACK_ECN: largest=10, delay=4, no extra ranges, first range length=0.
            0x03, 10, 4, 0, 0, 7, 8, 9,
        ];

        assert_eq!(
            parsed_frames(&payload),
            vec![
                QuicFrame::Ack {
                    largest_acknowledged: 20,
                    ack_delay: 5,
                    // First: 20 - 2 = 18, so (18, 20). Next largest:
                    // 18 - gap(1) - 2 = 15; 15 - range_length(3) = 12.
                    ack_ranges: vec![(18, 20), (12, 15)],
                    ecn_counts: None,
                },
                QuicFrame::Ack {
                    largest_acknowledged: 10,
                    ack_delay: 4,
                    ack_ranges: vec![(10, 10)],
                    ecn_counts: Some((7, 8, 9)),
                },
            ]
        );
    }

    #[test]
    fn parses_reset_stop_crypto_and_new_token() {
        let payload = [
            0x04, 5, 6, 7, 0x05, 8, 9, 0x06, 2, 3, 0xaa, 0xbb, 0xcc, 0x07, 2, 0xdd, 0xee,
        ];

        assert_eq!(
            parsed_frames(&payload),
            vec![
                QuicFrame::ResetStream {
                    stream_id: 5,
                    application_error_code: 6,
                    final_size: 7,
                },
                QuicFrame::StopSending {
                    stream_id: 8,
                    application_error_code: 9,
                },
                QuicFrame::Crypto {
                    offset: 2,
                    data: &[0xaa, 0xbb, 0xcc],
                },
                QuicFrame::NewToken {
                    token: &[0xdd, 0xee],
                },
            ]
        );
    }

    #[test]
    fn parses_length_prefixed_and_remainder_stream_frames() {
        let payload = [
            // OFF, LEN, and FIN set. Stream ID 64 uses a two-byte varint.
            0x0f, 0x40, 0x40, 2, 3, 0xaa, 0xbb, 0xcc,
            // No flags: implicit offset zero, no FIN, and data is the remainder.
            0x08, 5, 0xdd, 0xee,
        ];

        assert_eq!(
            parsed_frames(&payload),
            vec![
                QuicFrame::Stream {
                    stream_id: 64,
                    offset: 2,
                    fin: true,
                    data: &[0xaa, 0xbb, 0xcc],
                },
                QuicFrame::Stream {
                    stream_id: 5,
                    offset: 0,
                    fin: false,
                    data: &[0xdd, 0xee],
                },
            ]
        );
    }

    #[test]
    fn parses_all_flow_control_frames_and_directions() {
        let payload = [
            0x10, 0x40, 0x40, 0x11, 2, 3, 0x12, 4, 0x13, 5, 0x14, 6, 0x15, 7, 8, 0x16, 9, 0x17, 10,
        ];

        assert_eq!(
            parsed_frames(&payload),
            vec![
                QuicFrame::MaxData { maximum_data: 64 },
                QuicFrame::MaxStreamData {
                    stream_id: 2,
                    maximum_stream_data: 3,
                },
                QuicFrame::MaxStreams {
                    bidirectional: true,
                    maximum_streams: 4,
                },
                QuicFrame::MaxStreams {
                    bidirectional: false,
                    maximum_streams: 5,
                },
                QuicFrame::DataBlocked { maximum_data: 6 },
                QuicFrame::StreamDataBlocked {
                    stream_id: 7,
                    maximum_stream_data: 8,
                },
                QuicFrame::StreamsBlocked {
                    bidirectional: true,
                    maximum_streams: 9,
                },
                QuicFrame::StreamsBlocked {
                    bidirectional: false,
                    maximum_streams: 10,
                },
            ]
        );
    }

    #[test]
    fn parses_connection_id_retirement_and_path_validation_frames() {
        let mut payload = vec![0x18, 2, 1, 4, 0xde, 0xad, 0xbe, 0xef];
        payload.extend(0u8..16);
        payload.extend([0x19, 2]);
        payload.push(0x1a);
        payload.extend(1u8..=8);
        payload.push(0x1b);
        payload.extend(9u8..=16);

        let expected_token: &[u8; 16] = payload
            .get(8..24)
            .expect("token range")
            .try_into()
            .expect("token has fixed length");
        assert_eq!(
            parsed_frames(&payload),
            vec![
                QuicFrame::NewConnectionId {
                    sequence_number: 2,
                    retire_prior_to: 1,
                    connection_id: &[0xde, 0xad, 0xbe, 0xef],
                    stateless_reset_token: expected_token,
                },
                QuicFrame::RetireConnectionId { sequence_number: 2 },
                QuicFrame::PathChallenge {
                    data: [1, 2, 3, 4, 5, 6, 7, 8],
                },
                QuicFrame::PathResponse {
                    data: [9, 10, 11, 12, 13, 14, 15, 16],
                },
            ]
        );
    }

    #[test]
    fn parses_transport_and_application_connection_close() {
        let payload = [0x1c, 10, 0x06, 3, b'b', b'a', b'd', 0x1d, 12, 2, b'n', b'o'];

        assert_eq!(
            parsed_frames(&payload),
            vec![
                QuicFrame::ConnectionClose {
                    error_code: 10,
                    frame_type: Some(0x06),
                    reason_phrase: b"bad",
                },
                QuicFrame::ConnectionClose {
                    error_code: 12,
                    frame_type: None,
                    reason_phrase: b"no",
                },
            ]
        );
    }

    #[test]
    fn parses_length_prefixed_and_remainder_datagrams() {
        let payload = [0x31, 3, 1, 2, 3, 0x30, 4, 5];

        assert_eq!(
            parsed_frames(&payload),
            vec![
                QuicFrame::Datagram { data: &[1, 2, 3] },
                QuicFrame::Datagram { data: &[4, 5] },
            ]
        );
    }

    #[test]
    fn malformed_frame_poisoning_yields_one_error_then_stops() {
        let payload = [0x01, 0x06, 0, 4, 1, 2];
        let mut frames = iter_quic_frames(&payload);

        assert!(matches!(frames.next(), Some(Ok(QuicFrame::Ping))));
        assert!(matches!(
            frames.next(),
            Some(Err(LayerError::InvalidLength))
        ));
        assert!(frames.next().is_none());
    }

    #[test]
    fn malformed_ack_range_underflow_poisoning_stops_iteration() {
        // largest=1 cannot contain a first ACK range with length 2.
        let payload = [0x02, 1, 0, 0, 2, 0x01];
        let mut frames = iter_quic_frames(&payload);

        assert!(matches!(
            frames.next(),
            Some(Err(LayerError::MalformedPacket))
        ));
        assert!(frames.next().is_none());
    }

    #[cfg(feature = "quic-decrypt")]
    #[test]
    fn parses_rfc9001_appendix_a2_crypto_and_padding() {
        use crate::layer::application::quic::decrypt::{
            PROTECTED_PACKET_HEX, decrypt_initial_packet, extract_crypto_stream, from_hex,
        };
        use crate::layer::application::quic::parse_quic_long_header;

        let packet = from_hex(PROTECTED_PACKET_HEX);
        let header = parse_quic_long_header(&packet).expect("RFC Initial header should parse");
        let decrypted =
            decrypt_initial_packet(&header, &packet).expect("RFC Initial should decrypt");
        let known_client_hello = extract_crypto_stream(&decrypted.payload);
        let mut frames = iter_quic_frames(&decrypted.payload);

        assert!(matches!(
            frames.next(),
            Some(Ok(QuicFrame::Crypto { offset: 0, data }))
                if data == known_client_hello.as_slice()
        ));
        assert!(matches!(
            frames.next(),
            Some(Ok(QuicFrame::Padding { count: 917 }))
        ));
        assert!(frames.next().is_none());
    }
}
