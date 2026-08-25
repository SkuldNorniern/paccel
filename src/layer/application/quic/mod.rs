use crate::layer::LayerError;

#[cfg(feature = "quic-decrypt")]
pub mod decrypt;
#[cfg(feature = "quic-decrypt")]
pub mod keylog;

#[cfg(feature = "quic-decrypt")]
pub use decrypt::{
    DecryptedInitial, decrypt_initial_client_hello, decrypt_initial_packet,
    decrypt_packet_with_secret, extract_crypto_stream,
};
#[cfg(feature = "quic-decrypt")]
pub use keylog::{QuicKeyLog, QuicKeyLogLabel};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicLongHeader {
    pub version: u32,
    pub packet_type: u8,
    pub kind: QuicPacketType,
    pub is_initial: bool,
    pub is_version_negotiation: bool,
    pub fixed_bit: bool,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    /// Initial only. `None` for every other packet type.
    pub token: Option<Vec<u8>>,
    /// Declared length (bytes) of the packet-number-plus-payload region.
    /// Initial/0-RTT/Handshake only.
    pub length: Option<u64>,
    /// Byte offset into the original `payload` slice where the
    /// (still header-protected) packet number begins. Initial/0-RTT/Handshake
    /// only; needed to locate the PN once header protection is removed.
    pub packet_number_offset: Option<usize>,
    pub retry_token: Option<Vec<u8>>,
    pub retry_integrity_tag: Option<[u8; 16]>,
}

/// RFC 9000 sec 16 variable-length integer: top 2 bits of the first byte pick
/// the encoding length (1/2/4/8 bytes), remaining bits (of all length bytes)
/// are the value.
pub fn decode_varint(payload: &[u8]) -> Option<(u64, usize)> {
    let first = *payload.first()?;
    let len = 1usize << (first >> 6);
    let bytes = payload.get(..len)?;
    let mut value = u64::from(bytes[0] & 0x3f);
    for &byte in &bytes[1..] {
        value = (value << 8) | u64::from(byte);
    }
    Some((value, len))
}

/// Reconstructs a full QUIC packet number from its truncated wire encoding
/// using RFC 9000 Appendix A.3.
pub fn decode_packet_number(largest_pn: Option<u64>, truncated_pn: u32, pn_len: usize) -> u64 {
    let expected_pn = largest_pn.map_or(0, |pn| pn.saturating_add(1));
    let pn_nbits = pn_len.saturating_mul(8);
    let pn_win = u32::try_from(pn_nbits)
        .ok()
        .and_then(|bits| 1u64.checked_shl(bits))
        .unwrap_or(u64::MAX);
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win.saturating_sub(1);
    let candidate_pn = (expected_pn & !pn_mask) | u64::from(truncated_pn);
    let max_packet_number = 1u64 << 62;

    if let (Some(next_window), Some(expected_lower_bound), Some(packet_number_limit)) = (
        candidate_pn.checked_add(pn_win),
        expected_pn.checked_sub(pn_hwin),
        max_packet_number.checked_sub(pn_win),
    ) && candidate_pn <= expected_lower_bound
        && candidate_pn < packet_number_limit
    {
        return next_window;
    }

    if candidate_pn >= pn_win
        && expected_pn
            .checked_add(pn_hwin)
            .is_some_and(|expected_upper_bound| candidate_pn > expected_upper_bound)
    {
        return candidate_pn.saturating_sub(pn_win);
    }

    candidate_pn
}

pub fn quic_version_name(version: u32) -> &'static str {
    match version {
        0x0000_0000 => "version_negotiation",
        0x0000_0001 => "v1",
        0x6b33_43cf => "v2",
        0x709a_50c4 => "v2_draft",
        version if version & 0x0f0f_0f0f == 0x0a0a_0a0a => "greasing",
        _ => "unknown",
    }
}

const MAX_V1_V2_CID_LEN: usize = 20;

pub(crate) fn is_v1_or_v2_family(version: u32) -> bool {
    matches!(version, 0x0000_0001 | 0x6b33_43cf | 0x709a_50c4)
}

fn quic_packet_type(version: u32, packet_type: u8) -> QuicPacketType {
    match version {
        0x0000_0001 => match packet_type {
            0b00 => QuicPacketType::Initial,
            0b01 => QuicPacketType::ZeroRtt,
            0b10 => QuicPacketType::Handshake,
            0b11 => QuicPacketType::Retry,
            _ => QuicPacketType::Unknown,
        },
        // RFC 9369 sec 3.2 remaps v2's packet types; 0x709a50c4 is the pre-RFC draft codepoint, same layout.
        0x6b33_43cf | 0x709a_50c4 => match packet_type {
            0b00 => QuicPacketType::Retry,
            0b01 => QuicPacketType::Initial,
            0b10 => QuicPacketType::ZeroRtt,
            0b11 => QuicPacketType::Handshake,
            _ => QuicPacketType::Unknown,
        },
        _ => QuicPacketType::Unknown,
    }
}

pub fn parse_quic_long_header(payload: &[u8]) -> Result<QuicLongHeader, LayerError> {
    if payload.len() < 7 {
        return Err(LayerError::InvalidLength);
    }

    let first_byte = payload[0];
    if first_byte & 0x80 == 0 {
        return Err(LayerError::InvalidHeader);
    }

    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    // RFC 9287 allows negotiating away the fixed bit; record, don't reject on it.
    let fixed_bit = first_byte & 0x40 != 0;

    let known_version = is_v1_or_v2_family(version);

    let dcid_len = usize::from(payload[5]);
    if known_version && dcid_len > MAX_V1_V2_CID_LEN {
        return Err(LayerError::InvalidHeader);
    }
    let dcid_start = 6usize;
    let dcid_end = dcid_start
        .checked_add(dcid_len)
        .ok_or(LayerError::InvalidLength)?;
    let dcid = payload
        .get(dcid_start..dcid_end)
        .ok_or(LayerError::InvalidLength)?
        .to_vec();

    let scid_len = usize::from(*payload.get(dcid_end).ok_or(LayerError::InvalidLength)?);
    if known_version && scid_len > MAX_V1_V2_CID_LEN {
        return Err(LayerError::InvalidHeader);
    }
    let scid_start = dcid_end + 1;
    let scid_end = scid_start
        .checked_add(scid_len)
        .ok_or(LayerError::InvalidLength)?;
    let scid = payload
        .get(scid_start..scid_end)
        .ok_or(LayerError::InvalidLength)?
        .to_vec();

    let packet_type = (first_byte >> 4) & 0x03;
    let kind = quic_packet_type(version, packet_type);

    let mut token = None;
    let mut length = None;
    let mut packet_number_offset = None;
    let mut retry_token = None;
    let mut retry_integrity_tag = None;

    if known_version {
        match kind {
            QuicPacketType::Initial => {
                let (token_len, token_len_size) =
                    decode_varint(payload.get(scid_end..).ok_or(LayerError::InvalidLength)?)
                        .ok_or(LayerError::InvalidLength)?;
                let token_start = scid_end + token_len_size;
                let token_end = token_start
                    .checked_add(usize::try_from(token_len).map_err(|_| LayerError::InvalidLength)?)
                    .ok_or(LayerError::InvalidLength)?;
                token = Some(
                    payload
                        .get(token_start..token_end)
                        .ok_or(LayerError::InvalidLength)?
                        .to_vec(),
                );
                let (declared_length, length_size) =
                    decode_varint(payload.get(token_end..).ok_or(LayerError::InvalidLength)?)
                        .ok_or(LayerError::InvalidLength)?;
                length = Some(declared_length);
                packet_number_offset = Some(token_end + length_size);
            }
            QuicPacketType::ZeroRtt | QuicPacketType::Handshake => {
                let (declared_length, length_size) =
                    decode_varint(payload.get(scid_end..).ok_or(LayerError::InvalidLength)?)
                        .ok_or(LayerError::InvalidLength)?;
                length = Some(declared_length);
                packet_number_offset = Some(scid_end + length_size);
            }
            QuicPacketType::Retry => {
                const INTEGRITY_TAG_LEN: usize = 16;
                let tag_start = payload
                    .len()
                    .checked_sub(INTEGRITY_TAG_LEN)
                    .filter(|start| *start >= scid_end)
                    .ok_or(LayerError::InvalidLength)?;
                retry_token = Some(payload[scid_end..tag_start].to_vec());
                let mut tag = [0u8; INTEGRITY_TAG_LEN];
                tag.copy_from_slice(&payload[tag_start..]);
                retry_integrity_tag = Some(tag);
            }
            QuicPacketType::Unknown => {}
        }
    }

    Ok(QuicLongHeader {
        version,
        packet_type,
        kind,
        is_initial: kind == QuicPacketType::Initial,
        is_version_negotiation: version == 0,
        fixed_bit,
        dcid,
        scid,
        token,
        length,
        packet_number_offset,
        retry_token,
        retry_integrity_tag,
    })
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_n;

    use super::{QuicPacketType, decode_packet_number, parse_quic_long_header, quic_version_name};

    // token_length=0 (0x00), length=1 (0x01), 1 byte of (still-protected) packet number.
    const INITIAL_TAIL: [u8; 3] = [0x00, 0x01, 0x00];

    #[test]
    fn decodes_rfc_packet_number_example() {
        assert_eq!(
            decode_packet_number(Some(0xa82f_30ea), 0x9b32, 2),
            0xa82f_9b32
        );
    }

    #[test]
    fn decodes_packet_number_without_prior_state() {
        assert_eq!(decode_packet_number(None, 2, 1), 2);
    }

    #[test]
    fn decodes_small_monotonic_packet_number() {
        assert_eq!(decode_packet_number(Some(2), 3, 1), 3);
    }

    #[test]
    fn classifies_v1_initial_and_version_name() {
        let mut payload = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        payload.extend(INITIAL_TAIL);
        let header = parse_quic_long_header(&payload).unwrap();

        assert_eq!(header.kind, QuicPacketType::Initial);
        assert_eq!(quic_version_name(1), "v1");
        assert_eq!(header.token, Some(Vec::new()));
        assert_eq!(header.length, Some(1));
        assert_eq!(header.packet_number_offset, Some(payload.len() - 1));
    }

    #[test]
    fn classifies_v2_remapped_packet_type() {
        let mut payload = vec![0xd0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00];
        payload.extend(INITIAL_TAIL);
        let header = parse_quic_long_header(&payload).unwrap();

        assert_eq!(header.packet_type, 0b01);
        assert_eq!(header.kind, QuicPacketType::Initial);
        assert!(header.is_initial);
    }

    #[test]
    fn classifies_v2_draft_codepoint_with_same_layout_as_v2() {
        let mut payload = vec![0xd0, 0x70, 0x9a, 0x50, 0xc4, 0x00, 0x00];
        payload.extend(INITIAL_TAIL);
        let header = parse_quic_long_header(&payload).unwrap();

        assert_eq!(header.kind, QuicPacketType::Initial);
        assert!(header.is_initial);
    }

    #[test]
    fn does_not_reject_a_cleared_fixed_bit() {
        let mut payload = vec![0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        payload.extend(INITIAL_TAIL);
        let header = parse_quic_long_header(&payload).unwrap();

        assert!(!header.fixed_bit);
        assert_eq!(header.kind, QuicPacketType::Initial);
    }

    #[test]
    fn parses_handshake_length_and_pn_offset() {
        // Handshake has no token field, just length then PN.
        let payload = [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00];
        let header = parse_quic_long_header(&payload).unwrap();

        assert_eq!(header.kind, QuicPacketType::Handshake);
        assert_eq!(header.length, Some(2));
        assert_eq!(header.packet_number_offset, Some(8));
    }

    #[test]
    fn parses_retry_token_and_integrity_tag() {
        let mut payload = vec![0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        payload.extend([0xaa, 0xbb, 0xcc]); // retry token
        payload.extend([0u8; 16]); // integrity tag
        let header = parse_quic_long_header(&payload).unwrap();

        assert_eq!(header.kind, QuicPacketType::Retry);
        assert_eq!(header.retry_token, Some(vec![0xaa, 0xbb, 0xcc]));
        assert_eq!(header.retry_integrity_tag, Some([0u8; 16]));
    }

    #[test]
    fn rejects_oversized_dcid_for_known_versions_only() {
        let mut oversized = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 21];
        oversized.extend(repeat_n(0u8, 21));
        assert!(parse_quic_long_header(&oversized).is_err());

        let mut unknown_version = vec![0xc0, 0xff, 0x00, 0x00, 0x1d, 21];
        unknown_version.extend(repeat_n(0u8, 22));
        assert!(parse_quic_long_header(&unknown_version).is_ok());
    }

    #[test]
    fn names_greased_version_and_leaves_packet_type_unknown() {
        let header = parse_quic_long_header(&[0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 0x00, 0x00]).unwrap();

        assert_eq!(quic_version_name(header.version), "greasing");
        assert!(!header.is_initial);
        assert_eq!(header.kind, QuicPacketType::Unknown);
    }
}
