use crate::layer::LayerError;

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
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
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

fn quic_packet_type(version: u32, packet_type: u8) -> QuicPacketType {
    match version {
        0x0000_0001 => match packet_type {
            0b00 => QuicPacketType::Initial,
            0b01 => QuicPacketType::ZeroRtt,
            0b10 => QuicPacketType::Handshake,
            0b11 => QuicPacketType::Retry,
            _ => QuicPacketType::Unknown,
        },
        // RFC 9369 sec 3.2 remaps the long-header packet types for QUIC v2.
        0x6b33_43cf => match packet_type {
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
    if version != 0 && first_byte & 0x40 == 0 {
        return Err(LayerError::InvalidHeader);
    }

    let dcid_len = usize::from(payload[5]);
    let dcid_start = 6usize;
    let dcid_end = dcid_start
        .checked_add(dcid_len)
        .ok_or(LayerError::InvalidLength)?;
    let dcid = payload
        .get(dcid_start..dcid_end)
        .ok_or(LayerError::InvalidLength)?
        .to_vec();

    let scid_len = usize::from(*payload.get(dcid_end).ok_or(LayerError::InvalidLength)?);
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
    Ok(QuicLongHeader {
        version,
        packet_type,
        kind,
        is_initial: version != 0 && packet_type == 0,
        is_version_negotiation: version == 0,
        dcid,
        scid,
    })
}

#[cfg(test)]
mod tests {
    use super::{QuicPacketType, parse_quic_long_header, quic_version_name};

    #[test]
    fn classifies_v1_initial_and_version_name() {
        let header = parse_quic_long_header(&[0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]).unwrap();

        assert_eq!(header.kind, QuicPacketType::Initial);
        assert_eq!(quic_version_name(1), "v1");
    }

    #[test]
    fn classifies_v2_remapped_packet_type() {
        let header = parse_quic_long_header(&[0xd0, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x00]).unwrap();

        assert_eq!(header.packet_type, 0b01);
        assert_eq!(header.kind, QuicPacketType::Initial);
    }

    #[test]
    fn names_greased_version_and_leaves_packet_type_unknown() {
        let header = parse_quic_long_header(&[0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 0x00, 0x00]).unwrap();

        assert_eq!(quic_version_name(header.version), "greasing");
        assert_eq!(header.kind, QuicPacketType::Unknown);
    }
}
