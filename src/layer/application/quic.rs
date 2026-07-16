use crate::layer::LayerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicLongHeader {
    pub version: u32,
    pub packet_type: u8,
    pub is_initial: bool,
    pub is_version_negotiation: bool,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
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
    Ok(QuicLongHeader {
        version,
        packet_type,
        is_initial: version != 0 && packet_type == 0,
        is_version_negotiation: version == 0,
        dcid,
        scid,
    })
}
