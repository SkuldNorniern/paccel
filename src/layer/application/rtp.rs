use crate::layer::LayerError;

const FIXED_HEADER_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload_len: usize,
}

pub fn parse_rtp(payload: &[u8]) -> Result<RtpHeader, LayerError> {
    if payload.len() < FIXED_HEADER_LEN {
        return Err(LayerError::InvalidLength);
    }

    let version = payload[0] >> 6;
    if version != 2 {
        return Err(LayerError::InvalidHeader);
    }

    let extension = payload[0] & 0x10 != 0;
    let csrc_count = payload[0] & 0x0f;
    let csrc_len = usize::from(csrc_count) * 4;
    let mut header_len = FIXED_HEADER_LEN
        .checked_add(csrc_len)
        .ok_or(LayerError::InvalidLength)?;
    if payload.len() < header_len {
        return Err(LayerError::InvalidLength);
    }

    if extension {
        header_len = skip_extension(payload, header_len)?;
    }

    Ok(RtpHeader {
        version,
        padding: payload[0] & 0x20 != 0,
        extension,
        csrc_count,
        marker: payload[1] & 0x80 != 0,
        payload_type: payload[1] & 0x7f,
        sequence_number: u16::from_be_bytes([payload[2], payload[3]]),
        timestamp: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        ssrc: u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]),
        payload_len: payload.len() - header_len,
    })
}

fn skip_extension(payload: &[u8], extension_offset: usize) -> Result<usize, LayerError> {
    let extension_header_end = extension_offset
        .checked_add(4)
        .ok_or(LayerError::InvalidLength)?;
    let extension_header = payload
        .get(extension_offset..extension_header_end)
        .ok_or(LayerError::InvalidLength)?;
    let extension_words = u16::from_be_bytes([extension_header[2], extension_header[3]]);
    let extension_len = usize::from(extension_words)
        .checked_mul(4)
        .ok_or(LayerError::InvalidLength)?;
    let header_len = extension_header_end
        .checked_add(extension_len)
        .ok_or(LayerError::InvalidLength)?;
    if payload.len() < header_len {
        return Err(LayerError::InvalidLength);
    }
    Ok(header_len)
}

#[cfg(test)]
mod tests {
    use super::parse_rtp;

    #[test]
    fn parses_fixture_frame_six_header() {
        let payload = [
            0x80, 0x80, 0x92, 0xdb, 0x00, 0x00, 0x00, 0xa0, 0x34, 0x3d, 0xa9, 0x9b, 0xaa, 0xbb,
        ];
        let header = parse_rtp(&payload).expect("valid RTP packet");

        assert_eq!(
            (
                header.version,
                header.padding,
                header.extension,
                header.csrc_count,
                header.marker,
                header.payload_type,
            ),
            (2, false, false, 0, true, 0)
        );
        assert_eq!(
            (
                header.sequence_number,
                header.timestamp,
                header.ssrc,
                header.payload_len,
            ),
            (37_595, 160, 0x343d_a99b, 2)
        );
    }

    #[test]
    fn rejects_non_version_two() {
        assert!(parse_rtp(&[0x40; 12]).is_err());
    }

    #[test]
    fn rejects_short_packet() {
        assert!(parse_rtp(&[0x80; 11]).is_err());
    }

    #[test]
    fn skips_two_csrc_identifiers() {
        let mut payload = vec![0u8; 12 + 8 + 3];
        payload[0] = 0x82;
        payload[12..20].copy_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]);
        let header = parse_rtp(&payload).expect("valid RTP packet with CSRCs");

        assert_eq!(header.csrc_count, 2);
        assert_eq!(header.payload_len, 3);
    }
}
