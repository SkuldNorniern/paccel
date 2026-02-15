use crate::layer::LayerError;

#[derive(Debug, Clone)]
pub struct PcapFrame<'a> {
    pub timestamp_sec: u32,
    pub timestamp_subsec: u32,
    pub data: &'a [u8],
}

pub fn parse_pcap_frames(input: &[u8]) -> Result<Vec<PcapFrame<'_>>, LayerError> {
    let (little_endian, mut offset) = parse_global_header(input)?;
    let mut frames = Vec::new();

    while offset + 16 <= input.len() {
        let ts_sec = read_u32(input, offset, little_endian)?;
        let ts_subsec = read_u32(input, offset + 4, little_endian)?;
        let incl_len = read_u32(input, offset + 8, little_endian)? as usize;
        offset += 16;

        if offset + incl_len > input.len() {
            return Err(LayerError::InvalidLength);
        }

        frames.push(PcapFrame {
            timestamp_sec: ts_sec,
            timestamp_subsec: ts_subsec,
            data: &input[offset..offset + incl_len],
        });
        offset += incl_len;
    }

    Ok(frames)
}

fn parse_global_header(input: &[u8]) -> Result<(bool, usize), LayerError> {
    if input.len() < 24 {
        return Err(LayerError::InvalidLength);
    }

    let magic = [input[0], input[1], input[2], input[3]];
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => Ok((true, 24)),
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => Ok((false, 24)),
        _ => Err(LayerError::MalformedPacket),
    }
}

fn read_u32(input: &[u8], offset: usize, little_endian: bool) -> Result<u32, LayerError> {
    if offset + 4 > input.len() {
        return Err(LayerError::InvalidLength);
    }

    let bytes = [
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ];

    Ok(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

#[cfg(test)]
mod tests {
    use super::parse_pcap_frames;

    #[test]
    fn parses_single_frame_pcap() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/dns_udp_ipv4.pcap");
        let frames = parse_pcap_frames(bytes).expect("pcap should parse");
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].data.is_empty());
    }
}
