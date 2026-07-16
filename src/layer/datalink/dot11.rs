use crate::layer::LayerError;

const RADIOTAP_MIN_LEN: usize = 8;
const DOT11_MIN_LEN: usize = 10;
const DOT11_THREE_ADDRESS_LEN: usize = 24;
const DOT11_FOUR_ADDRESS_LEN: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadiotapHeader {
    pub version: u8,
    pub length: u16,
    pub present: u32,
}

pub fn parse_radiotap(data: &[u8]) -> Result<(RadiotapHeader, usize), LayerError> {
    if data.len() < RADIOTAP_MIN_LEN {
        return Err(LayerError::InvalidLength);
    }

    let version = data[0];
    if version != 0 {
        return Err(LayerError::InvalidHeader);
    }

    let length = u16::from_le_bytes([data[2], data[3]]);
    let offset = usize::from(length);
    if offset < RADIOTAP_MIN_LEN || offset > data.len() {
        return Err(LayerError::InvalidLength);
    }

    Ok((
        RadiotapHeader {
            version,
            length,
            present: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        },
        offset,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dot11Frame {
    pub frame_control: u16,
    pub frame_type: u8,
    pub frame_subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub duration: u16,
    pub addr1: [u8; 6],
    pub addr2: Option<[u8; 6]>,
    pub addr3: Option<[u8; 6]>,
    pub seq_control: Option<u16>,
    pub header_len: usize,
}

pub fn parse_dot11(data: &[u8]) -> Result<Dot11Frame, LayerError> {
    if data.len() < DOT11_MIN_LEN {
        return Err(LayerError::InvalidLength);
    }

    let frame_control = u16::from_le_bytes([data[0], data[1]]);
    let frame_type = ((frame_control >> 2) & 0x3) as u8;
    let to_ds = frame_control & 0x0100 != 0;
    let from_ds = frame_control & 0x0200 != 0;
    let mut frame = Dot11Frame {
        frame_control,
        frame_type,
        frame_subtype: ((frame_control >> 4) & 0xf) as u8,
        to_ds,
        from_ds,
        duration: u16::from_le_bytes([data[2], data[3]]),
        addr1: data[4..10].try_into().expect("fixed-length slice"),
        addr2: None,
        addr3: None,
        seq_control: None,
        header_len: DOT11_MIN_LEN,
    };

    if !matches!(frame_type, 0 | 2) {
        return Ok(frame);
    }

    frame.addr2 = data.get(10..16).and_then(|bytes| bytes.try_into().ok());
    frame.addr3 = data.get(16..22).and_then(|bytes| bytes.try_into().ok());
    frame.seq_control = data
        .get(22..24)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));

    let expected_len = if to_ds && from_ds {
        DOT11_FOUR_ADDRESS_LEN
    } else {
        DOT11_THREE_ADDRESS_LEN
    };
    frame.header_len = expected_len.min(data.len());

    Ok(frame)
}
