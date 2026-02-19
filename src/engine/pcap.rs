use crate::layer::LayerError;

const PCAPNG_BLOCK_SECTION_HEADER: u32 = 0x0a0d0d0a;
const PCAPNG_BLOCK_INTERFACE_DESC: u32 = 0x0000_0001;
const PCAPNG_BLOCK_SIMPLE_PACKET: u32 = 0x0000_0003;
const PCAPNG_BLOCK_ENHANCED_PACKET: u32 = 0x0000_0006;
const PCAPNG_OPT_ENDOFOPT: u16 = 0;
const PCAPNG_OPT_IF_TSRESOL: u16 = 9;

#[derive(Debug, Clone)]
pub struct PcapFrame<'a> {
    pub timestamp_sec: u32,
    pub timestamp_subsec: u32,
    pub data: &'a [u8],
}

pub struct PcapFrameIter<'a> {
    input: &'a [u8],
    little_endian: bool,
    offset: usize,
    finished: bool,
}

pub struct PcapNgFrameIter<'a> {
    input: &'a [u8],
    offset: usize,
    section_little_endian: Option<bool>,
    interfaces: Vec<InterfaceInfo>,
    finished: bool,
}

pub enum CaptureFrameIter<'a> {
    Pcap(PcapFrameIter<'a>),
    PcapNg(PcapNgFrameIter<'a>),
}

#[derive(Debug, Clone, Copy)]
struct InterfaceInfo {
    ts_ticks_per_second: u64,
}

enum CaptureFormat {
    Pcap,
    PcapNg,
}

pub fn iter_capture_frames(input: &[u8]) -> Result<CaptureFrameIter<'_>, LayerError> {
    match detect_capture_format(input)? {
        CaptureFormat::Pcap => Ok(CaptureFrameIter::Pcap(iter_pcap_frames(input)?)),
        CaptureFormat::PcapNg => Ok(CaptureFrameIter::PcapNg(iter_pcapng_frames(input)?)),
    }
}

pub fn parse_capture_frames(input: &[u8]) -> Result<Vec<PcapFrame<'_>>, LayerError> {
    let mut frames = Vec::new();
    for frame in iter_capture_frames(input)? {
        frames.push(frame?);
    }
    Ok(frames)
}

pub fn iter_pcap_frames(input: &[u8]) -> Result<PcapFrameIter<'_>, LayerError> {
    let (little_endian, offset) = parse_global_header(input)?;
    Ok(PcapFrameIter {
        input,
        little_endian,
        offset,
        finished: false,
    })
}

pub fn iter_pcapng_frames(input: &[u8]) -> Result<PcapNgFrameIter<'_>, LayerError> {
    if input.len() < 4 {
        return Err(LayerError::InvalidLength);
    }
    if !is_pcapng_magic([input[0], input[1], input[2], input[3]]) {
        return Err(LayerError::MalformedPacket);
    }

    Ok(PcapNgFrameIter {
        input,
        offset: 0,
        section_little_endian: None,
        interfaces: Vec::new(),
        finished: false,
    })
}

pub fn parse_pcap_frames(input: &[u8]) -> Result<Vec<PcapFrame<'_>>, LayerError> {
    parse_capture_frames(input)
}

impl<'a> Iterator for CaptureFrameIter<'a> {
    type Item = Result<PcapFrame<'a>, LayerError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Pcap(iter) => iter.next(),
            Self::PcapNg(iter) => iter.next(),
        }
    }
}

impl<'a> Iterator for PcapFrameIter<'a> {
    type Item = Result<PcapFrame<'a>, LayerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        if self.offset == self.input.len() {
            self.finished = true;
            return None;
        }

        if self.offset + 16 > self.input.len() {
            self.finished = true;
            return Some(Err(LayerError::InvalidLength));
        }

        let ts_sec = match read_u32(self.input, self.offset, self.little_endian) {
            Ok(value) => value,
            Err(err) => {
                self.finished = true;
                return Some(Err(err));
            }
        };
        let ts_subsec = match read_u32(self.input, self.offset + 4, self.little_endian) {
            Ok(value) => value,
            Err(err) => {
                self.finished = true;
                return Some(Err(err));
            }
        };
        let incl_len = match read_u32(self.input, self.offset + 8, self.little_endian) {
            Ok(value) => value as usize,
            Err(err) => {
                self.finished = true;
                return Some(Err(err));
            }
        };
        self.offset += 16;

        if self.offset + incl_len > self.input.len() {
            self.finished = true;
            return Some(Err(LayerError::InvalidLength));
        }

        let frame = PcapFrame {
            timestamp_sec: ts_sec,
            timestamp_subsec: ts_subsec,
            data: &self.input[self.offset..self.offset + incl_len],
        };
        self.offset += incl_len;
        Some(Ok(frame))
    }
}

impl<'a> Iterator for PcapNgFrameIter<'a> {
    type Item = Result<PcapFrame<'a>, LayerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        loop {
            if self.offset == self.input.len() {
                self.finished = true;
                return None;
            }
            if self.offset + 12 > self.input.len() {
                self.finished = true;
                return Some(Err(LayerError::InvalidLength));
            }

            let type_bytes = [
                self.input[self.offset],
                self.input[self.offset + 1],
                self.input[self.offset + 2],
                self.input[self.offset + 3],
            ];

            if is_pcapng_magic(type_bytes) {
                if let Err(err) = parse_pcapng_section_header(self) {
                    self.finished = true;
                    return Some(Err(err));
                }
                continue;
            }

            let little_endian = match self.section_little_endian {
                Some(v) => v,
                None => {
                    self.finished = true;
                    return Some(Err(LayerError::MalformedPacket));
                }
            };

            let block_type = match read_u32(self.input, self.offset, little_endian) {
                Ok(v) => v,
                Err(err) => {
                    self.finished = true;
                    return Some(Err(err));
                }
            };
            let block_len = match read_u32(self.input, self.offset + 4, little_endian) {
                Ok(v) => v as usize,
                Err(err) => {
                    self.finished = true;
                    return Some(Err(err));
                }
            };

            if let Err(err) =
                validate_pcapng_block(self.input, self.offset, block_len, little_endian)
            {
                self.finished = true;
                return Some(Err(err));
            }

            match block_type {
                PCAPNG_BLOCK_INTERFACE_DESC => {
                    if let Err(err) = parse_pcapng_interface_desc(
                        self.input,
                        self.offset,
                        block_len,
                        little_endian,
                        &mut self.interfaces,
                    ) {
                        self.finished = true;
                        return Some(Err(err));
                    }
                    self.offset += block_len;
                }
                PCAPNG_BLOCK_ENHANCED_PACKET => {
                    let frame = parse_pcapng_enhanced_packet(
                        self.input,
                        self.offset,
                        block_len,
                        little_endian,
                        &self.interfaces,
                    );
                    self.offset += block_len;
                    return Some(frame);
                }
                PCAPNG_BLOCK_SIMPLE_PACKET => {
                    let frame = parse_pcapng_simple_packet(
                        self.input,
                        self.offset,
                        block_len,
                        little_endian,
                    );
                    self.offset += block_len;
                    return Some(frame);
                }
                _ => {
                    self.offset += block_len;
                }
            }
        }
    }
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

fn detect_capture_format(input: &[u8]) -> Result<CaptureFormat, LayerError> {
    if input.len() < 4 {
        return Err(LayerError::InvalidLength);
    }
    let magic = [input[0], input[1], input[2], input[3]];
    if is_pcap_magic(magic) {
        return Ok(CaptureFormat::Pcap);
    }
    if is_pcapng_magic(magic) {
        return Ok(CaptureFormat::PcapNg);
    }
    Err(LayerError::MalformedPacket)
}

fn is_pcap_magic(magic: [u8; 4]) -> bool {
    matches!(
        magic,
        [0xd4, 0xc3, 0xb2, 0xa1]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0xa1, 0xb2, 0x3c, 0x4d]
    )
}

fn is_pcapng_magic(magic: [u8; 4]) -> bool {
    magic == PCAPNG_BLOCK_SECTION_HEADER.to_be_bytes()
}

fn parse_pcapng_section_header(iter: &mut PcapNgFrameIter<'_>) -> Result<(), LayerError> {
    if iter.offset + 28 > iter.input.len() {
        return Err(LayerError::InvalidLength);
    }

    let bom = [
        iter.input[iter.offset + 8],
        iter.input[iter.offset + 9],
        iter.input[iter.offset + 10],
        iter.input[iter.offset + 11],
    ];
    let little_endian = match bom {
        [0x4d, 0x3c, 0x2b, 0x1a] => true,
        [0x1a, 0x2b, 0x3c, 0x4d] => false,
        _ => return Err(LayerError::MalformedPacket),
    };

    let block_len = read_u32(iter.input, iter.offset + 4, little_endian)? as usize;
    validate_pcapng_block(iter.input, iter.offset, block_len, little_endian)?;

    iter.section_little_endian = Some(little_endian);
    iter.interfaces.clear();
    iter.offset += block_len;
    Ok(())
}

fn parse_pcapng_interface_desc(
    input: &[u8],
    offset: usize,
    block_len: usize,
    little_endian: bool,
    interfaces: &mut Vec<InterfaceInfo>,
) -> Result<(), LayerError> {
    if block_len < 20 {
        return Err(LayerError::InvalidLength);
    }

    let options_start = offset + 16;
    let options_end = offset + block_len - 4;
    let mut ts_ticks_per_second = 1_000_000u64;
    let mut cursor = options_start;

    while cursor + 4 <= options_end {
        let code = read_u16(input, cursor, little_endian)?;
        let len = read_u16(input, cursor + 2, little_endian)? as usize;
        if code == PCAPNG_OPT_ENDOFOPT {
            break;
        }

        let value_start = cursor + 4;
        let value_end = value_start + len;
        if value_end > options_end {
            return Err(LayerError::InvalidLength);
        }

        if code == PCAPNG_OPT_IF_TSRESOL && len >= 1 {
            if let Some(value) = parse_tsresol(input[value_start]) {
                ts_ticks_per_second = value;
            }
        }

        cursor = value_end + padding_len(len);
        if cursor > options_end {
            return Err(LayerError::InvalidLength);
        }
    }

    interfaces.push(InterfaceInfo {
        ts_ticks_per_second,
    });
    Ok(())
}

fn parse_pcapng_enhanced_packet<'a>(
    input: &'a [u8],
    offset: usize,
    block_len: usize,
    little_endian: bool,
    interfaces: &[InterfaceInfo],
) -> Result<PcapFrame<'a>, LayerError> {
    if block_len < 32 {
        return Err(LayerError::InvalidLength);
    }

    let interface_id = read_u32(input, offset + 8, little_endian)? as usize;
    let ts_high = read_u32(input, offset + 12, little_endian)? as u64;
    let ts_low = read_u32(input, offset + 16, little_endian)? as u64;
    let cap_len = read_u32(input, offset + 20, little_endian)? as usize;

    let data_start = offset + 28;
    let data_with_pad = align4(cap_len);
    let data_region_end = offset + block_len - 4;

    if data_start + data_with_pad > data_region_end || data_start + cap_len > data_region_end {
        return Err(LayerError::InvalidLength);
    }

    let raw_ts = (ts_high << 32) | ts_low;
    let ticks = interfaces
        .get(interface_id)
        .map(|i| i.ts_ticks_per_second)
        .unwrap_or(1_000_000);
    let (timestamp_sec, timestamp_subsec) = split_timestamp(raw_ts, ticks);

    Ok(PcapFrame {
        timestamp_sec,
        timestamp_subsec,
        data: &input[data_start..data_start + cap_len],
    })
}

fn parse_pcapng_simple_packet<'a>(
    input: &'a [u8],
    offset: usize,
    block_len: usize,
    little_endian: bool,
) -> Result<PcapFrame<'a>, LayerError> {
    if block_len < 16 {
        return Err(LayerError::InvalidLength);
    }

    let orig_len = read_u32(input, offset + 8, little_endian)? as usize;
    let data_start = offset + 12;
    let data_region_end = offset + block_len - 4;
    let available = data_region_end.saturating_sub(data_start);
    let cap_len = orig_len.min(available);

    if data_start + cap_len > input.len() {
        return Err(LayerError::InvalidLength);
    }

    Ok(PcapFrame {
        timestamp_sec: 0,
        timestamp_subsec: 0,
        data: &input[data_start..data_start + cap_len],
    })
}

fn validate_pcapng_block(
    input: &[u8],
    offset: usize,
    block_len: usize,
    little_endian: bool,
) -> Result<(), LayerError> {
    if block_len < 12 || (block_len % 4) != 0 {
        return Err(LayerError::InvalidLength);
    }
    if offset + block_len > input.len() {
        return Err(LayerError::InvalidLength);
    }

    let trailer = read_u32(input, offset + block_len - 4, little_endian)? as usize;
    if trailer != block_len {
        return Err(LayerError::MalformedPacket);
    }

    Ok(())
}

fn split_timestamp(raw: u64, ticks_per_second: u64) -> (u32, u32) {
    if ticks_per_second == 0 {
        return (0, 0);
    }

    let sec = (raw / ticks_per_second).min(u32::MAX as u64) as u32;
    let sub = (raw % ticks_per_second).min(u32::MAX as u64) as u32;
    (sec, sub)
}

fn parse_tsresol(value: u8) -> Option<u64> {
    if (value & 0x80) == 0 {
        let exp = value as u32;
        let mut out = 1u64;
        for _ in 0..exp {
            out = out.checked_mul(10)?;
        }
        Some(out)
    } else {
        let exp = (value & 0x7f) as u32;
        if exp > 63 {
            return None;
        }
        Some(1u64 << exp)
    }
}

fn align4(value: usize) -> usize {
    value + padding_len(value)
}

fn padding_len(value: usize) -> usize {
    (4 - (value % 4)) % 4
}

fn read_u16(input: &[u8], offset: usize, little_endian: bool) -> Result<u16, LayerError> {
    if offset + 2 > input.len() {
        return Err(LayerError::InvalidLength);
    }

    let bytes = [input[offset], input[offset + 1]];
    Ok(if little_endian {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
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
    use super::{iter_capture_frames, iter_pcap_frames, parse_pcap_frames};

    #[test]
    fn iterates_single_frame_pcap() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/dns_udp_ipv4.pcap");
        let mut iter = iter_pcap_frames(bytes).expect("pcap iterator should initialize");
        let first = iter
            .next()
            .expect("one frame")
            .expect("first frame should parse");
        assert!(!first.data.is_empty());
        assert!(iter.next().is_none());
    }

    #[test]
    fn parses_single_frame_pcap() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/dns_udp_ipv4.pcap");
        let frames = parse_pcap_frames(bytes).expect("pcap should parse");
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].data.is_empty());
    }

    #[test]
    fn iterator_reports_truncated_frame_error() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 10]);

        let mut iter = iter_pcap_frames(&bytes).expect("pcap iterator should initialize");
        let first = iter.next().expect("should produce one result");
        assert!(first.is_err());
        assert!(iter.next().is_none());
    }

    #[test]
    fn parses_single_frame_pcapng() {
        let frame = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let bytes = build_minimal_pcapng_epb(&frame);

        let frames = parse_pcap_frames(&bytes).expect("pcapng should parse");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].data, frame);
    }

    #[test]
    fn iter_capture_frames_accepts_pcapng() {
        let frame = [0xaa, 0xbb, 0xcc, 0xdd];
        let bytes = build_minimal_pcapng_epb(&frame);

        let mut iter = iter_capture_frames(&bytes).expect("capture iterator should init");
        let first = iter.next().expect("one frame").expect("frame should parse");
        assert_eq!(first.data, frame);
        assert!(iter.next().is_none());
    }

    fn build_minimal_pcapng_epb(frame: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());
        out.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(-1i64).to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());

        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&20u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&20u32.to_le_bytes());

        let cap_len = frame.len();
        let cap_padded = (cap_len + 3) & !3;
        let epb_total_len = 32 + cap_padded;

        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&(epb_total_len as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1_500_000u32.to_le_bytes());
        out.extend_from_slice(&(cap_len as u32).to_le_bytes());
        out.extend_from_slice(&(cap_len as u32).to_le_bytes());
        out.extend_from_slice(frame);
        out.extend(std::iter::repeat_n(0u8, cap_padded - cap_len));
        out.extend_from_slice(&(epb_total_len as u32).to_le_bytes());

        out
    }
}
