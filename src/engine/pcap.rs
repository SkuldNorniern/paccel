use crate::layer::LayerError;

const PCAPNG_BLOCK_SECTION_HEADER: u32 = 0x0a0d0d0a;
const PCAPNG_BLOCK_INTERFACE_DESC: u32 = 0x0000_0001;
const PCAPNG_BLOCK_SIMPLE_PACKET: u32 = 0x0000_0003;
const PCAPNG_BLOCK_ENHANCED_PACKET: u32 = 0x0000_0006;
const PCAPNG_OPT_ENDOFOPT: u16 = 0;
const PCAPNG_OPT_IF_TSRESOL: u16 = 9;
const PCAPNG_OPT_IF_TSOFFSET: u16 = 14;

/// When a frame was captured, in the units the capture itself uses.
///
/// A pcapng timestamp is a 64-bit tick count at a resolution the interface
/// declares, plus a signed seconds offset (`if_tsoffset`). Splitting that into
/// seconds and a sub-second remainder loses range and cannot represent the
/// offset, so the raw form is kept and the conversions are offered instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureTimestamp {
    /// Ticks since the epoch, before `offset_seconds` is applied.
    pub ticks: u64,
    /// Ticks in one second, from `if_tsresol`. Never zero.
    pub ticks_per_second: u64,
    /// pcapng `if_tsoffset`, added to the seconds the ticks work out to.
    pub offset_seconds: i64,
}

impl CaptureTimestamp {
    /// Whole seconds since the epoch, offset applied.
    #[must_use]
    pub fn seconds(self) -> i64 {
        let whole = i64::try_from(self.ticks / self.ticks_per_second).unwrap_or(i64::MAX);
        whole.saturating_add(self.offset_seconds)
    }

    /// Ticks past the second `seconds` names.
    #[must_use]
    pub fn subsecond_ticks(self) -> u64 {
        self.ticks % self.ticks_per_second
    }

    /// Nanoseconds since the epoch, or `None` before it or past `u64`.
    #[must_use]
    pub fn to_timestamp_ns(self) -> Option<u64> {
        let seconds = u64::try_from(self.seconds()).ok()?;
        let subsecond =
            u128::from(self.subsecond_ticks()) * 1_000_000_000 / u128::from(self.ticks_per_second);
        seconds
            .checked_mul(1_000_000_000)?
            .checked_add(u64::try_from(subsecond).ok()?)
    }

    /// The resolution, named where it has a familiar name.
    #[must_use]
    pub fn resolution(self) -> TsResolution {
        resolution_from_ticks(self.ticks_per_second)
    }
}

#[derive(Debug, Clone)]
pub struct PcapFrame<'a> {
    /// `None` for a pcapng Simple Packet Block, which carries no timestamp.
    /// Reporting zero there would be a time, not an absence.
    pub timestamp: Option<CaptureTimestamp>,
    pub linktype: u16,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsResolution {
    Micro,
    Nano,
    /// Any resolution other than microseconds or nanoseconds. `timestamp_subsec`
    /// is a raw count at this many ticks per second.
    Other(u64),
}

pub struct PcapFrameIter<'a> {
    input: &'a [u8],
    little_endian: bool,
    ts_resolution: TsResolution,
    linktype: u16,
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
    ts_offset_seconds: i64,
    linktype: u16,
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
    let (little_endian, ts_resolution, linktype, offset) = parse_global_header(input)?;
    Ok(PcapFrameIter {
        input,
        little_endian,
        ts_resolution,
        linktype,
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

        // A classic pcap header is seconds plus a sub-second field whose unit
        // the file magic names, so it converts straight into ticks.
        let ticks_per_second = match self.ts_resolution {
            TsResolution::Micro => 1_000_000,
            TsResolution::Nano => 1_000_000_000,
            TsResolution::Other(ticks) => ticks.max(1),
        };
        let frame = PcapFrame {
            timestamp: Some(CaptureTimestamp {
                ticks: u64::from(ts_sec)
                    .saturating_mul(ticks_per_second)
                    .saturating_add(u64::from(ts_subsec)),
                ticks_per_second,
                offset_seconds: 0,
            }),
            linktype: self.linktype,
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
                        &self.interfaces,
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

fn parse_global_header(input: &[u8]) -> Result<(bool, TsResolution, u16, usize), LayerError> {
    if input.len() < 24 {
        return Err(LayerError::InvalidLength);
    }

    let magic = [input[0], input[1], input[2], input[3]];
    let (little_endian, ts_resolution) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, TsResolution::Micro),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, TsResolution::Nano),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, TsResolution::Micro),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, TsResolution::Nano),
        _ => return Err(LayerError::MalformedPacket),
    };
    let linktype = u16::try_from(read_u32(input, 20, little_endian)? & 0xffff)
        .map_err(|_| LayerError::MalformedPacket)?;
    Ok((little_endian, ts_resolution, linktype, 24))
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
    let linktype = read_u16(input, offset + 8, little_endian)?;
    let mut ts_ticks_per_second = 1_000_000u64;
    let mut ts_offset_seconds = 0i64;
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

        if code == PCAPNG_OPT_IF_TSRESOL
            && len >= 1
            && let Some(value) = parse_tsresol(input[value_start])
        {
            ts_ticks_per_second = value;
        }
        // pcapng sec 4.2: if_tsoffset is signed 64-bit seconds added to every
        // timestamp on the interface.
        if code == PCAPNG_OPT_IF_TSOFFSET
            && len >= 8
            && let Some(bytes) = input.get(value_start..value_start + 8)
        {
            let raw = <[u8; 8]>::try_from(bytes).unwrap_or([0; 8]);
            ts_offset_seconds = if little_endian {
                i64::from_le_bytes(raw)
            } else {
                i64::from_be_bytes(raw)
            };
        }

        cursor = value_end + padding_len(len);
        if cursor > options_end {
            return Err(LayerError::InvalidLength);
        }
    }

    interfaces.push(InterfaceInfo {
        ts_ticks_per_second,
        ts_offset_seconds,
        linktype,
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
    let ts_high = u64::from(read_u32(input, offset + 12, little_endian)?);
    let ts_low = u64::from(read_u32(input, offset + 16, little_endian)?);
    let cap_len = read_u32(input, offset + 20, little_endian)? as usize;

    let data_start = offset + 28;
    let data_with_pad = align4(cap_len);
    let data_region_end = offset + block_len - 4;

    if data_start + data_with_pad > data_region_end || data_start + cap_len > data_region_end {
        return Err(LayerError::InvalidLength);
    }

    // An EPB's Interface ID must refer to an already-seen IDB (pcapng spec
    // sec 4.3); an out-of-range ID is an invalid capture, not "assume Ethernet".
    let interface = interfaces
        .get(interface_id)
        .ok_or(LayerError::InvalidHeader)?;
    let raw_ts = (ts_high << 32) | ts_low;

    Ok(PcapFrame {
        timestamp: Some(CaptureTimestamp {
            ticks: raw_ts,
            ticks_per_second: interface.ts_ticks_per_second.max(1),
            offset_seconds: interface.ts_offset_seconds,
        }),
        linktype: interface.linktype,
        data: &input[data_start..data_start + cap_len],
    })
}

fn parse_pcapng_simple_packet<'a>(
    input: &'a [u8],
    offset: usize,
    block_len: usize,
    little_endian: bool,
    interfaces: &[InterfaceInfo],
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

    // An SPB implicitly refers to interface 0 (pcapng spec sec 4.4); no IDB
    // means there's no interface 0 to refer to.
    let interface = interfaces.first().ok_or(LayerError::InvalidHeader)?;

    Ok(PcapFrame {
        // A Simple Packet Block carries no timestamp at all.
        timestamp: None,
        linktype: interface.linktype,
        data: &input[data_start..data_start + cap_len],
    })
}

fn resolution_from_ticks(ticks_per_second: u64) -> TsResolution {
    match ticks_per_second {
        1_000_000 => TsResolution::Micro,
        1_000_000_000 => TsResolution::Nano,
        other => TsResolution::Other(other),
    }
}

fn validate_pcapng_block(
    input: &[u8],
    offset: usize,
    block_len: usize,
    little_endian: bool,
) -> Result<(), LayerError> {
    if block_len < 12 || (block_len & 3) != 0 {
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

fn parse_tsresol(value: u8) -> Option<u64> {
    if (value & 0x80) == 0 {
        let exp = u32::from(value);
        let mut out = 1u64;
        for _ in 0..exp {
            out = out.checked_mul(10)?;
        }
        Some(out)
    } else {
        let exp = u32::from(value & 0x7f);
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
#[allow(clippy::absolute_paths, clippy::cast_possible_truncation)]
mod tests {
    use super::{
        TsResolution, iter_capture_frames, iter_pcap_frames, iter_pcapng_frames,
        parse_capture_frames, parse_pcap_frames,
    };

    /// A pcapng with `if_tsresol` and `if_tsoffset`, and one EPB at `ticks`.
    fn pcapng_with_offset(tsresol_byte: u8, offset_seconds: i64, ticks: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0a0d_0d0au32.to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());
        out.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(-1i64).to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());

        // IDB carrying both options.
        let idb_total_len: u32 = 16 + 8 + 4 + 12 + 4;
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&idb_total_len.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&65_535u32.to_le_bytes());
        out.extend_from_slice(&9u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(tsresol_byte);
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&14u16.to_le_bytes()); // if_tsoffset
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&offset_seconds.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&idb_total_len.to_le_bytes());

        let frame = [0u8; 4];
        let epb_total_len: u32 = 32 + 4;
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(&epb_total_len.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&u32::try_from(ticks >> 32).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(ticks & 0xffff_ffff)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&frame);
        out.extend_from_slice(&epb_total_len.to_le_bytes());
        out
    }

    /// pcapng sec 4.2: `if_tsoffset` shifts every timestamp on the interface.
    /// The old split into seconds and sub-seconds had nowhere to put it.
    #[test]
    fn an_interface_timestamp_offset_is_applied() {
        // Microsecond resolution, one hour of offset, two seconds of ticks.
        let capture = pcapng_with_offset(6, 3_600, 2_000_000);
        let frames = parse_capture_frames(&capture).expect("parses");
        let timestamp = frames[0].timestamp.expect("an EPB has a timestamp");

        assert_eq!(timestamp.seconds(), 3_602);
        assert_eq!(timestamp.subsecond_ticks(), 0);
        assert_eq!(timestamp.to_timestamp_ns(), Some(3_602_000_000_000));
    }

    /// A tick count past what 32 bits of seconds can hold used to saturate.
    #[test]
    fn a_timestamp_beyond_u32_seconds_is_kept_whole() {
        let seconds = u64::from(u32::MAX) + 10;
        let capture = pcapng_with_offset(6, 0, seconds * 1_000_000);
        let frames = parse_capture_frames(&capture).expect("parses");
        let timestamp = frames[0].timestamp.expect("a timestamp");

        assert_eq!(
            timestamp.seconds(),
            i64::try_from(seconds).expect("fits an i64"),
            "the seconds are no longer clamped to u32::MAX"
        );
    }

    #[test]
    fn iterates_single_frame_pcap() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/dns_udp_ipv4.pcap");
        let mut iter = iter_pcap_frames(bytes).expect("pcap iterator should initialize");
        let first = iter
            .next()
            .expect("one frame")
            .expect("first frame should parse");
        assert!(!first.data.is_empty());
        assert_eq!(first.linktype, 1);
        assert!(iter.next().is_none());
    }

    #[test]
    fn parses_single_frame_pcap() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/dns_udp_ipv4.pcap");
        let frames = parse_pcap_frames(bytes).expect("pcap should parse");
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].data.is_empty());
        assert_eq!(frames[0].linktype, 1);
    }

    #[test]
    fn parses_nanosecond_magic_pcap() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x4d, 0x3c, 0xb2, 0xa1]);
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&123u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        let frames = parse_pcap_frames(&bytes).expect("pcap should parse");
        assert_eq!(
            frames[0].timestamp.expect("a timestamp").resolution(),
            TsResolution::Nano
        );
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
        assert_eq!(frames[0].linktype, 1);
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

    #[test]
    fn epb_with_unknown_interface_id_errors_instead_of_assuming_ethernet() {
        let mut bytes = build_minimal_pcapng_epb(&[0xaa, 0xbb, 0xcc, 0xdd]);
        // EPB's Interface ID field, right after block type/length. SHB (28
        // bytes) + IDB (20 bytes) precede the EPB. Only interface 0 exists.
        let interface_id_offset = 28 + 20 + 8;
        bytes[interface_id_offset..interface_id_offset + 4].copy_from_slice(&99u32.to_le_bytes());

        let mut iter = iter_pcapng_frames(&bytes).expect("pcapng iterator should init");
        assert!(iter.next().expect("one block").is_err());
    }

    // ── Additional pcap file tests ─────────────────────────────────────

    #[test]
    fn dns_pcapng_file_has_one_frame() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/dns_udp_ipv4.pcapng");
        let mut iter = iter_pcapng_frames(bytes).expect("pcapng iterator should init");
        let first = iter.next().expect("one frame").expect("frame should parse");
        assert!(!first.data.is_empty());
        assert!(iter.next().is_none());
    }

    #[test]
    fn multi_frame_pcap_yields_three_frames() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/multi_frame.pcap");
        let frames = parse_pcap_frames(bytes).expect("multi-frame pcap should parse");
        assert_eq!(frames.len(), 3);
        for frame in &frames {
            assert!(!frame.data.is_empty());
        }
    }

    #[test]
    fn pcap_timestamps_are_present() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/dns_udp_ipv4.pcap");
        let frames = parse_pcap_frames(bytes).expect("pcap should parse");
        assert_eq!(frames.len(), 1);
        // Scapy writes a non-zero timestamp for the first frame
        assert!(frames[0].timestamp.expect("a timestamp").ticks > 0);
    }

    #[test]
    fn iter_capture_frames_accepts_pcap_file() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/tcp_syn_ipv4.pcap");
        let count = iter_capture_frames(bytes)
            .expect("iter init")
            .filter_map(|r| r.ok())
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn arp_pcap_frame_is_non_empty() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/arp_request.pcap");
        let frames = parse_pcap_frames(bytes).expect("arp pcap should parse");
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].data.is_empty());
    }

    #[test]
    fn icmp_pcap_frame_is_non_empty() {
        let bytes = include_bytes!("../../tests/pcaps/happy-path/icmp_echo_ipv4.pcap");
        let frames = parse_pcap_frames(bytes).expect("icmp pcap should parse");
        assert_eq!(frames.len(), 1);
        assert!(!frames[0].data.is_empty());
    }

    #[test]
    fn malformed_magic_returns_error() {
        let bad: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0];
        assert!(parse_pcap_frames(bad).is_err());
    }

    #[test]
    fn empty_input_returns_error() {
        assert!(parse_pcap_frames(&[]).is_err());
        assert!(iter_pcapng_frames(&[]).is_err());
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

    /// Builds a minimal pcapng with a custom `if_tsresol`.
    fn build_pcapng_epb_with_tsresol(tsresol_byte: u8, frame: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();

        out.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());
        out.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(-1i64).to_le_bytes());
        out.extend_from_slice(&28u32.to_le_bytes());

        // IDB: type/len, linktype/reserved, snaplen, if_tsresol option, endofopt, trailing len.
        let idb_total_len: u32 = 16 + 8 + 4 + 4;
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&idb_total_len.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&9u16.to_le_bytes()); // PCAPNG_OPT_IF_TSRESOL
        out.extend_from_slice(&1u16.to_le_bytes());
        out.push(tsresol_byte);
        out.extend_from_slice(&[0u8; 3]); // pad to 4 bytes
        out.extend_from_slice(&0u16.to_le_bytes()); // endofopt code
        out.extend_from_slice(&0u16.to_le_bytes()); // endofopt len
        out.extend_from_slice(&idb_total_len.to_le_bytes());

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

    #[test]
    fn millisecond_interface_resolution_is_not_mislabeled_as_micro() {
        let frame = [0xaa, 0xbb];
        // 0x03 (MSB clear) = decimal exponent 3 -> 10^3 = 1000 ticks/second (milliseconds).
        let bytes = build_pcapng_epb_with_tsresol(0x03, &frame);

        let frames = parse_pcap_frames(&bytes).expect("pcapng should parse");
        assert_eq!(
            frames[0].timestamp.expect("a timestamp").resolution(),
            TsResolution::Other(1_000)
        );
        assert_ne!(
            frames[0].timestamp.expect("a timestamp").resolution(),
            TsResolution::Micro
        );
    }

    #[test]
    fn microsecond_interface_resolution_still_reports_micro() {
        let frame = [0xaa, 0xbb];
        // 0x06 -> 10^6 = 1_000_000 ticks/second, the common case.
        let bytes = build_pcapng_epb_with_tsresol(0x06, &frame);

        let frames = parse_pcap_frames(&bytes).expect("pcapng should parse");
        assert_eq!(
            frames[0].timestamp.expect("a timestamp").resolution(),
            TsResolution::Micro
        );
    }
}
