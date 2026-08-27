//! Opt-in, stateful IP fragment and TCP stream reassembly.
//!
//! The built-in packet parser remains stateless. All payload state maintained here is bounded by
//! caller-configurable limits; excess IP datagrams are evicted and excess TCP data is refused.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::layer::application::quic::QuicFrame;
use crate::layer::network::ipv4::Ipv4Header;

const DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM: usize = 1_024;
const DEFAULT_MAX_DATAGRAM_BYTES: usize = 65_535;
const DEFAULT_MAX_CONCURRENT_DATAGRAMS: usize = 1_024;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 1_048_576;
const DEFAULT_MAX_GAP: usize = 65_535;
const DEFAULT_MAX_FLOWS: usize = 65_536;
const DEFAULT_MAX_STREAMS: usize = 65_536;
const TCP_SEQUENCE_HALF_RANGE: u32 = 1 << 31;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum IpDatagramKey {
    V4 {
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        identification: u16,
    },
    V6 {
        source: Ipv6Addr,
        destination: Ipv6Addr,
        identification: u32,
    },
}

#[derive(Debug, Default)]
struct IpDatagramState {
    bytes: Vec<u8>,
    received: Vec<bool>,
    fragment_count: usize,
    total_length: Option<usize>,
}

enum FragmentResult {
    Incomplete,
    Complete(Vec<u8>),
    Drop,
}

/// Reassembles IPv4 and IPv6 fragment payloads with explicit resource limits.
#[derive(Debug)]
pub struct IpFragmentReassembler {
    max_fragments_per_datagram: usize,
    max_datagram_bytes: usize,
    max_concurrent_datagrams: usize,
    datagrams: HashMap<IpDatagramKey, IpDatagramState>,
    insertion_order: VecDeque<IpDatagramKey>,
}

impl IpFragmentReassembler {
    /// Creates a reassembler with limits of 1024 fragments, 65,535 bytes, and 1024 datagrams.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM,
            DEFAULT_MAX_DATAGRAM_BYTES,
            DEFAULT_MAX_CONCURRENT_DATAGRAMS,
        )
    }

    /// Creates a reassembler with caller-supplied per-datagram and concurrency limits.
    #[must_use]
    pub fn with_limits(
        max_fragments_per_datagram: usize,
        max_datagram_bytes: usize,
        max_concurrent_datagrams: usize,
    ) -> Self {
        Self {
            max_fragments_per_datagram,
            max_datagram_bytes,
            max_concurrent_datagrams,
            datagrams: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    /// Offers an IPv4 fragment payload and returns the complete transport payload when available.
    pub fn offer_ipv4(&mut self, header: &Ipv4Header, l4_payload: &[u8]) -> Option<Vec<u8>> {
        let more_fragments = header.flags & 1 != 0;
        if header.fragment_offset == 0 && !more_fragments {
            return None;
        }

        let key = IpDatagramKey::V4 {
            source: header.source,
            destination: header.destination,
            protocol: header.protocol,
            identification: header.identification,
        };
        let offset = usize::from(header.fragment_offset) * 8;
        self.offer_fragment(key, offset, more_fragments, l4_payload)
    }

    /// Offers an IPv6 fragment payload and returns the complete upper-layer payload when available.
    #[allow(clippy::too_many_arguments)]
    pub fn offer_ipv6(
        &mut self,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        id: u32,
        frag_offset: u16,
        more_fragments: bool,
        next_header: u8,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        // The IPv6 fragment identity is source, destination, and identification. The next-header
        // value belongs to the reconstructed packet but is not part of that identity.
        let _ = next_header;
        let key = IpDatagramKey::V6 {
            source: src,
            destination: dst,
            identification: id,
        };
        let offset = usize::from(frag_offset) * 8;
        self.offer_fragment(key, offset, more_fragments, payload)
    }

    fn offer_fragment(
        &mut self,
        key: IpDatagramKey,
        offset: usize,
        more_fragments: bool,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let Some(end) = offset.checked_add(payload.len()) else {
            self.remove_datagram(&key);
            return None;
        };
        if end > self.max_datagram_bytes || self.max_fragments_per_datagram == 0 {
            self.remove_datagram(&key);
            return None;
        }

        if !self.datagrams.contains_key(&key) {
            if self.max_concurrent_datagrams == 0 {
                return None;
            }
            self.evict_until_room();
            self.datagrams
                .insert(key.clone(), IpDatagramState::default());
            self.insertion_order.push_back(key.clone());
        }

        let result = match self.datagrams.get_mut(&key) {
            Some(state) => Self::insert_fragment(
                state,
                offset,
                end,
                more_fragments,
                payload,
                self.max_fragments_per_datagram,
            ),
            None => FragmentResult::Drop,
        };

        match result {
            FragmentResult::Incomplete => None,
            FragmentResult::Complete(payload) => {
                self.remove_datagram(&key);
                Some(payload)
            }
            FragmentResult::Drop => {
                self.remove_datagram(&key);
                None
            }
        }
    }

    fn insert_fragment(
        state: &mut IpDatagramState,
        offset: usize,
        end: usize,
        more_fragments: bool,
        payload: &[u8],
        max_fragments: usize,
    ) -> FragmentResult {
        if state.fragment_count >= max_fragments {
            return FragmentResult::Drop;
        }
        if state.total_length.is_some_and(|total| end > total) {
            return FragmentResult::Drop;
        }
        if !more_fragments {
            if state
                .received
                .get(end..)
                .is_some_and(|tail| tail.contains(&true))
            {
                return FragmentResult::Drop;
            }
            state.total_length = Some(end);
        }

        state.fragment_count += 1;
        if state.bytes.len() < end {
            state.bytes.resize(end, 0);
            state.received.resize(end, false);
        }
        if state
            .received
            .get(offset..end)
            .is_some_and(|coverage| coverage.contains(&true))
        {
            return FragmentResult::Drop;
        }
        if let (Some(destination), Some(coverage)) = (
            state.bytes.get_mut(offset..end),
            state.received.get_mut(offset..end),
        ) {
            destination.copy_from_slice(payload);
            coverage.fill(true);
        } else {
            return FragmentResult::Drop;
        }

        let Some(total) = state.total_length else {
            return FragmentResult::Incomplete;
        };
        let Some(coverage) = state.received.get(..total) else {
            return FragmentResult::Drop;
        };
        if !coverage.iter().all(|received| *received) {
            return FragmentResult::Incomplete;
        }
        match state.bytes.get(..total) {
            Some(bytes) => FragmentResult::Complete(bytes.to_vec()),
            None => FragmentResult::Drop,
        }
    }

    fn evict_until_room(&mut self) {
        while self.datagrams.len() >= self.max_concurrent_datagrams {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.datagrams.clear();
                break;
            };
            self.datagrams.remove(&oldest);
        }
    }

    fn remove_datagram(&mut self, key: &IpDatagramKey) {
        self.datagrams.remove(key);
        self.insertion_order.retain(|queued| queued != key);
    }
}

impl Default for IpFragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    address: IpAddr,
    port: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TcpFlowKey {
    first: Endpoint,
    second: Endpoint,
}

#[derive(Debug, Default)]
struct TcpDirectionState {
    expected: Option<u32>,
    segments: BTreeMap<u32, Vec<u8>>,
    buffered_bytes: usize,
    closing: bool,
    fin_sequence: Option<u32>,
}

#[derive(Debug, Default)]
struct TcpFlowState {
    directions: [TcpDirectionState; 2],
}

/// Reassembles each direction of a TCP flow independently with capped out-of-order storage.
#[derive(Debug)]
pub struct TcpStreamReassembler {
    max_buffered_bytes: usize,
    max_gap: usize,
    max_flows: usize,
    flows: HashMap<TcpFlowKey, TcpFlowState>,
    insertion_order: VecDeque<TcpFlowKey>,
}

impl TcpStreamReassembler {
    /// Creates a reassembler with a 1 MiB per-direction buffer and a 65,535-byte maximum gap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_BUFFERED_BYTES, DEFAULT_MAX_GAP)
    }

    /// Creates a TCP reassembler with caller-supplied per-direction limits.
    #[must_use]
    pub fn with_limits(max_buffered_bytes: usize, max_gap: usize) -> Self {
        Self {
            max_buffered_bytes,
            max_gap,
            max_flows: DEFAULT_MAX_FLOWS,
            flows: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    /// Overrides the maximum number of concurrently tracked TCP flows.
    #[must_use]
    pub fn with_max_flows(mut self, max_flows: usize) -> Self {
        self.max_flows = max_flows;
        self
    }

    /// Offers one TCP segment and returns all newly contiguous payload bytes for its direction.
    #[allow(clippy::too_many_arguments)]
    pub fn offer(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        seq: u32,
        syn: bool,
        fin: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let Ok(payload_sequence_length) = u32::try_from(payload.len()) else {
            return Vec::new();
        };
        let (key, direction) = normalized_flow(src, src_port, dst, dst_port);
        if !self.flows.contains_key(&key) {
            if self.max_flows == 0 {
                return Vec::new();
            }
            self.evict_until_room();
            self.flows.insert(key.clone(), TcpFlowState::default());
            self.insertion_order.push_back(key.clone());
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            return Vec::new();
        };
        let state = &mut flow.directions[direction];

        if state.expected.is_none() {
            state.expected = Some(if syn { seq.wrapping_add(1) } else { seq });
        }
        let data_sequence = if syn { seq.wrapping_add(1) } else { seq };
        if fin {
            state.closing = true;
            state.fin_sequence = Some(data_sequence.wrapping_add(payload_sequence_length));
        }

        let mut output = Vec::new();
        Self::accept_payload(
            state,
            data_sequence,
            payload,
            self.max_buffered_bytes,
            self.max_gap,
            &mut output,
        );
        Self::consume_contiguous(state, &mut output);
        Self::consume_fin(state);
        output
    }

    /// Removes both directions of a normalized flow, returning whether it existed.
    pub fn remove_flow(&mut self, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> bool {
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        let removed = self.flows.remove(&key).is_some();
        self.insertion_order.retain(|queued| queued != &key);
        removed
    }

    /// Removes all flow state.
    pub fn clear(&mut self) {
        self.flows.clear();
        self.insertion_order.clear();
    }

    fn evict_until_room(&mut self) {
        while self.flows.len() >= self.max_flows {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.flows.clear();
                break;
            };
            self.flows.remove(&oldest);
        }
    }

    fn accept_payload(
        state: &mut TcpDirectionState,
        sequence: u32,
        payload: &[u8],
        max_buffered_bytes: usize,
        max_gap: usize,
        output: &mut Vec<u8>,
    ) {
        if payload.is_empty() {
            return;
        }
        let Some(expected) = state.expected else {
            return;
        };
        let delta = sequence.wrapping_sub(expected);
        if delta == 0 {
            output.extend_from_slice(payload);
            advance_expected(state, payload.len());
            return;
        }
        if delta < TCP_SEQUENCE_HALF_RANGE {
            if u32_to_usize(delta) > max_gap {
                return;
            }
            Self::buffer_segment(state, sequence, payload, max_buffered_bytes);
            return;
        }

        let already_consumed = u32_to_usize(expected.wrapping_sub(sequence));
        if already_consumed < payload.len() {
            output.extend_from_slice(&payload[already_consumed..]);
            advance_expected(state, payload.len() - already_consumed);
        }
    }

    fn buffer_segment(
        state: &mut TcpDirectionState,
        sequence: u32,
        payload: &[u8],
        max_buffered_bytes: usize,
    ) {
        let replaced = state.segments.get(&sequence).map_or(0, Vec::len);
        let Some(without_replaced) = state.buffered_bytes.checked_sub(replaced) else {
            state.segments.clear();
            state.buffered_bytes = 0;
            return;
        };
        let Some(projected) = without_replaced.checked_add(payload.len()) else {
            state.segments.clear();
            state.buffered_bytes = 0;
            return;
        };
        if projected > max_buffered_bytes {
            state.segments.clear();
            state.buffered_bytes = 0;
            return;
        }
        state.segments.insert(sequence, payload.to_vec());
        state.buffered_bytes = projected;
    }

    fn consume_contiguous(state: &mut TcpDirectionState, output: &mut Vec<u8>) {
        loop {
            let Some(expected) = state.expected else {
                return;
            };
            let candidate = state.segments.iter().find_map(|(sequence, bytes)| {
                let consumed = expected.wrapping_sub(*sequence);
                if consumed < TCP_SEQUENCE_HALF_RANGE && u32_to_usize(consumed) < bytes.len() {
                    Some((*sequence, u32_to_usize(consumed)))
                } else {
                    None
                }
            });
            let Some((sequence, consumed)) = candidate else {
                Self::discard_stale_segments(state, expected);
                return;
            };
            let Some(bytes) = state.segments.remove(&sequence) else {
                return;
            };
            state.buffered_bytes = state.buffered_bytes.saturating_sub(bytes.len());
            let Some(contiguous) = bytes.get(consumed..) else {
                continue;
            };
            output.extend_from_slice(contiguous);
            advance_expected(state, contiguous.len());
        }
    }

    fn discard_stale_segments(state: &mut TcpDirectionState, expected: u32) {
        let stale: Vec<u32> = state
            .segments
            .iter()
            .filter_map(|(sequence, bytes)| {
                let consumed = expected.wrapping_sub(*sequence);
                (consumed < TCP_SEQUENCE_HALF_RANGE && u32_to_usize(consumed) >= bytes.len())
                    .then_some(*sequence)
            })
            .collect();
        for sequence in stale {
            if let Some(bytes) = state.segments.remove(&sequence) {
                state.buffered_bytes = state.buffered_bytes.saturating_sub(bytes.len());
            }
        }
    }

    fn consume_fin(state: &mut TcpDirectionState) {
        if let (Some(expected), Some(fin_sequence)) = (state.expected, state.fin_sequence)
            && expected == fin_sequence
        {
            state.expected = Some(expected.wrapping_add(1));
            state.fin_sequence = None;
        }
    }
}

impl Default for TcpStreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct QuicStreamKey {
    first: Endpoint,
    second: Endpoint,
    stream_id: u64,
}

#[derive(Debug, Default)]
struct QuicStreamState {
    ranges: BTreeMap<u64, Vec<u8>>,
    expected: u64,
    buffered_bytes: usize,
    fin_offset: Option<u64>,
    closed: bool,
}

/// Reassembles QUIC STREAM-frame data with capped out-of-order storage.
#[derive(Debug)]
pub struct QuicStreamReassembler {
    max_buffered_bytes_per_stream: usize,
    max_gap: usize,
    max_streams: usize,
    streams: HashMap<QuicStreamKey, QuicStreamState>,
    insertion_order: VecDeque<QuicStreamKey>,
}

impl QuicStreamReassembler {
    /// Creates a reassembler with a 1 MiB per-stream buffer and a 65,535-byte maximum gap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_BUFFERED_BYTES, DEFAULT_MAX_GAP)
    }

    /// Creates a QUIC reassembler with caller-supplied per-stream limits.
    #[must_use]
    pub fn with_limits(max_buffered_bytes_per_stream: usize, max_gap: usize) -> Self {
        Self {
            max_buffered_bytes_per_stream,
            max_gap,
            max_streams: DEFAULT_MAX_STREAMS,
            streams: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    /// Overrides the maximum number of concurrently tracked QUIC streams.
    #[must_use]
    pub fn with_max_streams(mut self, max_streams: usize) -> Self {
        self.max_streams = max_streams;
        self
    }

    /// Offers one QUIC STREAM frame and returns all newly contiguous bytes for its stream.
    #[allow(clippy::too_many_arguments)]
    pub fn offer(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        stream_id: u64,
        offset: u64,
        fin: bool,
        data: &[u8],
    ) -> Vec<u8> {
        let Ok(data_length) = u64::try_from(data.len()) else {
            return Vec::new();
        };
        let Some(end) = offset.checked_add(data_length) else {
            return Vec::new();
        };
        let key = normalized_quic_stream(src, src_port, dst, dst_port, stream_id);
        if !self.ensure_stream(&key) {
            return Vec::new();
        }
        let Some(state) = self.streams.get_mut(&key) else {
            return Vec::new();
        };
        if state.closed || !offset_within_gap(state.expected, offset, self.max_gap) {
            return Vec::new();
        }
        if !Self::accept_final_offset(state, end, fin) {
            return Vec::new();
        }

        let mut output = Vec::new();
        Self::accept_payload(
            state,
            offset,
            data,
            self.max_buffered_bytes_per_stream,
            &mut output,
        );
        Self::consume_contiguous(state, &mut output);
        Self::update_closed(state);
        output
    }

    /// Offers a parsed STREAM frame, or returns `None` for any other QUIC frame.
    ///
    /// The byte-oriented [`Self::offer`] remains primary so callers can use alternate QUIC
    /// decoders without constructing this crate's frame enum.
    #[allow(clippy::too_many_arguments)]
    pub fn offer_frame(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        frame: &QuicFrame<'_>,
    ) -> Option<Vec<u8>> {
        match frame {
            QuicFrame::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => Some(self.offer(
                src, src_port, dst, dst_port, *stream_id, *offset, *fin, data,
            )),
            _ => None,
        }
    }

    /// Returns whether a stream's final offset has been consumed contiguously.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn is_finished(
        &self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        stream_id: u64,
    ) -> bool {
        let key = normalized_quic_stream(src, src_port, dst, dst_port, stream_id);
        self.streams.get(&key).is_some_and(|state| state.closed)
    }

    /// Removes one stream, returning whether it existed.
    #[allow(clippy::too_many_arguments)]
    pub fn remove_stream(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        stream_id: u64,
    ) -> bool {
        let key = normalized_quic_stream(src, src_port, dst, dst_port, stream_id);
        let removed = self.streams.remove(&key).is_some();
        self.insertion_order.retain(|queued| queued != &key);
        removed
    }

    /// Removes every stream for a normalized UDP flow, returning whether any existed.
    pub fn remove_flow(&mut self, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> bool {
        let flow = normalized_flow(src, src_port, dst, dst_port).0;
        let previous_len = self.streams.len();
        self.streams
            .retain(|key, _| key.first != flow.first || key.second != flow.second);
        self.insertion_order
            .retain(|key| key.first != flow.first || key.second != flow.second);
        self.streams.len() != previous_len
    }

    /// Removes all stream state.
    pub fn clear(&mut self) {
        self.streams.clear();
        self.insertion_order.clear();
    }

    fn ensure_stream(&mut self, key: &QuicStreamKey) -> bool {
        if self.streams.contains_key(key) {
            return true;
        }
        if self.max_streams == 0 {
            return false;
        }
        self.evict_until_room();
        self.streams.insert(key.clone(), QuicStreamState::default());
        self.insertion_order.push_back(key.clone());
        true
    }

    fn evict_until_room(&mut self) {
        while self.streams.len() >= self.max_streams {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.streams.clear();
                break;
            };
            self.streams.remove(&oldest);
        }
    }

    fn accept_final_offset(state: &mut QuicStreamState, end: u64, fin: bool) -> bool {
        if state
            .fin_offset
            .is_some_and(|final_offset| end > final_offset || (fin && end != final_offset))
        {
            return false;
        }
        if fin {
            if end < state.expected {
                return false;
            }
            state.fin_offset = Some(end);
        }
        true
    }

    fn accept_payload(
        state: &mut QuicStreamState,
        offset: u64,
        data: &[u8],
        max_buffered_bytes: usize,
        output: &mut Vec<u8>,
    ) {
        if data.is_empty() {
            return;
        }
        if offset == state.expected {
            output.extend_from_slice(data);
            advance_quic_expected(state, data.len());
            return;
        }
        if offset > state.expected {
            Self::buffer_range(state, offset, data, max_buffered_bytes);
            return;
        }

        let Some(consumed) = state.expected.checked_sub(offset) else {
            return;
        };
        let Ok(consumed) = usize::try_from(consumed) else {
            return;
        };
        let Some(contiguous) = data.get(consumed..) else {
            return;
        };
        output.extend_from_slice(contiguous);
        advance_quic_expected(state, contiguous.len());
    }

    fn buffer_range(
        state: &mut QuicStreamState,
        offset: u64,
        data: &[u8],
        max_buffered_bytes: usize,
    ) {
        let replaced = state.ranges.get(&offset).map_or(0, Vec::len);
        let Some(without_replaced) = state.buffered_bytes.checked_sub(replaced) else {
            state.ranges.clear();
            state.buffered_bytes = 0;
            return;
        };
        let Some(projected) = without_replaced.checked_add(data.len()) else {
            state.ranges.clear();
            state.buffered_bytes = 0;
            return;
        };
        if projected > max_buffered_bytes {
            state.ranges.clear();
            state.buffered_bytes = 0;
            return;
        }
        state.ranges.insert(offset, data.to_vec());
        state.buffered_bytes = projected;
    }

    fn consume_contiguous(state: &mut QuicStreamState, output: &mut Vec<u8>) {
        loop {
            let expected = state.expected;
            let candidate = state.ranges.iter().find_map(|(offset, bytes)| {
                let consumed = expected.checked_sub(*offset)?;
                let consumed = usize::try_from(consumed).ok()?;
                (consumed < bytes.len()).then_some((*offset, consumed))
            });
            let Some((offset, consumed)) = candidate else {
                Self::discard_stale_ranges(state);
                return;
            };
            let Some(bytes) = state.ranges.remove(&offset) else {
                return;
            };
            state.buffered_bytes = state.buffered_bytes.saturating_sub(bytes.len());
            let Some(contiguous) = bytes.get(consumed..) else {
                continue;
            };
            let contiguous = truncate_at_final_offset(state, contiguous);
            if contiguous.is_empty() {
                return;
            }
            output.extend_from_slice(contiguous);
            advance_quic_expected(state, contiguous.len());
        }
    }

    fn discard_stale_ranges(state: &mut QuicStreamState) {
        let stale: Vec<u64> = state
            .ranges
            .iter()
            .filter_map(|(offset, bytes)| {
                let length = u64::try_from(bytes.len()).ok()?;
                let end = offset.checked_add(length)?;
                (end <= state.expected).then_some(*offset)
            })
            .collect();
        for offset in stale {
            if let Some(bytes) = state.ranges.remove(&offset) {
                state.buffered_bytes = state.buffered_bytes.saturating_sub(bytes.len());
            }
        }
    }

    fn update_closed(state: &mut QuicStreamState) {
        state.closed = state
            .fin_offset
            .is_some_and(|fin_offset| state.expected == fin_offset);
    }
}

impl Default for QuicStreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

fn normalized_quic_stream(
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    stream_id: u64,
) -> QuicStreamKey {
    let (flow, _) = normalized_flow(src, src_port, dst, dst_port);
    QuicStreamKey {
        first: flow.first,
        second: flow.second,
        stream_id,
    }
}

fn offset_within_gap(expected: u64, offset: u64, max_gap: usize) -> bool {
    let Some(gap) = offset.checked_sub(expected) else {
        return true;
    };
    usize::try_from(gap).is_ok_and(|gap| gap <= max_gap)
}

fn advance_quic_expected(state: &mut QuicStreamState, byte_count: usize) {
    let Ok(increment) = u64::try_from(byte_count) else {
        return;
    };
    if let Some(expected) = state.expected.checked_add(increment) {
        state.expected = expected;
    }
}

fn truncate_at_final_offset<'a>(state: &QuicStreamState, bytes: &'a [u8]) -> &'a [u8] {
    let Some(fin_offset) = state.fin_offset else {
        return bytes;
    };
    let Some(remaining) = fin_offset.checked_sub(state.expected) else {
        return &[];
    };
    let Ok(remaining) = usize::try_from(remaining) else {
        return bytes;
    };
    bytes.get(..bytes.len().min(remaining)).unwrap_or_default()
}

fn normalized_flow(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> (TcpFlowKey, usize) {
    let source = Endpoint {
        address: src,
        port: src_port,
    };
    let destination = Endpoint {
        address: dst,
        port: dst_port,
    };
    if source <= destination {
        (
            TcpFlowKey {
                first: source,
                second: destination,
            },
            0,
        )
    } else {
        (
            TcpFlowKey {
                first: destination,
                second: source,
            },
            1,
        )
    }
}

fn advance_expected(state: &mut TcpDirectionState, byte_count: usize) {
    let Some(expected) = state.expected else {
        return;
    };
    if let Ok(increment) = u32::try_from(byte_count) {
        state.expected = Some(expected.wrapping_add(increment));
    }
}

fn u32_to_usize(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn ipv4_header(offset: u16, more_fragments: bool) -> Ipv4Header {
        Ipv4Header {
            version: 4,
            ihl: 5,
            dscp: 0,
            ecn: 0,
            total_length: 20,
            identification: 42,
            flags: u8::from(more_fragments),
            fragment_offset: offset,
            ttl: 64,
            protocol: 6,
            checksum: 0,
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            options: None,
        }
    }

    #[test]
    fn ipv4_fragments_reassemble_in_order() {
        let payload = b"abcdefghABCDEFGH01234567";
        let mut reassembler = IpFragmentReassembler::new();
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(0, true), &payload[..8]),
            None
        );
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(1, true), &payload[8..16]),
            None
        );
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(2, false), &payload[16..]),
            Some(payload.to_vec())
        );
    }

    #[test]
    fn ipv4_fragments_wait_for_missing_middle() {
        let payload = b"abcdefghABCDEFGH01234567";
        let mut reassembler = IpFragmentReassembler::new();
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(2, false), &payload[16..]),
            None
        );
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(0, true), &payload[..8]),
            None
        );
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(1, true), &payload[8..16]),
            Some(payload.to_vec())
        );
    }

    #[test]
    fn ipv4_overlapping_fragments_drop_datagram() {
        let mut reassembler = IpFragmentReassembler::new();
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(0, true), b"abcdefghijklmnop"),
            None
        );
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(1, false), b"overlap!tail!!!!"),
            None
        );
        assert!(reassembler.datagrams.is_empty());
    }

    #[test]
    fn ipv4_adjacent_fragments_reassemble() {
        let payload = b"abcdefghABCDEFGH";
        let mut reassembler = IpFragmentReassembler::new();
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(0, true), &payload[..8]),
            None
        );
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(1, false), &payload[8..]),
            Some(payload.to_vec())
        );
    }

    #[test]
    fn unfragmented_ipv4_is_ignored() {
        let mut reassembler = IpFragmentReassembler::new();
        assert_eq!(
            reassembler.offer_ipv4(&ipv4_header(0, false), b"payload"),
            None
        );
    }

    #[test]
    fn ipv6_fragments_reassemble_out_of_order() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::UNSPECIFIED;
        let payload = b"abcdefghABCDEFGH01234567";
        let mut reassembler = IpFragmentReassembler::new();
        assert_eq!(
            reassembler.offer_ipv6(src, dst, 7, 1, true, 17, &payload[8..16]),
            None
        );
        assert_eq!(
            reassembler.offer_ipv6(src, dst, 7, 2, false, 17, &payload[16..]),
            None
        );
        assert_eq!(
            reassembler.offer_ipv6(src, dst, 7, 0, true, 17, &payload[..8]),
            Some(payload.to_vec())
        );
    }

    fn endpoints() -> (IpAddr, IpAddr) {
        (
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
        )
    }

    #[test]
    fn tcp_in_order_segments_return_immediately() {
        let (src, dst) = endpoints();
        let mut reassembler = TcpStreamReassembler::new();
        assert_eq!(
            reassembler.offer(src, 1000, dst, 80, 1, false, false, b"abc"),
            b"abc"
        );
        assert_eq!(
            reassembler.offer(src, 1000, dst, 80, 4, false, false, b"def"),
            b"def"
        );
    }

    #[test]
    fn tcp_out_of_order_segments_are_joined() {
        let (src, dst) = endpoints();
        let mut reassembler = TcpStreamReassembler::new();
        assert!(
            reassembler
                .offer(src, 1000, dst, 80, 0, true, false, b"")
                .is_empty()
        );
        assert!(
            reassembler
                .offer(src, 1000, dst, 80, 1_001, false, false, b"late")
                .is_empty()
        );
        let prefix = vec![b'a'; 1_000];
        let mut expected = prefix.clone();
        expected.extend_from_slice(b"late");
        assert_eq!(
            reassembler.offer(src, 1000, dst, 80, 1, false, false, &prefix),
            expected
        );
    }

    #[test]
    fn tcp_syn_and_sequence_wraparound_are_handled() {
        let (src, dst) = endpoints();
        let mut reassembler = TcpStreamReassembler::new();
        assert!(
            reassembler
                .offer(src, 1000, dst, 80, u32::MAX - 1, true, false, b"")
                .is_empty()
        );
        assert_eq!(
            reassembler.offer(src, 1000, dst, 80, u32::MAX, false, false, b"x"),
            b"x"
        );
        assert_eq!(
            reassembler.offer(src, 1000, dst, 80, 0, false, true, b"y"),
            b"y"
        );
    }

    #[test]
    fn tcp_buffer_limit_is_graceful() {
        let (src, dst) = endpoints();
        let mut reassembler = TcpStreamReassembler::with_limits(4, 65_535);
        assert!(
            reassembler
                .offer(src, 1000, dst, 80, 0, true, false, b"")
                .is_empty()
        );
        assert!(
            reassembler
                .offer(src, 1000, dst, 80, 10, false, false, b"12345")
                .is_empty()
        );
        assert_eq!(
            reassembler.offer(src, 1000, dst, 80, 1, false, false, b"ok"),
            b"ok"
        );
    }

    #[test]
    fn tcp_flow_count_is_bounded() {
        let (src, dst) = endpoints();
        let mut reassembler = TcpStreamReassembler::new().with_max_flows(2);

        for src_port in [1_000, 1_001, 1_002, 1_003] {
            assert!(
                reassembler
                    .offer(src, src_port, dst, 80, 100, true, false, b"")
                    .is_empty()
            );
            assert!(reassembler.flows.len() <= 2);
        }
    }

    #[test]
    fn tcp_evicted_flow_starts_with_fresh_sequence_state() {
        let (src, dst) = endpoints();
        let mut reassembler = TcpStreamReassembler::new().with_max_flows(2);

        assert_eq!(
            reassembler.offer(src, 1_000, dst, 80, 100, true, false, b"old"),
            b"old"
        );
        assert!(
            reassembler
                .offer(src, 1_001, dst, 80, 200, true, false, b"")
                .is_empty()
        );
        assert!(
            reassembler
                .offer(src, 1_002, dst, 80, 300, true, false, b"")
                .is_empty()
        );

        assert_eq!(
            reassembler.offer(src, 1_000, dst, 80, 100, true, false, b"fresh"),
            b"fresh"
        );
        assert_eq!(reassembler.flows.len(), 2);
    }

    #[test]
    fn quic_in_order_frames_return_immediately_and_finish_on_fin() {
        let (src, dst) = endpoints();
        let mut reassembler = QuicStreamReassembler::new();

        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 4, 0, false, b"one"),
            b"one"
        );
        assert!(!reassembler.is_finished(src, 4_432, dst, 443, 4));
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 4, 3, false, b"two"),
            b"two"
        );
        assert!(!reassembler.is_finished(src, 4_432, dst, 443, 4));
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 4, 6, true, b"three"),
            b"three"
        );
        assert!(reassembler.is_finished(src, 4_432, dst, 443, 4));
    }

    #[test]
    fn quic_out_of_order_frames_are_joined() {
        let (src, dst) = endpoints();
        let mut reassembler = QuicStreamReassembler::new();

        assert!(
            reassembler
                .offer(src, 4_432, dst, 443, 8, 10, true, b"later")
                .is_empty()
        );
        assert!(!reassembler.is_finished(src, 4_432, dst, 443, 8));
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 8, 0, false, b"0123456789"),
            b"0123456789later"
        );
        assert!(reassembler.is_finished(src, 4_432, dst, 443, 8));
    }

    #[test]
    fn quic_stream_ids_on_one_flow_are_independent() {
        let (src, dst) = endpoints();
        let mut reassembler = QuicStreamReassembler::new();

        assert!(
            reassembler
                .offer(src, 4_432, dst, 443, 0, 3, true, b"zero")
                .is_empty()
        );
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 4, 0, true, b"four"),
            b"four"
        );
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 0, 0, false, b"abc"),
            b"abczero"
        );
        assert!(reassembler.is_finished(src, 4_432, dst, 443, 0));
        assert!(reassembler.is_finished(src, 4_432, dst, 443, 4));
    }

    #[test]
    fn quic_matching_stream_ids_on_different_flows_are_independent() {
        let (src, dst) = endpoints();
        let mut reassembler = QuicStreamReassembler::new();

        assert!(
            reassembler
                .offer(src, 4_432, dst, 443, 0, 3, true, b"first")
                .is_empty()
        );
        assert!(
            reassembler
                .offer(src, 4_433, dst, 443, 0, 3, true, b"second")
                .is_empty()
        );
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 0, 0, false, b"one"),
            b"onefirst"
        );
        assert_eq!(
            reassembler.offer(src, 4_433, dst, 443, 0, 0, false, b"two"),
            b"twosecond"
        );
    }

    #[test]
    fn quic_max_gap_refuses_distant_frames() {
        let (src, dst) = endpoints();
        let mut reassembler = QuicStreamReassembler::with_limits(64, 4);

        assert!(
            reassembler
                .offer(src, 4_432, dst, 443, 0, 5, false, b"far")
                .is_empty()
        );
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 0, 0, false, b"abcde"),
            b"abcde"
        );
        let key = normalized_quic_stream(src, 4_432, dst, 443, 0);
        assert!(
            reassembler
                .streams
                .get(&key)
                .is_some_and(|state| state.ranges.is_empty())
        );
    }

    #[test]
    fn quic_stream_count_uses_fifo_eviction() {
        let (src, dst) = endpoints();
        let mut reassembler = QuicStreamReassembler::new().with_max_streams(2);

        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 0, 0, true, b"old"),
            b"old"
        );
        assert!(reassembler.is_finished(src, 4_432, dst, 443, 0));
        assert!(
            reassembler
                .offer(src, 4_432, dst, 443, 4, 3, false, b"held")
                .is_empty()
        );
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 8, 0, false, b"third"),
            b"third"
        );

        assert!(!reassembler.is_finished(src, 4_432, dst, 443, 0));
        assert_eq!(
            reassembler.offer(src, 4_432, dst, 443, 0, 0, false, b"fresh"),
            b"fresh"
        );
        assert_eq!(reassembler.streams.len(), 2);
    }

    #[test]
    fn parsed_quic_stream_frames_reassemble_end_to_end() {
        use crate::layer::application::quic::iter_quic_frames;

        let (src, dst) = endpoints();
        let payload = [
            0x0f, 9, 3, 3, b'd', b'e', b'f', 0x0a, 9, 3, b'a', b'b', b'c',
        ];
        let mut reassembler = QuicStreamReassembler::new();
        let mut output = Vec::new();

        for parsed in iter_quic_frames(&payload) {
            let Ok(frame) = parsed else {
                panic!("synthetic STREAM frame should parse");
            };
            let Some(contiguous) = reassembler.offer_frame(src, 4_432, dst, 443, &frame) else {
                panic!("synthetic payload should contain only STREAM frames");
            };
            output.extend_from_slice(&contiguous);
        }

        assert_eq!(output, b"abcdef");
        assert!(reassembler.is_finished(src, 4_432, dst, 443, 9));
    }
}
