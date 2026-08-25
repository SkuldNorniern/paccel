//! Opt-in, stateful IP fragment and TCP stream reassembly.
//!
//! The built-in packet parser remains stateless. All payload state maintained here is bounded by
//! caller-configurable limits; excess IP datagrams are evicted and excess TCP data is refused.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::layer::network::ipv4::Ipv4Header;

const DEFAULT_MAX_FRAGMENTS_PER_DATAGRAM: usize = 1_024;
const DEFAULT_MAX_DATAGRAM_BYTES: usize = 65_535;
const DEFAULT_MAX_CONCURRENT_DATAGRAMS: usize = 1_024;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 1_048_576;
const DEFAULT_MAX_GAP: usize = 65_535;
const DEFAULT_MAX_FLOWS: usize = 65_536;
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
    usize::try_from(value).map_or(usize::MAX, |converted| converted)
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
}
