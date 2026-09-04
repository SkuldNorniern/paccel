//! Opt-in QUIC connection-ID and packet-number state tracking.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::layer::Confidence;
use crate::layer::application::quic::{
    QuicShortHeader, decode_packet_number, parse_quic_short_header,
};

const DEFAULT_MAX_FLOWS: usize = 65_536;

/// RFC 9000 sec 12.3: packet numbers are independent per space, not one
/// sequence across a connection. 0-RTT and 1-RTT share the Application space.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuicPacketNumberSpace {
    Initial,
    Handshake,
    Application,
}

impl QuicPacketNumberSpace {
    fn index(self) -> usize {
        match self {
            Self::Initial => 0,
            Self::Handshake => 1,
            Self::Application => 2,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    address: IpAddr,
    port: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    first: Endpoint,
    second: Endpoint,
}

#[derive(Debug, Default)]
struct QuicFlowState {
    expected_dcids: [Option<Vec<u8>>; 2],
    largest_packet_numbers: [[Option<u64>; 3]; 2],
}

/// Tracks connection IDs and packet numbers for each direction of a UDP flow.
///
/// State is keyed on the 5-tuple, with connection IDs as a lookup into it.
/// That is not migration tracking. A connection that changes address gets a
/// new tuple with no learned DCID length, and short-header classification
/// needs that length before it can read the DCID, so the CID cannot pull the
/// two tuples back together. Packet-number state stays on the old tuple too.
///
/// Following a connection across a move needs identity on the connection
/// rather than the tuple, plus `NEW_CONNECTION_ID` and
/// `RETIRE_CONNECTION_ID` frames. Not in 0.3.
#[derive(Debug)]
pub struct QuicConnectionTracker {
    max_flows: usize,
    flows: HashMap<FlowKey, QuicFlowState>,
    insertion_order: VecDeque<FlowKey>,
    cid_index: HashMap<Vec<u8>, FlowKey>,
}

impl QuicConnectionTracker {
    /// Tracks up to 65,536 concurrent UDP flows.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            flows: HashMap::new(),
            insertion_order: VecDeque::new(),
            cid_index: HashMap::new(),
        }
    }

    /// Sets the concurrent UDP flow limit.
    #[must_use]
    pub fn with_max_flows(mut self, max_flows: usize) -> Self {
        self.max_flows = max_flows;
        self
    }

    /// Records a long-header SCID as the opposite direction's expected DCID.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_long_header(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        scid: &[u8],
    ) {
        if scid.is_empty() {
            return;
        }
        let (key, direction) = normalized_flow(src, src_port, dst, dst_port);
        if !self.ensure_flow(&key) {
            return;
        }
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.expected_dcids[1 - direction] = Some(scid.to_vec());
            self.cid_index.insert(scid.to_vec(), key);
        }
    }

    /// Resolves `dcid` across migration or NAT rebinding. The returned endpoints
    /// are the connection's last-seen tuple, not the packet's arrival tuple.
    #[must_use]
    pub fn connection_for_dcid(&self, dcid: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16)> {
        let key = self.cid_index.get(dcid)?;
        Some((
            key.first.address,
            key.first.port,
            key.second.address,
            key.second.port,
        ))
    }

    /// Returns the expected short-header DCID length learned from a long header.
    #[must_use]
    pub fn expected_dcid_len(
        &self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
    ) -> Option<usize> {
        let (key, direction) = normalized_flow(src, src_port, dst, dst_port);
        self.flows.get(&key)?.expected_dcids[direction]
            .as_ref()
            .map(Vec::len)
    }

    /// Parses a short header using the learned DCID length and rates the
    /// result: `Stateful` if the DCID matches a tracked connection,
    /// `Structural` otherwise. Returns `None` (not `Heuristic`) when no DCID
    /// length has been learned yet - the caller's own port/byte-pattern
    /// guess belongs outside this tracker.
    #[allow(clippy::too_many_arguments)]
    pub fn classify_short_header<'a>(
        &self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        payload: &'a [u8],
    ) -> Option<(QuicShortHeader<'a>, Confidence)> {
        let dcid_len = self.expected_dcid_len(src, src_port, dst, dst_port)?;
        let header = parse_quic_short_header(payload, dcid_len)?;
        let confidence = if self.connection_for_dcid(header.dcid).is_some() {
            Confidence::Stateful
        } else {
            Confidence::Structural
        };
        Some((header, confidence))
    }

    /// Reconstructs the packet number per RFC 9000 Appendix A.3 and updates
    /// that direction's maximum for `space` - Initial/Handshake/Application
    /// track independent packet-number sequences, per RFC 9000 sec 12.3.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_packet_number(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        space: QuicPacketNumberSpace,
        truncated_pn: u32,
        pn_len: usize,
    ) -> u64 {
        let (key, direction) = normalized_flow(src, src_port, dst, dst_port);
        if !self.ensure_flow(&key) {
            return decode_packet_number(None, truncated_pn, pn_len);
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            return decode_packet_number(None, truncated_pn, pn_len);
        };
        let space_index = space.index();
        let largest_pn = flow.largest_packet_numbers[direction][space_index];
        let packet_number = decode_packet_number(largest_pn, truncated_pn, pn_len);
        if largest_pn.is_none_or(|largest| packet_number >= largest) {
            flow.largest_packet_numbers[direction][space_index] = Some(packet_number);
        }
        packet_number
    }

    /// Removes both directions of a normalized flow, returning whether it existed.
    pub fn remove_flow(&mut self, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> bool {
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        let removed = self.flows.remove(&key).is_some();
        self.insertion_order.retain(|queued| queued != &key);
        self.remove_indexed_cids(&key);
        removed
    }

    /// Removes all flow state.
    pub fn clear(&mut self) {
        self.flows.clear();
        self.insertion_order.clear();
        self.cid_index.clear();
    }

    fn ensure_flow(&mut self, key: &FlowKey) -> bool {
        if self.flows.contains_key(key) {
            return true;
        }
        if self.max_flows == 0 {
            return false;
        }
        self.evict_until_room();
        self.flows.insert(key.clone(), QuicFlowState::default());
        self.insertion_order.push_back(key.clone());
        true
    }

    fn evict_until_room(&mut self) {
        while self.flows.len() >= self.max_flows {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.flows.clear();
                self.cid_index.clear();
                break;
            };
            self.flows.remove(&oldest);
            self.remove_indexed_cids(&oldest);
        }
    }

    fn remove_indexed_cids(&mut self, key: &FlowKey) {
        self.cid_index.retain(|_, indexed_flow| indexed_flow != key);
    }
}

impl Default for QuicConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn normalized_flow(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> (FlowKey, usize) {
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
            FlowKey {
                first: source,
                second: destination,
            },
            0,
        )
    } else {
        (
            FlowKey {
                first: destination,
                second: source,
            },
            1,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn endpoints() -> (IpAddr, IpAddr) {
        (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        )
    }

    #[test]
    fn learns_dcid_length_for_opposite_direction() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();

        tracker.observe_long_header(src, 1_000, dst, 443, &[1, 2, 3, 4, 5, 6, 7, 8]);

        assert_eq!(tracker.expected_dcid_len(dst, 443, src, 1_000), Some(8));
        assert_eq!(tracker.expected_dcid_len(src, 2_000, dst, 443), None);
    }

    #[test]
    fn resolves_connection_by_observed_cid() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();
        let cid = [1, 2, 3, 4, 5, 6, 7, 8];

        tracker.observe_long_header(src, 1_000, dst, 443, &cid);

        assert_eq!(
            tracker.connection_for_dcid(&cid),
            Some((src, 1_000, dst, 443))
        );
        assert_eq!(tracker.connection_for_dcid(&[9, 9, 9, 9]), None);
    }

    #[test]
    fn classify_short_header_is_stateful_when_dcid_matches_tracked_connection() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();
        let cid = [1, 2, 3, 4, 5, 6, 7, 8];
        tracker.observe_long_header(src, 1_000, dst, 443, &cid);

        let mut payload = vec![0x40];
        payload.extend_from_slice(&cid);
        let (header, confidence) = tracker
            .classify_short_header(dst, 443, src, 1_000, &payload)
            .expect("short header should parse");

        assert_eq!(header.dcid, cid);
        assert_eq!(confidence, Confidence::Stateful);
    }

    #[test]
    fn classify_short_header_is_structural_when_dcid_unrecognized() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();
        // Learns an 8-byte DCID length for the opposite direction, but the
        // packet below carries a different (never-observed) DCID value.
        tracker.observe_long_header(src, 1_000, dst, 443, &[1, 2, 3, 4, 5, 6, 7, 8]);

        let mut payload = vec![0x40];
        payload.extend_from_slice(&[9, 9, 9, 9, 9, 9, 9, 9]);
        let (_, confidence) = tracker
            .classify_short_header(dst, 443, src, 1_000, &payload)
            .expect("short header should parse");

        assert_eq!(confidence, Confidence::Structural);
    }

    #[test]
    fn classify_short_header_is_none_without_learned_dcid_length() {
        let (src, dst) = endpoints();
        let tracker = QuicConnectionTracker::new();
        let payload = [0x40, 1, 2, 3, 4];

        assert_eq!(
            tracker.classify_short_header(src, 1_000, dst, 443, &payload),
            None
        );
    }

    #[test]
    fn reconstructs_packet_numbers_with_per_direction_state() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();

        assert_eq!(
            tracker.reconstruct_packet_number(
                src,
                1_000,
                dst,
                443,
                QuicPacketNumberSpace::Application,
                0xa82f_30ea,
                4
            ),
            0xa82f_30ea
        );
        assert_eq!(
            tracker.reconstruct_packet_number(
                src,
                1_000,
                dst,
                443,
                QuicPacketNumberSpace::Application,
                0x9b32,
                2
            ),
            0xa82f_9b32
        );

        let (key, direction) = normalized_flow(src, 1_000, dst, 443);
        assert_eq!(
            tracker
                .flows
                .get(&key)
                .and_then(|flow| flow.largest_packet_numbers[direction]
                    [QuicPacketNumberSpace::Application.index()]),
            Some(0xa82f_9b32)
        );
    }

    #[test]
    fn packet_number_spaces_are_independent() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();

        // Push Initial's largest to 200.
        assert_eq!(
            tracker.reconstruct_packet_number(
                src,
                1_000,
                dst,
                443,
                QuicPacketNumberSpace::Initial,
                200,
                1
            ),
            200
        );
        // Handshake, same direction, has no state of its own yet - a truncated
        // PN of 5 must reconstruct to 5, not to a value inflated by treating
        // Initial's largest-200 as this space's context (which would give 261).
        assert_eq!(
            tracker.reconstruct_packet_number(
                src,
                1_000,
                dst,
                443,
                QuicPacketNumberSpace::Handshake,
                5,
                1
            ),
            5
        );
    }

    #[test]
    fn quic_flow_count_is_bounded_by_fifo_eviction() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new().with_max_flows(2);

        for src_port in [1_000, 1_001, 1_002, 1_003] {
            assert_eq!(
                tracker.reconstruct_packet_number(
                    src,
                    src_port,
                    dst,
                    443,
                    QuicPacketNumberSpace::Application,
                    0,
                    1
                ),
                0
            );
            assert!(tracker.flows.len() <= 2);
        }

        let (oldest, _) = normalized_flow(src, 1_000, dst, 443);
        let (newest, _) = normalized_flow(src, 1_003, dst, 443);
        assert!(!tracker.flows.contains_key(&oldest));
        assert!(tracker.flows.contains_key(&newest));
    }

    #[test]
    fn fifo_eviction_removes_cid_index_entry() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new().with_max_flows(2);
        let oldest_cid = [1, 2, 3, 4];

        tracker.observe_long_header(src, 1_000, dst, 443, &oldest_cid);
        tracker.observe_long_header(src, 1_001, dst, 443, &[5, 6, 7, 8]);
        tracker.observe_long_header(src, 1_002, dst, 443, &[9, 10, 11, 12]);

        assert_eq!(tracker.connection_for_dcid(&oldest_cid), None);
        assert_eq!(
            tracker.connection_for_dcid(&[9, 10, 11, 12]),
            Some((src, 1_002, dst, 443))
        );
    }
}
