//! Opt-in QUIC connection-ID and packet-number state tracking.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::layer::application::quic::decode_packet_number;

const DEFAULT_MAX_FLOWS: usize = 65_536;

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
    largest_packet_numbers: [Option<u64>; 2],
}

/// Tracks connection IDs and packet numbers for each direction of a UDP flow.
#[derive(Debug)]
pub struct QuicConnectionTracker {
    max_flows: usize,
    flows: HashMap<FlowKey, QuicFlowState>,
    insertion_order: VecDeque<FlowKey>,
}

impl QuicConnectionTracker {
    /// Creates a tracker for up to 65,536 concurrent UDP flows.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            flows: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    /// Overrides the maximum number of concurrently tracked UDP flows.
    #[must_use]
    pub fn with_max_flows(mut self, max_flows: usize) -> Self {
        self.max_flows = max_flows;
        self
    }

    /// Records a long-header packet's SCID as the connection ID the opposite
    /// direction should expect as DCID in future short-header packets.
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
        }
    }

    /// Returns the connection ID length this direction's short-header packets
    /// are expected to use as DCID, if learned from an earlier long-header
    /// exchange. Returns `None` if it is not yet known, allowing callers to
    /// retain their existing heuristic as a fallback.
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

    /// Reconstructs a full packet number for this direction using the flow's
    /// largest packet number (RFC 9000 Appendix A.3) and updates the stored
    /// maximum.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_packet_number(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
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
        let largest_pn = flow.largest_packet_numbers[direction];
        let packet_number = decode_packet_number(largest_pn, truncated_pn, pn_len);
        if largest_pn.is_none_or(|largest| packet_number >= largest) {
            flow.largest_packet_numbers[direction] = Some(packet_number);
        }
        packet_number
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
                break;
            };
            self.flows.remove(&oldest);
        }
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
    fn reconstructs_packet_numbers_with_per_direction_state() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();

        assert_eq!(
            tracker.reconstruct_packet_number(src, 1_000, dst, 443, 0xa82f_30ea, 4),
            0xa82f_30ea
        );
        assert_eq!(
            tracker.reconstruct_packet_number(src, 1_000, dst, 443, 0x9b32, 2),
            0xa82f_9b32
        );

        let (key, direction) = normalized_flow(src, 1_000, dst, 443);
        assert_eq!(
            tracker
                .flows
                .get(&key)
                .and_then(|flow| flow.largest_packet_numbers[direction]),
            Some(0xa82f_9b32)
        );
    }

    #[test]
    fn quic_flow_count_is_bounded_by_fifo_eviction() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new().with_max_flows(2);

        for src_port in [1_000, 1_001, 1_002, 1_003] {
            assert_eq!(
                tracker.reconstruct_packet_number(src, src_port, dst, 443, 0, 1),
                0
            );
            assert!(tracker.flows.len() <= 2);
        }

        let (oldest, _) = normalized_flow(src, 1_000, dst, 443);
        let (newest, _) = normalized_flow(src, 1_003, dst, 443);
        assert!(!tracker.flows.contains_key(&oldest));
        assert!(tracker.flows.contains_key(&newest));
    }
}
