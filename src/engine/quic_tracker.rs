//! Opt-in QUIC connection-ID and packet-number state tracking.

use std::collections::{HashMap, VecDeque};
use std::mem;
use std::net::IpAddr;

use crate::engine::flow::{BiFlow, Endpoint, LastSeen, Timestamp};
use crate::layer::Confidence;
use crate::layer::application::quic::{
    QuicShortHeader, decode_packet_number, parse_quic_short_header,
};

const DEFAULT_MAX_FLOWS: usize = 65_536;

/// The longest connection ID RFC 9000 allows. Longer ones cannot be indexed by
/// length, so they are not remembered.
const MAX_CID_LEN: usize = 20;

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

/// A connection, independent of the addresses carrying it.
///
/// Handed out by the tracker and only meaningful to it. A connection keeps its
/// id across a migration, which is the point: the tuple changes, this does not.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuicConnectionId(u64);

#[derive(Debug)]
struct QuicConnectionState {
    /// The endpoint that did not initiate. Direction is measured against it, so
    /// that a client changing address keeps the same two directions.
    ///
    /// Taken from the destination of the first long header seen, which in a
    /// capture that starts at the handshake is the server. A capture joined
    /// mid-connection, or one where the server's packet is seen first, can
    /// anchor on the wrong end; directions are then consistent but swapped.
    responder: Endpoint,
    /// Every tuple this connection has been seen on, most recent last.
    tuples: Vec<BiFlow>,
    /// Indexed by direction: 0 toward the responder, 1 away from it.
    expected_dcids: [Option<Vec<u8>>; 2],
    /// Connection IDs announced for this connection, with the sequence number
    /// that named each. Ordered by sequence number.
    ///
    /// RFC 9000 sec 5.1.1: an endpoint may issue several at once and retire
    /// them out of order, so the sequence number, not arrival, decides what is
    /// still live.
    issued_cids: Vec<(u64, Vec<u8>)>,
    last_seen: LastSeen,
    largest_packet_numbers: [[Option<u64>; 3]; 2],
}

impl QuicConnectionState {
    fn new(responder: Endpoint) -> Self {
        QuicConnectionState {
            responder,
            tuples: Vec::new(),
            expected_dcids: [None, None],
            issued_cids: Vec::new(),
            last_seen: LastSeen::default(),
            largest_packet_numbers: [[None; 3]; 2],
        }
    }

    /// 0 when the packet is headed for the responder, 1 when it comes from it.
    fn direction_to(&self, destination: Endpoint) -> usize {
        usize::from(destination != self.responder)
    }
}

/// What a [`QuicConnectionTracker`] is holding.
///
/// `active_tuples` and `active_cids` differ once a connection has announced
/// more than one identifier, or migrated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct QuicTrackerStats {
    /// UDP flows held right now.
    pub active_tuples: usize,
    /// Connection IDs that resolve to one of them.
    pub active_cids: usize,
    /// Connections held right now. Lower than `active_tuples` once one has
    /// migrated, since the old tuple stays bound until it is expired.
    pub active_connections: usize,
}

/// Tracks connection IDs and packet numbers for each direction of a connection.
///
/// State lives on the connection, not on the address pair carrying it. Tuples
/// and connection IDs are both indices into it:
///
/// ```text
/// 5-tuple ────┐
/// CID ────────┼──> QuicConnectionId ──> packet numbers, expected DCIDs
/// old tuple ──┘
/// ```
///
/// So a connection that changes address keeps its packet-number state.
/// [`Self::classify_short_header`] recognises the moved packet by its ID, and
/// [`Self::observe_short_header`] binds the new tuple to the connection it
/// names.
///
/// Direction is measured against the responder, the end that did not initiate,
/// rather than against the tuple, because the tuple's own ordering is not
/// stable across a move. The responder is taken to be the destination of the
/// first packet seen, which in a capture that starts at the handshake is the
/// server. A capture joined mid-connection can anchor on the wrong end;
/// directions are then consistent with each other but swapped.
#[derive(Debug)]
pub struct QuicConnectionTracker {
    /// Every connection-ID length seen, as a bit per length.
    ///
    /// A short header carries no length field, so one has to be assumed before
    /// the ID can be read. The tuple's own learned length is tried first; this
    /// is what lets a packet from a tuple that has never been seen - the shape
    /// of a migration - still be matched by its ID.
    cid_lengths: u32,
    max_flows: usize,
    connections: HashMap<QuicConnectionId, QuicConnectionState>,
    by_tuple: HashMap<BiFlow, QuicConnectionId>,
    by_cid: HashMap<Vec<u8>, QuicConnectionId>,
    /// Connections oldest first, for the capacity limit.
    insertion_order: VecDeque<QuicConnectionId>,
    next_id: u64,
}

impl QuicConnectionTracker {
    /// Tracks up to 65,536 concurrent UDP flows.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cid_lengths: 0,
            max_flows: DEFAULT_MAX_FLOWS,
            connections: HashMap::new(),
            by_tuple: HashMap::new(),
            by_cid: HashMap::new(),
            insertion_order: VecDeque::new(),
            next_id: 0,
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
        self.observe_long_header_inner(src, src_port, dst, dst_port, scid, None);
    }

    /// As [`Self::observe_long_header`], dating the flow so
    /// [`Self::expire_before`] can age it out.
    pub fn observe_long_header_at(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        scid: &[u8],
        now: Timestamp,
    ) {
        self.observe_long_header_inner(src, src_port, dst, dst_port, scid, Some(now));
    }

    /// Drop every dated connection last seen before `cutoff`, along with the
    /// tuples and connection IDs that pointed at it. Undated connections are
    /// left to the capacity limit.
    ///
    /// Returns the number of connections dropped, not tuples: a migrated
    /// connection expires once however many addresses it used.
    pub fn expire_before(&mut self, cutoff: Timestamp) -> usize {
        let before = self.connections.len();
        self.connections
            .retain(|_, connection| !connection.last_seen.is_before(cutoff));
        let expired = before - self.connections.len();
        if expired > 0 {
            self.reindex();
        }
        expired
    }

    /// Drops index entries whose connection is gone.
    fn reindex(&mut self) {
        self.by_tuple
            .retain(|_, id| self.connections.contains_key(id));
        self.by_cid
            .retain(|_, id| self.connections.contains_key(id));
        self.insertion_order
            .retain(|id| self.connections.contains_key(id));
    }

    fn observe_long_header_inner(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        scid: &[u8],
        now: Option<Timestamp>,
    ) {
        if scid.is_empty() {
            return;
        }
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        let source = Endpoint::new(src, src_port);
        let destination = Endpoint::new(dst, dst_port);

        // An SCID already on the books names the connection even when the
        // address pair does not: that is a long header arriving after a move.
        let id = match self.by_tuple.get(&key).or_else(|| self.by_cid.get(scid)) {
            Some(id) => *id,
            // Nothing known yet, so this is the first packet of a connection
            // and its destination is the end that did not initiate.
            None => {
                let Some(id) = self.open_connection(key, destination) else {
                    return;
                };
                id
            }
        };
        self.bind_tuple(id, key);

        let Some(connection) = self.connections.get_mut(&id) else {
            return;
        };
        // The sender announces the ID its peer should send *back* to, so this
        // is the DCID expected on packets headed the other way.
        let reply_direction = connection.direction_to(source);
        connection.expected_dcids[reply_direction] = Some(scid.to_vec());
        if let Some(now) = now {
            connection.last_seen.observe(now);
        }
        if scid.len() <= MAX_CID_LEN {
            self.cid_lengths |= 1 << scid.len();
        }
        self.by_cid.insert(scid.to_vec(), id);
    }

    /// Binds the arrival tuple of a short-header packet to the connection its
    /// DCID names, so that packet-number state follows a connection that moved.
    /// Returns the connection, or `None` when the DCID is not known.
    ///
    /// [`Self::classify_short_header`] only reads; this is what records the
    /// move.
    pub fn observe_short_header(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        dcid: &[u8],
    ) -> Option<QuicConnectionId> {
        self.observe_short_header_inner(src, src_port, dst, dst_port, dcid, None)
    }

    /// As [`Self::observe_short_header`], dating the connection so
    /// [`Self::expire_before`] can age it out.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_short_header_at(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        dcid: &[u8],
        now: Timestamp,
    ) -> Option<QuicConnectionId> {
        self.observe_short_header_inner(src, src_port, dst, dst_port, dcid, Some(now))
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_short_header_inner(
        &mut self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        dcid: &[u8],
        now: Option<Timestamp>,
    ) -> Option<QuicConnectionId> {
        let id = *self.by_cid.get(dcid)?;
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        self.bind_tuple(id, key);
        if let Some(now) = now
            && let Some(connection) = self.connections.get_mut(&id)
        {
            connection.last_seen.observe(now);
        }
        Some(id)
    }

    /// The connection a DCID names, if it is one being tracked.
    #[must_use]
    pub fn connection_id_for_dcid(&self, dcid: &[u8]) -> Option<QuicConnectionId> {
        self.by_cid.get(dcid).copied()
    }

    /// Every address pair a connection has been seen on, oldest first. A
    /// connection that has not migrated has exactly one.
    #[must_use]
    pub fn tuples_for_connection(&self, id: QuicConnectionId) -> &[BiFlow] {
        self.connections
            .get(&id)
            .map_or(&[][..], |connection| &connection.tuples)
    }

    /// Records a NEW_CONNECTION_ID frame: `cid` becomes another way to reach
    /// `id`, and everything below `retire_prior_to` stops resolving.
    ///
    /// RFC 9000 sec 19.15. Re-announcing a sequence number with different bytes
    /// is a protocol violation; the newer bytes win here rather than the frame
    /// being dropped, since a capture cannot make the peer behave.
    ///
    /// A connection ID longer than 20 bytes is refused, as RFC 9000 sec 5.1.1
    /// does not allow it. Returns whether the ID was recorded.
    pub fn observe_new_connection_id(
        &mut self,
        id: QuicConnectionId,
        sequence_number: u64,
        cid: &[u8],
        retire_prior_to: u64,
    ) -> bool {
        if cid.is_empty() || cid.len() > MAX_CID_LEN {
            return false;
        }
        let Some(connection) = self.connections.get_mut(&id) else {
            return false;
        };

        // Everything the peer just retired, before adding the new one: a frame
        // is allowed to announce a sequence number and retire earlier ones at
        // the same time.
        let mut dropped = Vec::new();
        connection.issued_cids.retain(|(sequence, held)| {
            let live = *sequence >= retire_prior_to;
            if !live {
                dropped.push(held.clone());
            }
            live
        });

        match connection
            .issued_cids
            .binary_search_by_key(&sequence_number, |(sequence, _)| *sequence)
        {
            Ok(position) => {
                let previous = mem::replace(&mut connection.issued_cids[position].1, cid.to_vec());
                if previous != cid {
                    dropped.push(previous);
                }
            }
            Err(position) => connection
                .issued_cids
                .insert(position, (sequence_number, cid.to_vec())),
        }

        for stale in dropped {
            self.by_cid.remove(&stale);
        }
        self.cid_lengths |= 1 << cid.len();
        self.by_cid.insert(cid.to_vec(), id);
        true
    }

    /// Records a RETIRE_CONNECTION_ID frame: the ID at `sequence_number` stops
    /// resolving to `id`. Returns whether there was one to retire.
    ///
    /// RFC 9000 sec 19.16. The connection itself survives - retiring one of its
    /// identifiers is routine, and other identifiers and its address pairs
    /// still reach it.
    pub fn observe_retire_connection_id(
        &mut self,
        id: QuicConnectionId,
        sequence_number: u64,
    ) -> bool {
        let Some(connection) = self.connections.get_mut(&id) else {
            return false;
        };
        let Ok(position) = connection
            .issued_cids
            .binary_search_by_key(&sequence_number, |(sequence, _)| *sequence)
        else {
            return false;
        };
        let (_, retired) = connection.issued_cids.remove(position);
        self.by_cid.remove(&retired);
        true
    }

    /// The connection IDs currently live for a connection, by sequence number.
    #[must_use]
    pub fn issued_connection_ids(&self, id: QuicConnectionId) -> Vec<(u64, &[u8])> {
        self.connections
            .get(&id)
            .map_or_else(Vec::new, |connection| {
                connection
                    .issued_cids
                    .iter()
                    .map(|(sequence, cid)| (*sequence, cid.as_slice()))
                    .collect()
            })
    }

    /// What this tracker is holding.
    #[must_use]
    pub fn stats(&self) -> QuicTrackerStats {
        QuicTrackerStats {
            active_tuples: self.by_tuple.len(),
            active_cids: self.by_cid.len(),
            active_connections: self.connections.len(),
        }
    }

    /// Resolves `dcid` across migration or NAT rebinding. The returned endpoints
    /// are the connection's last-seen tuple, not the packet's arrival tuple.
    #[must_use]
    pub fn connection_for_dcid(&self, dcid: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16)> {
        let id = self.by_cid.get(dcid)?;
        let key = self.connections.get(id)?.tuples.last()?;
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
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        let id = self.by_tuple.get(&key)?;
        let connection = self.connections.get(id)?;
        let direction = connection.direction_to(Endpoint::new(dst, dst_port));
        connection.expected_dcids[direction].as_ref().map(Vec::len)
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
        // The tuple's own learned length first: that is the ordinary case and
        // it costs one lookup.
        if let Some(dcid_len) = self.expected_dcid_len(src, src_port, dst, dst_port)
            && let Some(header) = parse_quic_short_header(payload, dcid_len)
        {
            let confidence = if self.connection_for_dcid(header.dcid).is_some() {
                Confidence::Stateful
            } else {
                Confidence::Structural
            };
            return Some((header, confidence));
        }

        // No length for this tuple. A connection that moved arrives exactly
        // this way, so try the lengths other connections have used and let the
        // ID say which connection it is. Longest first: a short ID can be a
        // prefix of a longer one, and the longer match is the specific
        // connection.
        let mut remaining = self.cid_lengths;
        while remaining != 0 {
            let length = (u32::BITS - 1 - remaining.leading_zeros()) as usize;
            remaining &= !(1 << length);

            let Some(header) = parse_quic_short_header(payload, length) else {
                continue;
            };
            if self.connection_for_dcid(header.dcid).is_some() {
                return Some((header, Confidence::Stateful));
            }
        }

        None
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
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        let destination = Endpoint::new(dst, dst_port);
        let id = match self.by_tuple.get(&key) {
            Some(id) => *id,
            None => match self.open_connection(key, destination) {
                Some(id) => id,
                None => return decode_packet_number(None, truncated_pn, pn_len),
            },
        };
        let Some(connection) = self.connections.get_mut(&id) else {
            return decode_packet_number(None, truncated_pn, pn_len);
        };
        let direction = connection.direction_to(destination);
        let space_index = space.index();
        let largest_pn = connection.largest_packet_numbers[direction][space_index];
        let packet_number = decode_packet_number(largest_pn, truncated_pn, pn_len);
        if largest_pn.is_none_or(|largest| packet_number >= largest) {
            connection.largest_packet_numbers[direction][space_index] = Some(packet_number);
        }
        packet_number
    }

    /// Removes both directions of a normalized flow, returning whether it
    /// existed.
    ///
    /// Removing one tuple of a migrated connection leaves the connection, and
    /// its other tuples, in place.
    pub fn remove_flow(&mut self, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> bool {
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        let Some(id) = self.by_tuple.remove(&key) else {
            return false;
        };
        let empty = match self.connections.get_mut(&id) {
            Some(connection) => {
                connection.tuples.retain(|held| held != &key);
                connection.tuples.is_empty()
            }
            None => true,
        };
        if empty {
            self.drop_connection(id);
        }
        true
    }

    /// Removes all connection state.
    pub fn clear(&mut self) {
        self.connections.clear();
        self.by_tuple.clear();
        self.by_cid.clear();
        self.insertion_order.clear();
    }

    /// Starts a connection on `key`, with `responder` as the end that did not
    /// initiate. `None` when the tracker is not allowed to hold any.
    fn open_connection(&mut self, key: BiFlow, responder: Endpoint) -> Option<QuicConnectionId> {
        if self.max_flows == 0 {
            return None;
        }
        self.evict_until_room();
        let id = QuicConnectionId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        let mut connection = QuicConnectionState::new(responder);
        connection.tuples.push(key);
        self.connections.insert(id, connection);
        self.by_tuple.insert(key, id);
        self.insertion_order.push_back(id);
        Some(id)
    }

    /// Points `key` at `id`, recording a migration when the tuple is new.
    ///
    /// An address pair can be reused by a new connection - a port comes back
    /// round, or a NAT rebinds - so binding it here may take it from whoever
    /// held it. The previous holder is told, because a connection left with a
    /// tuple it no longer owns reports addresses that reach a different
    /// connection, and can never be removed through that address again.
    fn bind_tuple(&mut self, id: QuicConnectionId, key: BiFlow) {
        match self.by_tuple.insert(key, id) {
            Some(previous) if previous == id => return,
            Some(previous) => {
                let emptied = self
                    .connections
                    .get_mut(&previous)
                    .is_some_and(|connection| {
                        connection.tuples.retain(|held| held != &key);
                        connection.tuples.is_empty()
                    });
                if emptied {
                    // Its last address is gone. Its connection IDs would
                    // otherwise resolve to a connection reachable by nothing.
                    self.drop_connection(previous);
                }
            }
            None => {}
        }

        if let Some(connection) = self.connections.get_mut(&id)
            && !connection.tuples.contains(&key)
        {
            connection.tuples.push(key);
        }
    }

    fn evict_until_room(&mut self) {
        while self.connections.len() >= self.max_flows {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.connections.clear();
                self.by_tuple.clear();
                self.by_cid.clear();
                break;
            };
            self.drop_connection(oldest);
        }
    }

    fn drop_connection(&mut self, id: QuicConnectionId) {
        self.connections.remove(&id);
        self.by_tuple.retain(|_, held| held != &id);
        self.by_cid.retain(|_, held| held != &id);
        self.insertion_order.retain(|queued| queued != &id);
    }
}

impl Default for QuicConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn normalized_flow(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> (BiFlow, usize) {
    let (flow, direction) = BiFlow::normalize(src, src_port, dst, dst_port);
    (flow, direction.index())
}

#[cfg(test)]
mod tests {

    #[test]
    fn expire_before_drops_dated_flows_and_their_connection_ids() {
        let mut tracker = QuicConnectionTracker::new();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        tracker.observe_long_header_at(a, 5_000, b, 443, &[1, 2, 3, 4], 1_000);
        tracker.observe_long_header_at(a, 6_000, b, 443, &[5, 6, 7, 8], 9_000);
        assert!(tracker.connection_for_dcid(&[1, 2, 3, 4]).is_some());

        assert_eq!(tracker.expire_before(5_000), 1);
        assert!(
            tracker.connection_for_dcid(&[1, 2, 3, 4]).is_none(),
            "the id goes with the flow"
        );
        assert!(tracker.connection_for_dcid(&[5, 6, 7, 8]).is_some());
    }

    /// The client moves to an address that sorts on the *other* side of the
    /// server, so the tuple's own direction ordering flips. Direction is
    /// anchored on the responder for exactly this reason.
    #[test]
    fn packet_number_state_follows_a_connection_that_moved() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let moved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let server_cid = [9, 9, 9, 9];
        let mut tracker = QuicConnectionTracker::new();

        tracker.observe_long_header(client, 5_000, server, 443, &[1, 2, 3, 4]);
        tracker.observe_long_header(server, 443, client, 5_000, &server_cid);
        assert_eq!(
            tracker.reconstruct_packet_number(
                client,
                5_000,
                server,
                443,
                QuicPacketNumberSpace::Application,
                0xa82f_30ea,
                4
            ),
            0xa82f_30ea
        );

        let (original, original_direction) = normalized_flow(client, 5_000, server, 443);
        let (relocated, relocated_direction) = normalized_flow(moved, 53_000, server, 443);
        assert_ne!(
            original_direction, relocated_direction,
            "the tuple orders the two addresses differently after the move, \
             which is what the responder anchor has to absorb"
        );

        let id = tracker
            .observe_short_header(moved, 53_000, server, 443, &server_cid)
            .expect("the server's id names the connection");
        assert_eq!(
            tracker.tuples_for_connection(id),
            &[original, relocated],
            "both addresses belong to the one connection"
        );

        assert_eq!(
            tracker.reconstruct_packet_number(
                moved,
                53_000,
                server,
                443,
                QuicPacketNumberSpace::Application,
                0x9b32,
                2
            ),
            0xa82f_9b32,
            "a truncated packet number decodes against what the connection \
             saw before it moved"
        );

        let stats = tracker.stats();
        assert_eq!(stats.active_connections, 1);
        assert_eq!(stats.active_tuples, 2);
    }

    fn opened(tracker: &mut QuicConnectionTracker) -> QuicConnectionId {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        tracker.observe_long_header(server, 443, client, 5_000, &[9, 9, 9, 9]);
        tracker
            .connection_id_for_dcid(&[9, 9, 9, 9])
            .expect("the long header opened one")
    }

    #[test]
    fn an_announced_connection_id_reaches_the_same_connection() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);

        assert!(tracker.observe_new_connection_id(id, 1, &[0xaa; 8], 0));
        assert_eq!(tracker.connection_id_for_dcid(&[0xaa; 8]), Some(id));
        assert_eq!(
            tracker.connection_id_for_dcid(&[9, 9, 9, 9]),
            Some(id),
            "announcing another id does not retire the first"
        );
        assert_eq!(tracker.stats().active_connections, 1);
    }

    #[test]
    fn a_retired_connection_id_stops_resolving() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);
        tracker.observe_new_connection_id(id, 1, &[0xaa; 8], 0);

        assert!(tracker.observe_retire_connection_id(id, 1));
        assert!(tracker.connection_id_for_dcid(&[0xaa; 8]).is_none());
        assert_eq!(
            tracker.stats().active_connections,
            1,
            "retiring one identifier does not end the connection"
        );
        assert!(
            !tracker.observe_retire_connection_id(id, 1),
            "retiring it twice reports nothing to retire"
        );
    }

    /// RFC 9000 sec 19.15: the frame can announce and retire in one step.
    #[test]
    fn retire_prior_to_drops_the_ids_it_names() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);
        tracker.observe_new_connection_id(id, 1, &[0xaa; 8], 0);
        tracker.observe_new_connection_id(id, 2, &[0xbb; 8], 0);

        tracker.observe_new_connection_id(id, 3, &[0xcc; 8], 2);
        assert!(tracker.connection_id_for_dcid(&[0xaa; 8]).is_none());
        assert_eq!(tracker.connection_id_for_dcid(&[0xbb; 8]), Some(id));
        assert_eq!(tracker.connection_id_for_dcid(&[0xcc; 8]), Some(id));
        assert_eq!(
            tracker.issued_connection_ids(id),
            vec![(2, &[0xbb; 8][..]), (3, &[0xcc; 8][..])]
        );
    }

    #[test]
    fn a_connection_id_that_breaks_the_length_rule_is_refused() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);

        assert!(!tracker.observe_new_connection_id(id, 1, &[], 0));
        assert!(!tracker.observe_new_connection_id(id, 2, &[0xdd; 21], 0));
        assert!(tracker.issued_connection_ids(id).is_empty());
    }

    /// Re-announcing a sequence number is a protocol violation, but a capture
    /// has to hold some answer. The newer bytes win and the older stop
    /// resolving, so one sequence number never names two live ids.
    #[test]
    fn re_announcing_a_sequence_number_replaces_the_id() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);
        tracker.observe_new_connection_id(id, 1, &[0xaa; 8], 0);

        tracker.observe_new_connection_id(id, 1, &[0xee; 8], 0);
        assert!(tracker.connection_id_for_dcid(&[0xaa; 8]).is_none());
        assert_eq!(tracker.connection_id_for_dcid(&[0xee; 8]), Some(id));
        assert_eq!(tracker.issued_connection_ids(id).len(), 1);
    }

    #[test]
    fn a_connection_id_announced_for_no_connection_is_refused() {
        let mut tracker = QuicConnectionTracker::new();
        assert!(!tracker.observe_new_connection_id(QuicConnectionId(99), 1, &[0xaa; 8], 0));
    }

    /// An announced id must be usable to follow a move, which is the whole
    /// point of the peer issuing spares.
    #[test]
    fn a_connection_moves_onto_an_announced_id() {
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let moved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);
        tracker.observe_new_connection_id(id, 1, &[0xaa; 8], 0);

        assert_eq!(
            tracker.observe_short_header(moved, 53_000, server, 443, &[0xaa; 8]),
            Some(id)
        );
        assert_eq!(tracker.stats().active_tuples, 2);
        assert_eq!(tracker.stats().active_connections, 1);
    }

    #[test]
    fn expiring_a_connection_drops_the_ids_it_announced() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut tracker = QuicConnectionTracker::new();
        tracker.observe_long_header_at(server, 443, client, 5_000, &[9, 9, 9, 9], 1_000);
        let id = tracker.connection_id_for_dcid(&[9, 9, 9, 9]).expect("open");
        tracker.observe_new_connection_id(id, 1, &[0xaa; 8], 0);

        assert_eq!(tracker.expire_before(2_000), 1);
        assert!(tracker.connection_id_for_dcid(&[0xaa; 8]).is_none());
        assert_eq!(tracker.stats().active_cids, 0);
    }

    /// An address pair can come back round to a different connection. When it
    /// does, the connection that held it must lose it: one left holding a
    /// tuple that now reaches someone else reports addresses that are not its
    /// own, and can never be removed through that address again.
    #[test]
    fn reusing_an_address_pair_takes_it_from_the_connection_that_held_it() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let mut tracker = QuicConnectionTracker::new();

        // One connection on the shared tuple, and a second one elsewhere.
        tracker.observe_long_header(server, 443, client, 5_000, &[1, 1, 1, 1]);
        tracker.observe_long_header(server, 443, other, 6_000, &[2, 2, 2, 2]);
        let first = tracker
            .connection_id_for_dcid(&[1, 1, 1, 1])
            .expect("the first connection");
        let second = tracker
            .connection_id_for_dcid(&[2, 2, 2, 2])
            .expect("the second connection");
        assert_ne!(first, second);

        // The second connection now appears on the first one's address pair.
        tracker.observe_short_header(client, 5_000, server, 443, &[2, 2, 2, 2]);

        let stats = tracker.stats();
        assert!(
            stats.active_connections <= stats.active_tuples,
            "{} connections holding only {} addresses means one is unreachable",
            stats.active_connections,
            stats.active_tuples
        );
        assert_eq!(
            tracker.tuples_for_connection(first).len(),
            0,
            "the first connection no longer holds an address it does not own"
        );
        assert!(
            tracker.connection_id_for_dcid(&[1, 1, 1, 1]).is_none(),
            "a connection with no addresses left keeps no ids either"
        );
    }

    #[test]
    fn an_unknown_id_binds_no_tuple() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut tracker = QuicConnectionTracker::new();

        tracker.observe_long_header(client, 5_000, server, 443, &[1, 2, 3, 4]);
        assert!(
            tracker
                .observe_short_header(client, 6_000, server, 443, &[7, 7, 7, 7])
                .is_none()
        );
        assert_eq!(tracker.stats().active_tuples, 1);
    }

    /// Removing one address of a migrated connection must not take the
    /// connection with it.
    #[test]
    fn removing_one_tuple_leaves_the_rest_of_the_connection() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let moved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let server_cid = [9, 9, 9, 9];
        let mut tracker = QuicConnectionTracker::new();

        tracker.observe_long_header(server, 443, client, 5_000, &server_cid);
        tracker.observe_short_header(moved, 53_000, server, 443, &server_cid);

        assert!(tracker.remove_flow(client, 5_000, server, 443));
        assert_eq!(tracker.stats().active_connections, 1);
        assert!(
            tracker.connection_for_dcid(&server_cid).is_some(),
            "the id still resolves through the address it moved to"
        );

        assert!(tracker.remove_flow(moved, 53_000, server, 443));
        assert_eq!(tracker.stats().active_connections, 0);
        assert!(tracker.connection_for_dcid(&server_cid).is_none());
    }

    /// A connection that has moved expires once, not once per address.
    #[test]
    fn expiry_counts_connections_not_tuples() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let moved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let server_cid = [9, 9, 9, 9];
        let mut tracker = QuicConnectionTracker::new();

        tracker.observe_long_header_at(server, 443, client, 5_000, &server_cid, 1_000);
        tracker.observe_short_header_at(moved, 53_000, server, 443, &server_cid, 2_000);

        assert_eq!(
            tracker.expire_before(1_500),
            0,
            "the move refreshed the connection"
        );
        assert_eq!(tracker.expire_before(3_000), 1);
        assert_eq!(
            tracker.stats().active_tuples,
            0,
            "both addresses go with it"
        );
    }

    #[test]
    fn undated_flows_survive_expiry() {
        let mut tracker = QuicConnectionTracker::new();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        tracker.observe_long_header(a, 5_000, b, 443, &[1, 2, 3, 4]);
        assert_eq!(tracker.expire_before(u64::MAX), 0);
        assert!(tracker.connection_for_dcid(&[1, 2, 3, 4]).is_some());
    }
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

    /// A connection that changes address arrives on a tuple that has never been
    /// seen, so it has no learned DCID length. Classification used to give up
    /// there, before the connection ID had a chance to say which connection it
    /// was - which is exactly the migration case.
    #[test]
    fn classify_short_header_follows_a_connection_that_moved() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();
        let cid = [1, 2, 3, 4, 5, 6, 7, 8];

        // Handshake on the original tuple.
        tracker.observe_long_header(src, 50_000, dst, 443, &cid);

        let mut payload = vec![0x40];
        payload.extend_from_slice(&cid);

        // The client reappears on a different port, carrying the same ID.
        let moved = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let (header, confidence) = tracker
            .classify_short_header(dst, 443, moved, 53_000, &payload)
            .expect("the id should still resolve");

        assert_eq!(header.dcid, cid);
        assert_eq!(
            confidence,
            Confidence::Stateful,
            "matched by connection ID, not by tuple"
        );
        assert!(tracker.connection_for_dcid(&cid).is_some());
    }

    /// An unknown ID on an unknown tuple stays unknown: the fallback must not
    /// invent a match out of whatever bytes happen to be there.
    #[test]
    fn classify_short_header_does_not_invent_a_connection() {
        let (src, dst) = endpoints();
        let mut tracker = QuicConnectionTracker::new();
        tracker.observe_long_header(src, 50_000, dst, 443, &[1, 2, 3, 4, 5, 6, 7, 8]);

        let mut payload = vec![0x40];
        payload.extend_from_slice(&[9, 9, 9, 9, 9, 9, 9, 9]);

        let moved = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        assert!(
            tracker
                .classify_short_header(dst, 443, moved, 53_000, &payload)
                .is_none()
        );
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

        let (key, _) = normalized_flow(src, 1_000, dst, 443);
        let id = tracker.by_tuple[&key];
        let connection = &tracker.connections[&id];
        let direction = connection.direction_to(Endpoint::new(dst, 443));
        assert_eq!(
            connection.largest_packet_numbers[direction]
                [QuicPacketNumberSpace::Application.index()],
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
            assert!(tracker.connections.len() <= 2);
        }

        let (oldest, _) = normalized_flow(src, 1_000, dst, 443);
        let (newest, _) = normalized_flow(src, 1_003, dst, 443);
        assert!(!tracker.by_tuple.contains_key(&oldest));
        assert!(tracker.by_tuple.contains_key(&newest));
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
