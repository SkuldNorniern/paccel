//! Opt-in QUIC connection-ID and packet-number state tracking.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;

use crate::engine::flow::{BiFlow, Endpoint, LastSeen, Timestamp};
use crate::layer::Confidence;
use crate::layer::application::quic::{
    QuicShortHeader, decode_packet_number, parse_quic_short_header,
};

const DEFAULT_MAX_FLOWS: usize = 65_536;
/// Four addresses per connection on average, which is generous for migration.
const DEFAULT_MAX_TUPLES: usize = DEFAULT_MAX_FLOWS * 4;
/// RFC 9000 sec 9 migrations are occasional, not continuous.
const DEFAULT_MAX_TUPLES_PER_CONNECTION: usize = 8;
/// RFC 9000 sec 5.1.1: active_connection_id_limit is small, and both ends have
/// one pool each.
const DEFAULT_MAX_CIDS: usize = DEFAULT_MAX_FLOWS * 4;
/// Generous next to the active_connection_id_limit peers actually negotiate.
const DEFAULT_MAX_CIDS_PER_POOL: usize = 32;

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

/// Which way a packet travelled through a QUIC connection.
///
/// Anchored on the endpoint roles, not on address ordering, so it stays the
/// same when a client changes address.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QuicDirection {
    InitiatorToResponder,
    ResponderToInitiator,
}

impl QuicDirection {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::InitiatorToResponder => 0,
            Self::ResponderToInitiator => 1,
        }
    }

    fn from_index(index: usize) -> Self {
        if index == 0 {
            Self::InitiatorToResponder
        } else {
            Self::ResponderToInitiator
        }
    }
}

/// A connection, independent of the addresses carrying it.
///
/// Handed out by the tracker and only meaningful to it. A connection keeps its
/// id across a migration, which is the point: the tuple changes, this does not.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QuicConnectionId(u64);

/// The connection IDs one endpoint has issued.
#[derive(Debug, Default)]
struct QuicCidPool {
    ids: BTreeMap<u64, Vec<u8>>,
    /// The largest `Retire Prior To` seen. RFC 9000 sec 19.15: a smaller value
    /// later has no effect, and an ID below the threshold stays retired even if
    /// it is announced afterwards.
    retire_prior_to: u64,
}

#[derive(Debug)]
struct QuicConnectionState {
    /// The endpoint that did not initiate, taken from the destination of the
    /// first long header. Direction is measured against it so a client that
    /// changes address keeps the same two directions. A capture joined
    /// mid-connection can anchor on the wrong end and swap them.
    responder: Endpoint,
    /// Every tuple this connection has been seen on, most recent last.
    tuples: Vec<BiFlow>,
    /// Indexed by direction: 0 toward the responder, 1 away from it.
    expected_dcids: [Option<Vec<u8>>; 2],
    /// One pool per issuer, indexed the same way as `expected_dcids`.
    ///
    /// Each endpoint numbers its own connection IDs from zero, so both sides
    /// hold a sequence 1. One shared pool lets the server's overwrite the
    /// client's.
    issued_cids: [QuicCidPool; 2],
    last_seen: LastSeen,
    largest_packet_numbers: [[Option<u64>; 3]; 2],
}

impl QuicConnectionState {
    fn indexed_cids(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.expected_dcids
            .iter()
            .flatten()
            .chain(self.issued_cids.iter().flat_map(|pool| pool.ids.values()))
    }

    fn new(responder: Endpoint) -> Self {
        QuicConnectionState {
            responder,
            tuples: Vec::new(),
            expected_dcids: [None, None],
            issued_cids: [QuicCidPool::default(), QuicCidPool::default()],
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
    /// Distinct connection ID byte strings indexed right now.
    ///
    /// Counted once each, not once per holder: two connections may hold the
    /// same ID, and this is what `with_max_cids` bounds.
    pub active_cids: usize,
    /// Connections held right now. Lower than `active_tuples` once one has
    /// migrated, since the old tuple stays bound until it is expired.
    pub active_connections: usize,
}

/// Tracks connection IDs and packet numbers for each direction of a connection.
///
/// State lives on the connection, not the address pair carrying it; tuples and
/// connection IDs are both indices into it, so a move keeps its state.
///
/// [`Self::classify_short_header`] recognises a moved packet by its ID, and
/// [`Self::observe_short_header`] binds the new tuple. Direction is measured
/// against the responder, since the tuple's ordering is not stable across a
/// move.
#[derive(Debug)]
pub struct QuicConnectionTracker {
    /// Every connection-ID length seen, as a bit per length. A short header
    /// carries no length field, so one has to be assumed; trying the lengths
    /// other connections used is what matches a packet from a moved tuple.
    cid_lengths: u32,
    max_flows: usize,
    /// Address pairs across every connection. A migrating connection binds a
    /// new tuple without adding a connection, so the connection cap alone does
    /// not bound this.
    max_tuples: usize,
    /// Address pairs one connection may hold. A peer that keeps moving would
    /// otherwise grow a single connection without limit.
    max_tuples_per_connection: usize,
    /// Live connection IDs across every connection.
    max_cids: usize,
    /// Live connection IDs one endpoint of one connection may hold. RFC 9000
    /// sec 5.1.1 bounds this with active_connection_id_limit; a peer that
    /// ignores it must not grow the index without limit.
    max_cids_per_pool: usize,
    connections: HashMap<QuicConnectionId, QuicConnectionState>,
    by_tuple: HashMap<BiFlow, QuicConnectionId>,
    /// Connections holding each connection ID. Two may hold the same bytes.
    by_cid: HashMap<Vec<u8>, Vec<QuicConnectionId>>,
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
            max_tuples: DEFAULT_MAX_TUPLES,
            max_tuples_per_connection: DEFAULT_MAX_TUPLES_PER_CONNECTION,
            max_cids: DEFAULT_MAX_CIDS,
            max_cids_per_pool: DEFAULT_MAX_CIDS_PER_POOL,
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

    /// Sets the address pairs held across every connection, and the most one
    /// connection may hold.
    ///
    /// A migrating connection binds another tuple without adding a connection,
    /// so the connection cap does not bound this on its own.
    #[must_use]
    pub fn with_max_tuples(mut self, total: usize, per_connection: usize) -> Self {
        self.max_tuples = total;
        self.max_tuples_per_connection = per_connection;
        self
    }

    /// Sets the live connection IDs held across every connection.
    #[must_use]
    pub fn with_max_cids(mut self, max_cids: usize) -> Self {
        self.max_cids = max_cids;
        self
    }

    /// Sets the live connection IDs one endpoint of one connection may hold.
    #[must_use]
    pub fn with_max_cids_per_pool(mut self, max_cids_per_pool: usize) -> Self {
        self.max_cids_per_pool = max_cids_per_pool;
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

    /// Drop every dated connection last seen before `cutoff`, and the tuples
    /// and IDs pointing at it. Undated ones are left to the capacity limit.
    ///
    /// Counts connections, not tuples: a migrated one expires once.
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
        let connections = &self.connections;
        self.by_cid.retain(|_, holders| {
            holders.retain(|id| connections.contains_key(id));
            !holders.is_empty()
        });
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
        // A zero-length SCID is legal (RFC 9000 sec 17.2): an endpoint that
        // does not need its peer to address it by ID uses none.
        let named = !scid.is_empty();
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        let source = Endpoint::new(src, src_port);
        let destination = Endpoint::new(dst, dst_port);

        // An SCID already on the books names the connection even when the
        // address pair does not: that is a long header arriving after a move.
        let matched = self.by_tuple.get(&key).copied().or_else(|| {
            named
                .then(|| self.holder_sharing_an_endpoint(scid, key))
                .flatten()
        });

        let id = match matched {
            Some(id) => id,
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
        let reply_direction = connection.direction_to(source);
        if !named {
            // Nothing to expect back and nothing to index, but the tuple above
            // is now bound and the connection is dated below.
            if let Some(now) = now {
                connection.last_seen.observe(now);
            }
            return;
        }

        // The sender announces the ID its peer should send *back* to, so this
        // is the DCID expected on packets headed the other way.
        let displaced = connection.expected_dcids[reply_direction]
            .replace(scid.to_vec())
            .filter(|previous| previous != scid);

        // RFC 9000 sec 5.1.1: the ID an endpoint puts in its first long header
        // is its sequence 0. Without it here, RETIRE_CONNECTION_ID(0) and a
        // retire_prior_to above 0 have nothing to act on.
        let pool = &mut connection.issued_cids[reply_direction];
        if pool.retire_prior_to == 0 && self.max_cids_per_pool > 0 {
            pool.ids.entry(0).or_insert_with(|| scid.to_vec());
        }
        if let Some(now) = now {
            connection.last_seen.observe(now);
        }
        if scid.len() <= MAX_CID_LEN {
            self.cid_lengths |= 1 << scid.len();
        }

        if let Some(displaced) = displaced
            && let Some(connection) = self.connections.get(&id)
            && !connection.indexed_cids().any(|held| held == &displaced)
        {
            self.release_cid(&displaced, id);
        }

        self.remember_cid(scid, id);
    }

    /// Binds a short header's arrival tuple to the connection its DCID names,
    /// so packet-number state follows a move. `None` if the DCID is unknown.
    /// [`Self::classify_short_header`] only reads; this records the move.
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
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        // The connection ID decides, not the address pair: RFC 9000 sec 5.1
        // gives a connection an ID so it survives a change of address, and a
        // pair can be reused by whatever comes next.
        let id = self.holder_for(dcid, key)?;
        self.bind_tuple(id, key);
        if let Some(now) = now
            && let Some(connection) = self.connections.get_mut(&id)
        {
            connection.last_seen.observe(now);
        }
        Some(id)
    }

    /// Which way a packet from `src` to `dst` travelled through `id`.
    ///
    /// The stable answer, so a caller keying state on direction does not have
    /// to know that the tuple's own ordering flips when a client moves.
    #[must_use]
    pub fn direction_for(
        &self,
        id: QuicConnectionId,
        _src: Endpoint,
        dst: Endpoint,
    ) -> Option<QuicDirection> {
        let connection = self.connections.get(&id)?;
        Some(QuicDirection::from_index(connection.direction_to(dst)))
    }

    /// The connection a packet belongs to and which way it travelled, resolved
    /// by its address pair or, when that is new, by its connection ID.
    #[must_use]
    pub fn connection_and_direction(
        &self,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        dcid: &[u8],
    ) -> Option<(QuicConnectionId, QuicDirection)> {
        let (key, _) = normalized_flow(src, src_port, dst, dst_port);
        let id = self
            .by_tuple
            .get(&key)
            .copied()
            .or_else(|| self.holder_for(dcid, key))?;
        let direction = self.direction_for(
            id,
            Endpoint::new(src, src_port),
            Endpoint::new(dst, dst_port),
        )?;
        Some((id, direction))
    }

    /// The connection a DCID names, if it is one being tracked.
    #[must_use]
    pub fn connection_id_for_dcid(&self, dcid: &[u8]) -> Option<QuicConnectionId> {
        match self.by_cid.get(dcid)?.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// Every connection holding `dcid`, in the order they claimed it.
    #[must_use]
    pub fn connections_for_dcid(&self, dcid: &[u8]) -> &[QuicConnectionId] {
        self.by_cid.get(dcid).map_or(&[], Vec::as_slice)
    }

    fn holder_for(&self, dcid: &[u8], key: BiFlow) -> Option<QuicConnectionId> {
        match self.by_cid.get(dcid)?.as_slice() {
            [] => None,
            [only] => Some(*only),
            _ => self.holder_sharing_an_endpoint(dcid, key),
        }
    }

    fn holder_sharing_an_endpoint(&self, dcid: &[u8], key: BiFlow) -> Option<QuicConnectionId> {
        self.by_cid.get(dcid)?.iter().copied().find(|id| {
            self.connections.get(id).is_some_and(|connection| {
                connection
                    .tuples
                    .iter()
                    .any(|held| key.shared_endpoint(*held).is_some())
            })
        })
    }

    /// Every address pair a connection has been seen on, oldest first. A
    /// connection that has not migrated has exactly one.
    #[must_use]
    pub fn tuples_for_connection(&self, id: QuicConnectionId) -> &[BiFlow] {
        self.connections
            .get(&id)
            .map_or(&[][..], |connection| &connection.tuples)
    }

    /// Records a NEW_CONNECTION_ID frame from `issuer`.
    ///
    /// `cid` becomes another way to reach `id`, and everything the issuer
    /// numbered below `retire_prior_to` stops resolving. The issuer is needed
    /// because each endpoint numbers its own IDs from zero.
    ///
    /// RFC 9000 sec 19.15. `retire_prior_to` above `sequence_number` is a
    /// FRAME_ENCODING_ERROR and is refused. An ID over 20 bytes is refused.
    /// Re-announcing a sequence number is a violation; the newer bytes win,
    /// since a capture cannot make the peer behave. Returns whether the ID was
    /// recorded.
    pub fn observe_new_connection_id(
        &mut self,
        id: QuicConnectionId,
        issuer: Endpoint,
        sequence_number: u64,
        cid: &[u8],
        retire_prior_to: u64,
    ) -> bool {
        if cid.is_empty() || cid.len() > MAX_CID_LEN || retire_prior_to > sequence_number {
            return false;
        }
        let Some(connection) = self.connections.get_mut(&id) else {
            return false;
        };
        let pool = &mut connection.issued_cids[connection.direction_to(issuer)];

        // A smaller value later has no effect.
        pool.retire_prior_to = pool.retire_prior_to.max(retire_prior_to);

        let mut dropped: Vec<Vec<u8>> = pool
            .ids
            .range(..pool.retire_prior_to)
            .map(|(_, held)| held.clone())
            .collect();
        pool.ids
            .retain(|sequence, _| *sequence >= pool.retire_prior_to);

        // Already retired by an earlier frame, so it does not come back.
        if sequence_number < pool.retire_prior_to {
            for stale in dropped {
                self.release_cid(&stale, id);
            }
            return false;
        }

        if let Some(previous) = pool.ids.insert(sequence_number, cid.to_vec())
            && previous != cid
        {
            dropped.push(previous);
        }

        // A peer that ignores its own active_connection_id_limit loses its
        // oldest ids rather than growing the index without bound.
        while pool.ids.len() > self.max_cids_per_pool {
            let Some(oldest) = pool.ids.keys().next().copied() else {
                break;
            };
            if let Some(stale) = pool.ids.remove(&oldest) {
                dropped.push(stale);
            }
        }

        let kept = pool
            .ids
            .get(&sequence_number)
            .is_some_and(|held| held == cid);

        for stale in dropped {
            self.release_cid(&stale, id);
        }
        if !kept {
            return false;
        }

        self.cid_lengths |= 1 << cid.len();
        self.remember_cid(cid, id);
        true
    }

    /// Records a RETIRE_CONNECTION_ID frame: the ID `issuer` numbered
    /// `sequence_number` stops resolving to `id`.
    ///
    /// RFC 9000 sec 19.16. The connection survives; its other IDs and address
    /// pairs still reach it. Returns whether there was one to retire.
    pub fn observe_retire_connection_id(
        &mut self,
        id: QuicConnectionId,
        issuer: Endpoint,
        sequence_number: u64,
    ) -> bool {
        let Some(connection) = self.connections.get_mut(&id) else {
            return false;
        };
        let pool = &mut connection.issued_cids[connection.direction_to(issuer)];
        let Some(retired) = pool.ids.remove(&sequence_number) else {
            return false;
        };
        self.release_cid(&retired, id);
        true
    }

    /// The connection IDs `issuer` currently has live, by sequence number.
    #[must_use]
    pub fn issued_connection_ids(
        &self,
        id: QuicConnectionId,
        issuer: Endpoint,
    ) -> Vec<(u64, &[u8])> {
        self.connections
            .get(&id)
            .map_or_else(Vec::new, |connection| {
                connection.issued_cids[connection.direction_to(issuer)]
                    .ids
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
        let id = self.connection_id_for_dcid(dcid)?;
        let key = self.connections.get(&id)?.tuples.last()?;
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
        // A zero cap on any of the three means there is nowhere to put this.
        if self.max_flows == 0 || self.max_tuples == 0 || self.max_tuples_per_connection == 0 {
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
    /// An address pair can be reused - a port comes round, a NAT rebinds - so
    /// this may take it from whoever held it. The previous holder is told, or
    /// it reports an address that now reaches someone else.
    fn bind_tuple(&mut self, id: QuicConnectionId, key: BiFlow) {
        // The responder is a role, not an address. If the address it was
        // anchored on is gone from this pair, the responder is the end that
        // moved, so the anchor follows it to its new address. Anchoring on the
        // end that stayed would hand the role to the initiator and swap both
        // directions.
        if let Some(connection) = self.connections.get_mut(&id)
            && !key.holds(connection.responder)
            && let Some(moved) = connection
                .tuples
                .iter()
                .find_map(|held| key.shared_endpoint(*held))
                .and_then(|stationary| key.other_endpoint(stationary))
        {
            connection.responder = moved;
        }

        if !self.by_tuple.contains_key(&key) {
            // A cap of zero means zero: there is no room to make.
            if self.max_tuples == 0 || self.max_tuples_per_connection == 0 {
                return;
            }
            // A connection that keeps moving drops its oldest address rather
            // than growing without bound.
            if let Some(connection) = self.connections.get_mut(&id)
                && connection.tuples.len() >= self.max_tuples_per_connection
                && !connection.tuples.is_empty()
            {
                let oldest = connection.tuples.remove(0);
                self.by_tuple.remove(&oldest);
            }
            // And the tracker as a whole stays inside its total.
            while self.by_tuple.len() >= self.max_tuples {
                let Some(victim) = self.insertion_order.front().copied() else {
                    break;
                };
                self.insertion_order.pop_front();
                self.drop_connection(victim);
            }
        }
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

    /// Indexes `cid`, evicting whole connections first if the tracker is at its
    /// connection-ID cap. An index bigger than what it points at is how a
    /// tracker grows without bound while its connection count looks healthy.
    fn remember_cid(&mut self, cid: &[u8], id: QuicConnectionId) {
        if self.max_cids == 0 {
            return;
        }
        while self.by_cid.len() >= self.max_cids && !self.by_cid.contains_key(cid) {
            // Another connection first: this one is the reason for the insert.
            if let Some(position) = self.insertion_order.iter().position(|queued| *queued != id)
                && let Some(victim) = self.insertion_order.remove(position)
            {
                self.drop_dequeued_connection(victim);
                continue;
            }
            // Nothing else left to give, so this connection gives up its own
            // oldest id rather than the cap being exceeded.
            if !self.drop_oldest_cid(id) {
                break;
            }
        }

        if self.by_cid.len() >= self.max_cids && !self.by_cid.contains_key(cid) {
            return;
        }

        let holders = self.by_cid.entry(cid.to_vec()).or_default();
        if !holders.contains(&id) {
            holders.push(id);
        }
    }

    /// Drops `id`'s claim on `cid`, and the entry once nobody holds it.
    fn release_cid(&mut self, cid: &[u8], id: QuicConnectionId) {
        let Some(holders) = self.by_cid.get_mut(cid) else {
            return;
        };
        holders.retain(|held| *held != id);
        if holders.is_empty() {
            self.by_cid.remove(cid);
        }
    }

    /// Drops the lowest-numbered id `id` still holds, in either pool. Returns
    /// whether there was one.
    fn drop_oldest_cid(&mut self, id: QuicConnectionId) -> bool {
        let Some(connection) = self.connections.get_mut(&id) else {
            return false;
        };
        let oldest = connection
            .issued_cids
            .iter()
            .enumerate()
            .filter_map(|(pool, ids)| ids.ids.keys().next().map(|sequence| (*sequence, pool)))
            .min();
        let Some((sequence, pool)) = oldest else {
            return false;
        };
        let Some(stale) = connection.issued_cids[pool].ids.remove(&sequence) else {
            return false;
        };
        self.release_cid(&stale, id);
        true
    }

    fn evict_until_room(&mut self) {
        while self.connections.len() >= self.max_flows {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.connections.clear();
                self.by_tuple.clear();
                self.by_cid.clear();
                break;
            };
            self.drop_dequeued_connection(oldest);
        }
    }

    fn drop_connection(&mut self, id: QuicConnectionId) {
        self.forget_connection(id);
        self.insertion_order.retain(|queued| queued != &id);
    }

    /// Drops a connection whose id the caller has already dequeued.
    fn drop_dequeued_connection(&mut self, id: QuicConnectionId) {
        self.forget_connection(id);
    }

    fn forget_connection(&mut self, id: QuicConnectionId) {
        let Some(connection) = self.connections.remove(&id) else {
            return;
        };

        for key in &connection.tuples {
            if self.by_tuple.get(key) == Some(&id) {
                self.by_tuple.remove(key);
            }
        }
        // Cloned, because releasing borrows the index while `connection` is
        // still holding the ids being released.
        let held: Vec<Vec<u8>> = connection.indexed_cids().cloned().collect();
        for cid in held {
            self.release_cid(&cid, id);
        }
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
    fn a_zero_length_scid_is_still_tracked_by_its_addresses() {
        let mut tracker = QuicConnectionTracker::new();
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        tracker.observe_long_header(client, 50_000, server, 443, &[]);

        let (id, direction) = tracker
            .connection_and_direction(client, 50_000, server, 443, &[])
            .expect("the connection is addressable by its tuple");
        assert_eq!(direction, QuicDirection::InitiatorToResponder);
        assert_eq!(
            tracker.tuples_for_connection(id).len(),
            1,
            "the address pair it was seen on"
        );

        // Nothing was indexed by ID, because there was no ID to index.
        assert!(tracker.connection_id_for_dcid(&[]).is_none());
        assert_eq!(tracker.stats().active_connections, 1);
    }

    #[test]
    fn two_connections_sharing_a_connection_id_stay_apart() {
        let mut tracker = QuicConnectionTracker::new();
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let c = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let d = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

        tracker.observe_long_header(a, 1_000, b, 443, b"abcdefgh");
        tracker.observe_long_header(c, 2_000, d, 443, b"abcdefgh");

        assert_eq!(
            tracker.stats().active_connections,
            2,
            "two endpoint pairs sharing a CID are two connections"
        );
    }

    /// The global cap has to hold even when there is nothing to evict to make
    /// room. Inserting anyway let the index grow without limit.
    #[test]
    fn the_connection_id_cap_holds_when_nothing_can_be_reclaimed() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut tracker = QuicConnectionTracker::new()
            .with_max_cids(1)
            .with_max_cids_per_pool(0);

        tracker.observe_long_header(a, 5_000, b, 443, b"initial0");
        let id = tracker
            .connection_and_direction(a, 5_000, b, 443, b"initial0")
            .map(|(id, _)| id)
            .expect("the connection");

        for n in 1u32..8 {
            tracker.observe_new_connection_id(
                id,
                Endpoint::new(a, 5_000),
                u64::from(n),
                &n.to_be_bytes(),
                0,
            );
        }

        assert!(
            tracker.stats().active_cids <= 1,
            "the cap is one, got {}",
            tracker.stats().active_cids
        );
    }

    #[test]
    fn a_connection_id_its_own_pool_refused_is_not_indexed() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut tracker = QuicConnectionTracker::new().with_max_cids_per_pool(1);

        tracker.observe_long_header(a, 5_000, b, 443, b"initial0");
        let id = tracker
            .connection_id_for_dcid(b"initial0")
            .expect("the connection");
        let issuer = Endpoint::new(b, 443);

        // Fills the pool at sequence 5, then offers a lower sequence, which the
        // pool has no room to keep.
        assert!(tracker.observe_new_connection_id(id, issuer, 5, b"highseq0", 0));
        assert!(
            !tracker.observe_new_connection_id(id, issuer, 1, b"lowseq00", 0),
            "the pool kept the higher sequence, so this one was not recorded"
        );
        assert!(
            tracker.connection_id_for_dcid(b"lowseq00").is_none(),
            "an id no pool holds must not resolve to anything"
        );

        // And dropping the connection leaves nothing behind.
        tracker.remove_flow(a, 5_000, b, 443);
        assert!(tracker.connection_id_for_dcid(b"highseq0").is_none());
        assert_eq!(tracker.stats().active_cids, 0);
    }

    #[test]
    fn colliding_connection_ids_keep_both_connections_reachable() {
        let a_client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let a_server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let b_client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b_server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let shared = b"01020304";

        let mut tracker = QuicConnectionTracker::new();
        tracker.observe_long_header(a_server, 443, a_client, 50_000, shared);
        tracker.observe_long_header(b_server, 443, b_client, 60_000, shared);

        assert_eq!(
            tracker.stats().active_connections,
            2,
            "two endpoint pairs are two connections"
        );

        // Each must still be findable from the tuple it opened on.
        let a = tracker
            .connection_and_direction(a_server, 443, a_client, 50_000, shared)
            .map(|(id, _)| id)
            .expect("connection A");
        let b = tracker
            .connection_and_direction(b_server, 443, b_client, 60_000, shared)
            .map(|(id, _)| id)
            .expect("connection B");
        assert_ne!(a, b);

        // A migrates: its client appears from a new address, still using the
        // shared id. It must be followed to A, not to B and not to nothing.
        let a_moved = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77));
        tracker.observe_short_header(a_moved, 51_000, a_server, 443, shared);
        assert_eq!(
            tracker
                .connection_and_direction(a_moved, 51_000, a_server, 443, shared)
                .map(|(id, _)| id),
            Some(a),
            "A's move must land on A"
        );

        // And B is untouched by it.
        assert_eq!(
            tracker
                .connection_and_direction(b_server, 443, b_client, 60_000, shared)
                .map(|(id, _)| id),
            Some(b),
            "B still answers on its own addresses"
        );
    }

    #[test]
    fn dropping_one_holder_of_a_shared_id_leaves_the_other() {
        let a_client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let a_server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let b_client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b_server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let shared = b"01020304";

        for drop_first in [true, false] {
            let mut tracker = QuicConnectionTracker::new();
            tracker.observe_long_header(a_server, 443, a_client, 50_000, shared);
            tracker.observe_long_header(b_server, 443, b_client, 60_000, shared);

            assert_eq!(tracker.connections_for_dcid(shared).len(), 2);

            let (gone, kept) = if drop_first {
                (
                    (a_server, 443, a_client, 50_000),
                    (b_server, 443, b_client, 60_000),
                )
            } else {
                (
                    (b_server, 443, b_client, 60_000),
                    (a_server, 443, a_client, 50_000),
                )
            };
            let survivor = tracker
                .connection_and_direction(kept.0, kept.1, kept.2, kept.3, shared)
                .map(|(id, _)| id)
                .expect("the survivor");

            assert!(tracker.remove_flow(gone.0, gone.1, gone.2, gone.3));

            assert_eq!(
                tracker.connections_for_dcid(shared),
                [survivor],
                "only the dropped connection's claim goes"
            );
            assert_eq!(
                tracker
                    .connection_and_direction(kept.0, kept.1, kept.2, kept.3, shared)
                    .map(|(id, _)| id),
                Some(survivor),
                "the survivor still answers on its own addresses"
            );
        }
    }

    /// With the collision present, either connection may move and each move
    /// lands on the connection that made it.
    #[test]
    fn either_holder_of_a_shared_id_can_migrate() {
        let a_client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let a_server = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let b_client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let b_server = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let shared = b"01020304";

        let mut tracker = QuicConnectionTracker::new();
        tracker.observe_long_header(a_server, 443, a_client, 50_000, shared);
        tracker.observe_long_header(b_server, 443, b_client, 60_000, shared);
        let a = tracker
            .connection_and_direction(a_server, 443, a_client, 50_000, shared)
            .map(|(id, _)| id)
            .expect("A");
        let b = tracker
            .connection_and_direction(b_server, 443, b_client, 60_000, shared)
            .map(|(id, _)| id)
            .expect("B");

        // Each client moves, keeping its own server still.
        let a_moved = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77));
        let b_moved = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
        tracker.observe_short_header(a_moved, 51_000, a_server, 443, shared);
        tracker.observe_short_header(b_moved, 61_000, b_server, 443, shared);

        assert_eq!(
            tracker
                .connection_and_direction(a_moved, 51_000, a_server, 443, shared)
                .map(|(id, _)| id),
            Some(a)
        );
        assert_eq!(
            tracker
                .connection_and_direction(b_moved, 61_000, b_server, 443, shared)
                .map(|(id, _)| id),
            Some(b)
        );
        assert_eq!(
            tracker.stats().active_connections,
            2,
            "still two connections after both moved"
        );
    }

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

    /// The server in `opened`, which is the endpoint that issued [9,9,9,9].
    fn server_endpoint() -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443)
    }

    /// The client in `opened`.
    fn client_endpoint() -> Endpoint {
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5_000)
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

        assert!(tracker.observe_new_connection_id(id, server_endpoint(), 1, &[0xaa; 8], 0));
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
        tracker.observe_new_connection_id(id, server_endpoint(), 1, &[0xaa; 8], 0);

        assert!(tracker.observe_retire_connection_id(id, server_endpoint(), 1));
        assert!(tracker.connection_id_for_dcid(&[0xaa; 8]).is_none());
        assert_eq!(
            tracker.stats().active_connections,
            1,
            "retiring one identifier does not end the connection"
        );
        assert!(
            !tracker.observe_retire_connection_id(id, server_endpoint(), 1),
            "retiring it twice reports nothing to retire"
        );
    }

    /// RFC 9000 sec 19.15: the frame can announce and retire in one step.
    #[test]
    fn retire_prior_to_drops_the_ids_it_names() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);
        tracker.observe_new_connection_id(id, server_endpoint(), 1, &[0xaa; 8], 0);
        tracker.observe_new_connection_id(id, server_endpoint(), 2, &[0xbb; 8], 0);

        tracker.observe_new_connection_id(id, server_endpoint(), 3, &[0xcc; 8], 2);
        assert!(tracker.connection_id_for_dcid(&[0xaa; 8]).is_none());
        assert_eq!(tracker.connection_id_for_dcid(&[0xbb; 8]), Some(id));
        assert_eq!(tracker.connection_id_for_dcid(&[0xcc; 8]), Some(id));
        assert_eq!(
            tracker.issued_connection_ids(id, server_endpoint()),
            vec![(2, &[0xbb; 8][..]), (3, &[0xcc; 8][..])]
        );
    }

    #[test]
    fn a_connection_id_that_breaks_the_length_rule_is_refused() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);

        assert!(!tracker.observe_new_connection_id(id, server_endpoint(), 1, &[], 0));
        assert!(!tracker.observe_new_connection_id(id, server_endpoint(), 2, &[0xdd; 21], 0));
        assert_eq!(
            tracker.issued_connection_ids(id, server_endpoint()),
            vec![(0, &[9, 9, 9, 9][..])],
            "only the initial scid, which is sequence 0"
        );
    }

    /// Re-announcing a sequence number is a protocol violation, but a capture
    /// has to hold some answer. The newer bytes win and the older stop
    /// resolving, so one sequence number never names two live ids.
    #[test]
    fn re_announcing_a_sequence_number_replaces_the_id() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);
        tracker.observe_new_connection_id(id, server_endpoint(), 1, &[0xaa; 8], 0);

        tracker.observe_new_connection_id(id, server_endpoint(), 1, &[0xee; 8], 0);
        assert!(tracker.connection_id_for_dcid(&[0xaa; 8]).is_none());
        assert_eq!(tracker.connection_id_for_dcid(&[0xee; 8]), Some(id));
        assert_eq!(
            tracker.issued_connection_ids(id, server_endpoint()).len(),
            2,
            "the initial scid at sequence 0, plus the re-announced one"
        );
    }

    #[test]
    fn a_connection_id_announced_for_no_connection_is_refused() {
        let mut tracker = QuicConnectionTracker::new();
        assert!(!tracker.observe_new_connection_id(
            QuicConnectionId(99),
            server_endpoint(),
            1,
            &[0xaa; 8],
            0
        ));
    }

    /// An announced id must be usable to follow a move, which is the whole
    /// point of the peer issuing spares.
    #[test]
    fn a_connection_moves_onto_an_announced_id() {
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let moved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);
        tracker.observe_new_connection_id(id, server_endpoint(), 1, &[0xaa; 8], 0);

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
        tracker.observe_new_connection_id(id, server_endpoint(), 1, &[0xaa; 8], 0);

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

    /// RFC 9000 sec 5.1.1: each endpoint numbers its own connection IDs from
    /// zero, so both sides hold a sequence 1. One shared pool let the second
    /// one overwrite the first.
    #[test]
    fn each_endpoint_has_its_own_sequence_space() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);

        assert!(tracker.observe_new_connection_id(id, client_endpoint(), 1, &[0xc1; 8], 0));
        assert!(tracker.observe_new_connection_id(id, server_endpoint(), 1, &[0x51; 8], 0));

        assert_eq!(
            tracker.connection_id_for_dcid(&[0xc1; 8]),
            Some(id),
            "the client's sequence 1 was not replaced by the server's"
        );
        assert_eq!(tracker.connection_id_for_dcid(&[0x51; 8]), Some(id));

        // Retiring one side's sequence 1 leaves the other's alone.
        assert!(tracker.observe_retire_connection_id(id, server_endpoint(), 1));
        assert!(tracker.connection_id_for_dcid(&[0x51; 8]).is_none());
        assert_eq!(tracker.connection_id_for_dcid(&[0xc1; 8]), Some(id));
    }

    /// RFC 9000 sec 19.15: the initial connection ID is its issuer's sequence
    /// 0, so the lifecycle has to be able to retire it.
    #[test]
    fn the_initial_connection_id_is_sequence_zero() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);

        assert_eq!(
            tracker.issued_connection_ids(id, server_endpoint()),
            vec![(0, &[9, 9, 9, 9][..])]
        );
        assert!(tracker.observe_retire_connection_id(id, server_endpoint(), 0));
        assert!(
            tracker.connection_id_for_dcid(&[9, 9, 9, 9]).is_none(),
            "the initial id retires through the lifecycle like any other"
        );
    }

    /// RFC 9000 sec 19.15: a Retire Prior To above the frame's own sequence
    /// number is a FRAME_ENCODING_ERROR.
    #[test]
    fn a_retire_prior_to_above_the_sequence_number_is_refused() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);

        assert!(!tracker.observe_new_connection_id(id, server_endpoint(), 3, &[0xaa; 8], 7));
        assert!(tracker.connection_id_for_dcid(&[0xaa; 8]).is_none());
    }

    /// RFC 9000 sec 19.15: a smaller Retire Prior To later has no effect, and
    /// an id below a threshold already set stays retired even if it arrives
    /// afterwards.
    #[test]
    fn a_retirement_threshold_is_not_walked_back() {
        let mut tracker = QuicConnectionTracker::new();
        let id = opened(&mut tracker);

        tracker.observe_new_connection_id(id, server_endpoint(), 5, &[0x55; 8], 5);
        assert!(tracker.connection_id_for_dcid(&[9, 9, 9, 9]).is_none());

        // A later frame lowering the threshold changes nothing.
        tracker.observe_new_connection_id(id, server_endpoint(), 6, &[0x66; 8], 2);
        assert_eq!(
            tracker.issued_connection_ids(id, server_endpoint()),
            vec![(5, &[0x55; 8][..]), (6, &[0x66; 8][..])]
        );

        // And an id below the threshold does not come back.
        assert!(
            !tracker.observe_new_connection_id(id, server_endpoint(), 3, &[0x33; 8], 0),
            "sequence 3 is below the threshold of 5"
        );
        assert!(tracker.connection_id_for_dcid(&[0x33; 8]).is_none());
    }

    /// A migrating connection binds another address without adding a
    /// connection, so the connection cap alone leaves the tuple index
    /// unbounded. One peer moving repeatedly must not grow it without limit.
    #[test]
    fn a_moving_connection_cannot_grow_the_tuple_index_without_bound() {
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let cid = [9, 9, 9, 9];
        let mut tracker = QuicConnectionTracker::new().with_max_tuples(64, 4);
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tracker.observe_long_header(server, 443, client, 5_000, &cid);
        let id = tracker.connection_id_for_dcid(&cid).expect("opened");

        for port in 0..500u16 {
            tracker.observe_short_header(client, 6_000 + port, server, 443, &cid);
        }

        let stats = tracker.stats();
        assert!(
            stats.active_tuples <= 64,
            "{} address pairs held past the cap",
            stats.active_tuples
        );
        assert!(
            tracker.tuples_for_connection(id).len() <= 4,
            "one connection held {} addresses",
            tracker.tuples_for_connection(id).len()
        );
    }

    /// The same for connection IDs: a peer that keeps issuing them must not
    /// grow the id index past its cap.
    #[test]
    fn announced_connection_ids_stay_inside_their_cap() {
        let mut tracker = QuicConnectionTracker::new()
            .with_max_cids(8)
            .with_max_cids_per_pool(4);
        let id = opened(&mut tracker);

        for sequence in 1..200u64 {
            let cid = sequence.to_be_bytes();
            tracker.observe_new_connection_id(id, server_endpoint(), sequence, &cid, 0);
        }

        assert!(
            tracker.stats().active_cids <= 8,
            "{} ids held past the cap",
            tracker.stats().active_cids
        );
    }

    /// A capture joined mid-connection can anchor direction on the wrong end.
    /// If the anchored end then moves, the anchor follows it to its new
    /// address rather than matching neither and collapsing both directions.
    #[test]
    fn the_direction_anchor_follows_the_end_it_named() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let moved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let server_cid = [9, 9, 9, 9];
        let mut tracker = QuicConnectionTracker::new();

        // The server's packet is seen first, so the anchor lands on the client.
        tracker.observe_long_header(server, 443, client, 5_000, &server_cid);
        let id = tracker.connection_id_for_dcid(&server_cid).expect("opened");

        // The client then moves, and the anchor with it.
        tracker.observe_short_header(moved, 53_000, server, 443, &server_cid);

        let to_server = tracker
            .direction_for(id, Endpoint::new(moved, 53_000), Endpoint::new(server, 443))
            .expect("a direction");
        let to_client = tracker
            .direction_for(id, Endpoint::new(server, 443), Endpoint::new(moved, 53_000))
            .expect("a direction");
        assert_ne!(
            to_server, to_client,
            "both ways must not collapse onto one direction"
        );
    }

    /// When one connection's own pool is allowed more ids than the tracker
    /// holds in total, it has to give up its oldest rather than push the total
    /// past the cap. There is no other connection to evict.
    #[test]
    fn one_connection_cannot_push_the_id_total_past_the_cap() {
        let mut tracker = QuicConnectionTracker::new()
            .with_max_cids(4)
            .with_max_cids_per_pool(16);
        let id = opened(&mut tracker);

        for sequence in 1..12u64 {
            let cid = sequence.to_be_bytes();
            tracker.observe_new_connection_id(id, server_endpoint(), sequence, &cid, 0);
            assert!(
                tracker.stats().active_cids <= 4,
                "{} ids held past the cap after sequence {sequence}",
                tracker.stats().active_cids
            );
        }
    }

    /// A limit of zero has to mean zero. A cap that silently keeps one entry
    /// is worse than no cap, because a caller that set it cannot tell.
    #[test]
    fn a_zero_limit_retains_nothing() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let mut no_tuples = QuicConnectionTracker::new().with_max_tuples(0, 0);
        no_tuples.observe_long_header(client, 5_000, server, 443, &[1, 1, 1, 1]);
        assert_eq!(no_tuples.stats().active_tuples, 0);
        assert_eq!(no_tuples.stats().active_connections, 0);

        let mut no_cids = QuicConnectionTracker::new().with_max_cids(0);
        no_cids.observe_long_header(client, 5_000, server, 443, &[2, 2, 2, 2]);
        assert_eq!(no_cids.stats().active_cids, 0);

        let mut no_pool = QuicConnectionTracker::new().with_max_cids_per_pool(0);
        no_pool.observe_long_header(client, 5_000, server, 443, &[3, 3, 3, 3]);
        if let Some(id) = no_pool.connection_id_for_dcid(&[3, 3, 3, 3]) {
            assert!(
                no_pool
                    .issued_connection_ids(id, Endpoint::new(client, 5_000))
                    .is_empty()
            );
        }

        let mut no_flows = QuicConnectionTracker::new().with_max_flows(0);
        no_flows.observe_long_header(client, 5_000, server, 443, &[4, 4, 4, 4]);
        assert_eq!(no_flows.stats().active_connections, 0);
    }

    /// The server can move too, not just the client. Direction has to stay
    /// meaningful either way, or state keyed on it swaps sides mid-connection.
    #[test]
    fn direction_survives_the_responder_changing_address() {
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let server_moved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let client_cid = [1, 1, 1, 1];
        let mut tracker = QuicConnectionTracker::new();

        // The client's Initial first, so the responder anchor is the server.
        tracker.observe_long_header(client, 5_000, server, 443, &client_cid);
        let (id, before) = tracker
            .connection_and_direction(client, 5_000, server, 443, &client_cid)
            .expect("the connection is known");
        assert_eq!(before, QuicDirection::InitiatorToResponder);

        // Now the responder moves. The client stayed put.
        tracker.observe_short_header(server_moved, 443, client, 5_000, &client_cid);

        let to_server = tracker
            .direction_for(
                id,
                Endpoint::new(client, 5_000),
                Endpoint::new(server_moved, 443),
            )
            .expect("a direction");
        let to_client = tracker
            .direction_for(
                id,
                Endpoint::new(server_moved, 443),
                Endpoint::new(client, 5_000),
            )
            .expect("a direction");

        assert_ne!(
            to_server, to_client,
            "the two ways must stay distinguishable after the responder moves"
        );
        assert_eq!(
            to_server, before,
            "and the way to the responder is still the way to the responder"
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
