//! Endpoints and the bidirectional key the stateful engines share.
//!
//! TCP reassembly, session tracking and QUIC each had their own copy of this.
//! One copy means they cannot disagree about which side is `first`.

use std::net::IpAddr;

/// One end of a conversation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

impl Endpoint {
    #[must_use]
    pub fn new(address: IpAddr, port: u16) -> Self {
        Endpoint { address, port }
    }
}

/// Which way a packet travelled through a [`BiFlow`].
///
/// `First` is the endpoint that sorts lower, so the same conversation gets the
/// same direction whichever side is seen first.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    FirstToSecond,
    SecondToFirst,
}

impl Direction {
    /// Index into a two-element per-direction array.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Direction::FirstToSecond => 0,
            Direction::SecondToFirst => 1,
        }
    }
}

/// Both ends of a conversation, ordered so either direction produces the same
/// key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BiFlow {
    pub first: Endpoint,
    pub second: Endpoint,
}

impl BiFlow {
    /// Whether `endpoint` is one of this pair.
    #[must_use]
    pub fn holds(&self, endpoint: Endpoint) -> bool {
        self.first == endpoint || self.second == endpoint
    }

    /// The endpoint this pair and `other` have in common, if exactly one.
    ///
    /// When a connection moves, one end stays put. That end is the one both
    /// address pairs share.
    #[must_use]
    pub fn shared_endpoint(&self, other: Self) -> Option<Endpoint> {
        let mut shared = None;
        for endpoint in [self.first, self.second] {
            if other.holds(endpoint) {
                if shared.is_some() {
                    // Both ends match, so nothing moved and there is nothing
                    // to learn from this pair.
                    return None;
                }
                shared = Some(endpoint);
            }
        }
        shared
    }

    /// Order the endpoints and say which way this packet went.
    #[must_use]
    pub fn normalize(
        source: IpAddr,
        source_port: u16,
        destination: IpAddr,
        destination_port: u16,
    ) -> (Self, Direction) {
        let source = Endpoint::new(source, source_port);
        let destination = Endpoint::new(destination, destination_port);

        if source <= destination {
            (
                BiFlow {
                    first: source,
                    second: destination,
                },
                Direction::FirstToSecond,
            )
        } else {
            (
                BiFlow {
                    first: destination,
                    second: source,
                },
                Direction::SecondToFirst,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn both_directions_produce_one_key() {
        let (forward, forward_direction) = BiFlow::normalize(ip(1), 5_000, ip(2), 443);
        let (reverse, reverse_direction) = BiFlow::normalize(ip(2), 443, ip(1), 5_000);

        assert_eq!(forward, reverse, "one conversation, one key");
        assert_ne!(forward_direction, reverse_direction);
        assert_ne!(forward_direction.index(), reverse_direction.index());
    }

    #[test]
    fn an_undated_entry_is_never_expired() {
        let undated = LastSeen::default();
        assert!(!undated.is_before(u64::MAX));
        assert_eq!(undated.get(), None);
    }

    #[test]
    fn last_seen_moves_forward_only() {
        let mut seen = LastSeen::default();
        seen.observe(1_000);
        seen.observe(500);
        assert_eq!(
            seen.get(),
            Some(1_000),
            "a late packet does not age it early"
        );
        assert!(seen.is_before(1_001));
        assert!(!seen.is_before(1_000));
    }

    /// Same address, different ports: the port decides the order.
    #[test]
    fn ports_break_the_tie() {
        let (flow, direction) = BiFlow::normalize(ip(1), 9_000, ip(1), 80);

        assert_eq!(flow.first.port, 80);
        assert_eq!(flow.second.port, 9_000);
        assert_eq!(direction, Direction::SecondToFirst);
    }
}

/// Capture time in nanoseconds, supplied by the caller.
///
/// Paccel never reads a clock, so a live capture, a pcap replay and a test all
/// age state the same way.
pub type Timestamp = u64;

/// When an entry was last touched, for callers that age their state.
///
/// `None` means undated, and [`Self::is_before`] never expires those, so
/// mixing the timed and untimed methods is safe.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LastSeen(Option<Timestamp>);

impl LastSeen {
    /// Move forward to `now`, never backwards. Out-of-order delivery would
    /// otherwise age an entry out early.
    pub fn observe(&mut self, now: Timestamp) {
        self.0 = Some(self.0.map_or(now, |seen| seen.max(now)));
    }

    /// Whether this entry was last touched before `cutoff`. Undated entries
    /// are never before anything.
    #[must_use]
    pub fn is_before(self, cutoff: Timestamp) -> bool {
        self.0.is_some_and(|seen| seen < cutoff)
    }

    #[must_use]
    pub fn get(self) -> Option<Timestamp> {
        self.0
    }
}

/// What a reassembler did with one offered segment or frame.
///
/// `offer` returns only the bytes that became contiguous, so an empty result
/// covers buffered, duplicate, refused overlap and limit alike. This tells
/// them apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReassemblyEvent {
    /// Bytes became contiguous and are in the output.
    Data,
    /// Held behind a gap, waiting for what comes before it.
    Buffered,
    /// Already seen. Nothing changed.
    Duplicate,
    /// Contradicted bytes already held. The first copy stands.
    Conflict,
    /// A reset tore the flow down.
    Reset,
    /// The sender finished this direction.
    Fin,
    /// The stream is closed; later data is ignored.
    Closed,
    /// Too far past what is expected to be worth holding.
    GapLimit,
    /// A limit refused it: no room for the flow, or for the bytes.
    ResourceLimit,
    /// A QUIC frame disagreed with the stream's already-declared final size,
    /// which RFC 9000 calls a FINAL_SIZE_ERROR.
    FinalSizeError,
    /// Nothing to do: no payload, or the segment could not be placed.
    Ignored,
}

/// Bytes that became contiguous, and what happened to the offered data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReassemblyOutput {
    pub data: Vec<u8>,
    pub event: ReassemblyEvent,
}

impl ReassemblyOutput {
    pub(crate) fn new(data: Vec<u8>, event: ReassemblyEvent) -> Self {
        ReassemblyOutput { data, event }
    }

    pub(crate) fn empty(event: ReassemblyEvent) -> Self {
        ReassemblyOutput {
            data: Vec::new(),
            event,
        }
    }
}
