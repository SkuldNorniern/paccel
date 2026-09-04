//! Endpoints and the bidirectional key the stateful engines share.
//!
//! TCP reassembly, session tracking and QUIC all group the two directions of a
//! conversation under one key, and all three had their own copy of the type and
//! of the normalisation. One copy means they cannot disagree about which side
//! is `first`.

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
/// Paccel never reads a clock. Live capture passes a monotonic reading, a pcap
/// replay passes the packet's own timestamp, and a test passes whatever integer
/// it likes; all three then age state the same way.
pub type Timestamp = u64;

/// When an entry was last touched, for callers that age their state.
///
/// `None` means nothing has been dated: entries fed through the untimed methods
/// are never expired by [`Self::is_before`], so mixing the two is safe rather
/// than quietly dropping everything.
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
