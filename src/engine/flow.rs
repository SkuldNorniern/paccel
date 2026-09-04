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

    /// Same address, different ports: the port decides the order.
    #[test]
    fn ports_break_the_tie() {
        let (flow, direction) = BiFlow::normalize(ip(1), 9_000, ip(1), 80);

        assert_eq!(flow.first.port, 80);
        assert_eq!(flow.second.port, 9_000);
        assert_eq!(direction, Direction::SecondToFirst);
    }
}
