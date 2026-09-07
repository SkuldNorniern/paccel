//! Property tests over sequences of operations, not single inputs.
//!
//! A reassembler that parses every individual segment correctly can still be
//! wrong about the stream those segments build, and only a walk over many
//! orderings catches that. Each test here drives a random sequence and then
//! checks an invariant that has to hold whatever the sequence was.

#![allow(clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};

use paccel::engine::{
    Endpoint, IpFragmentReassembler, QuicConnectionTracker, QuicStreamReassembler, ReassemblyEvent,
    TcpStreamReassembler,
};
use proptest::prelude::*;

const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

/// The stream a test reassembles, so an emitted byte can be checked against
/// what was actually sent at that position.
fn truth(length: usize) -> Vec<u8> {
    // 251 is prime, so the pattern does not line up with any segment size a
    // test picks and a misplaced byte shows as a mismatch rather than luck.
    (0..length)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

/// Cuts `stream` into consecutive segments of the given sizes.
fn segments(stream: &[u8], sizes: &[usize]) -> Vec<(usize, Vec<u8>)> {
    let mut cuts = Vec::new();
    let mut offset = 0usize;
    for size in sizes {
        if offset >= stream.len() {
            break;
        }
        let end = (offset + size.max(&1)).min(stream.len());
        cuts.push((offset, stream[offset..end].to_vec()));
        offset = end;
    }
    if offset < stream.len() {
        cuts.push((offset, stream[offset..].to_vec()));
    }
    cuts
}

/// Deterministically permutes by a seed, so a failure shrinks to a seed.
fn permuted<T>(mut items: Vec<T>, seed: u64) -> Vec<T> {
    let mut state = seed | 1;
    let length = items.len();
    for index in (1..length).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        items.swap(index, (state >> 33) as usize % (index + 1));
    }
    items
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// However the segments arrive, the bytes handed back are the bytes that
    /// were sent, in order, with nothing invented and nothing reordered.
    #[test]
    fn tcp_reassembly_rebuilds_the_stream_whatever_the_arrival_order(
        length in 1usize..1024,
        sizes in prop::collection::vec(1usize..64, 1..24),
        seed in any::<u64>(),
    ) {
        let stream = truth(length);
        let mut reassembler = TcpStreamReassembler::new();
        reassembler.offer(SRC, 40_000, DST, 443, 0, true, false, false, &[]);

        let mut emitted = Vec::new();
        for (offset, payload) in permuted(segments(&stream, &sizes), seed) {
            let sequence = 1u32.wrapping_add(u32::try_from(offset).unwrap_or(u32::MAX));
            emitted.extend(reassembler.offer(
                SRC, 40_000, DST, 443, sequence, false, false, false, &payload,
            ));
        }

        // The segments cover the stream exactly once and it is far below both
        // the buffer and gap limits, so every byte has to come back out.
        // Asserting only a prefix would be satisfied by a reassembler that
        // dropped everything.
        prop_assert_eq!(
            &emitted[..],
            &stream[..],
            "the stream did not come back whole"
        );
    }

    /// Offering every segment a second time must not add a byte: the stream
    /// has already moved past them.
    #[test]
    fn tcp_reassembly_ignores_a_wholesale_retransmission(
        length in 1usize..512,
        sizes in prop::collection::vec(1usize..48, 1..16),
        seed in any::<u64>(),
    ) {
        let stream = truth(length);
        let cuts = permuted(segments(&stream, &sizes), seed);
        let mut reassembler = TcpStreamReassembler::new();
        reassembler.offer(SRC, 40_000, DST, 443, 0, true, false, false, &[]);

        let offer_all = |reassembler: &mut TcpStreamReassembler| {
            let mut emitted = Vec::new();
            for (offset, payload) in &cuts {
                let sequence = 1u32.wrapping_add(u32::try_from(*offset).unwrap_or(u32::MAX));
                emitted.extend(reassembler.offer(
                    SRC, 40_000, DST, 443, sequence, false, false, false, payload,
                ));
            }
            emitted
        };

        let first = offer_all(&mut reassembler);
        let second = offer_all(&mut reassembler);
        prop_assert!(
            second.is_empty(),
            "a retransmission of {} bytes emitted {} more",
            first.len(),
            second.len()
        );
    }

    /// RFC 9000 sec 2.2: the data at a given offset never changes. So a QUIC
    /// stream rebuilt from frames in any order is the stream that was sent.
    #[test]
    fn quic_reassembly_rebuilds_the_stream_whatever_the_arrival_order(
        length in 1usize..1024,
        sizes in prop::collection::vec(1usize..64, 1..24),
        seed in any::<u64>(),
    ) {
        let stream = truth(length);
        let mut reassembler = QuicStreamReassembler::new();

        let mut emitted = Vec::new();
        for (offset, payload) in permuted(segments(&stream, &sizes), seed) {
            emitted.extend(reassembler.offer(
                SRC, 40_000, DST, 443, 0, u64::try_from(offset).unwrap_or(u64::MAX), false, &payload,
            ));
        }

        prop_assert_eq!(
            &emitted[..],
            &stream[..],
            "the stream did not come back whole"
        );
    }

    /// Expiring twice at the same cutoff must find nothing the second time,
    /// and expiring at a later cutoff must never resurrect anything.
    #[test]
    fn expiring_a_quic_tracker_is_monotone(
        stamps in prop::collection::vec(1u64..1000, 1..32),
        first_cutoff in 0u64..1000,
        later in 0u64..1000,
    ) {
        let mut tracker = QuicConnectionTracker::new();
        for (index, stamp) in stamps.iter().enumerate() {
            let cid = u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes();
            let port = 40_000u16.wrapping_add(u16::try_from(index).unwrap_or(0));
            tracker.observe_long_header_at(SRC, port, DST, 443, &cid, *stamp);
        }

        let before = tracker.stats().active_connections;
        let expired = tracker.expire_before(first_cutoff);
        prop_assert!(expired <= before);
        prop_assert_eq!(tracker.stats().active_connections, before - expired);

        prop_assert_eq!(
            tracker.expire_before(first_cutoff),
            0,
            "the same cutoff found something to expire twice"
        );

        let after_first = tracker.stats().active_connections;
        let second_cutoff = first_cutoff.saturating_add(later);
        tracker.expire_before(second_cutoff);
        prop_assert!(
            tracker.stats().active_connections <= after_first,
            "a later cutoff brought a connection back"
        );
    }

    /// Every connection id the tracker still holds must resolve to a
    /// connection it still holds. An index outliving its target is how a
    /// lookup starts returning another connection's state.
    #[test]
    fn a_quic_tracker_never_keeps_a_dangling_index(
        stamps in prop::collection::vec(1u64..500, 1..24),
        cutoff in 0u64..500,
        removals in prop::collection::vec(0usize..24, 0..8),
    ) {
        let mut tracker = QuicConnectionTracker::new();
        for (index, stamp) in stamps.iter().enumerate() {
            let cid = u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes();
            let port = 40_000u16.wrapping_add(u16::try_from(index).unwrap_or(0));
            tracker.observe_long_header_at(SRC, port, DST, 443, &cid, *stamp);
        }
        for index in &removals {
            let port = 40_000u16.wrapping_add(u16::try_from(*index).unwrap_or(0));
            tracker.remove_flow(SRC, port, DST, 443);
        }
        tracker.expire_before(cutoff);

        for index in 0..stamps.len() {
            let cid = u32::try_from(index).unwrap_or(u32::MAX).to_be_bytes();
            if let Some(id) = tracker.connection_id_for_dcid(&cid) {
                prop_assert!(
                    !tracker.tuples_for_connection(id).is_empty(),
                    "a connection id resolved to a connection with no addresses"
                );
                prop_assert!(
                    tracker.connection_for_dcid(&cid).is_some(),
                    "an id resolved by one lookup and not the other"
                );
            }
        }

        let stats = tracker.stats();
        prop_assert!(
            stats.active_connections <= stats.active_tuples,
            "{} connections hold only {} addresses between them",
            stats.active_connections,
            stats.active_tuples
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// RFC 9293 sec 3.5: once a direction's FIN is reached its stream is over.
    /// Whatever arrives afterwards, at any sequence, must never come back out.
    #[test]
    fn nothing_is_emitted_after_a_tcp_direction_closes(
        sizes in prop::collection::vec(1usize..48, 1..12),
        offsets in prop::collection::vec(any::<u32>(), 1..12),
        seed in any::<u64>(),
    ) {
        let stream = truth(64);
        let mut reassembler = TcpStreamReassembler::new();
        reassembler.offer(SRC, 40_000, DST, 443, 0, true, false, false, &stream[..0]);
        for (offset, payload) in segments(&stream, &sizes) {
            let sequence = 1u32.wrapping_add(u32::try_from(offset).unwrap_or(u32::MAX));
            reassembler.offer(SRC, 40_000, DST, 443, sequence, false, false, false, &payload);
        }
        // Close the direction at the end of what was sent.
        let fin_sequence = 1u32.wrapping_add(u32::try_from(stream.len()).unwrap_or(u32::MAX));
        reassembler.offer(SRC, 40_000, DST, 443, fin_sequence, false, true, false, &[]);

        for (index, sequence) in permuted(offsets, seed).into_iter().enumerate() {
            let payload = [u8::try_from(index % 251).unwrap_or(0); 8];
            let out =
                reassembler.offer_detailed(SRC, 40_000, DST, 443, sequence, false, false, false, &payload);
            prop_assert!(
                out.data.is_empty(),
                "{} bytes emitted after the fin at sequence {sequence}",
                out.data.len()
            );
            prop_assert_eq!(out.event, ReassemblyEvent::Closed);
        }
    }

    /// Every index the tracker keeps has to stay inside its own bound, per
    /// connection as well as in total. A global cap alone left one connection
    /// able to grow its own pools without limit.
    #[test]
    fn every_quic_index_stays_inside_its_bound(
        operations in prop::collection::vec((0u8..5, 0u8..40, 1u64..500), 1..120),
    ) {
        const MAX_CONNECTIONS: usize = 8;
        const MAX_TUPLES: usize = 16;
        const MAX_TUPLES_PER_CONNECTION: usize = 3;
        const MAX_CIDS: usize = 16;
        const MAX_CIDS_PER_POOL: usize = 3;

        let mut tracker = QuicConnectionTracker::new()
            .with_max_flows(MAX_CONNECTIONS)
            .with_max_tuples(MAX_TUPLES, MAX_TUPLES_PER_CONNECTION)
            .with_max_cids(MAX_CIDS)
            .with_max_cids_per_pool(MAX_CIDS_PER_POOL);
        let mut opened: Vec<(u32, u16)> = Vec::new();

        for (op, which, stamp) in operations {
            let port = 40_000u16.wrapping_add(u16::from(which));
            let cid = u32::from(which).to_be_bytes();
            match op {
                0 => {
                    tracker.observe_long_header_at(SRC, port, DST, 443, &cid, stamp);
                    opened.push((u32::from(which), port));
                }
                1 => {
                    // Bind the first connection to a port derived from `stamp`,
                    // so one connection accumulates address pairs. Deriving the
                    // port from `which` gave each connection one tuple and left
                    // the per-connection bound untested.
                    if let Some((first, _)) = opened.first().copied() {
                        let moved = 50_000u16.wrapping_add(u16::try_from(stamp % 400).unwrap_or(0));
                        tracker.observe_short_header_at(
                            SRC,
                            moved,
                            DST,
                            443,
                            &first.to_be_bytes(),
                            stamp,
                        );
                    }
                }
                2 => {
                    // The sequence and the announced id come from `stamp`, not
                    // from `which`, so one connection accumulates a pool. Tying
                    // them together gave every connection a single id and left
                    // the per-pool bound untested.
                    if let Some((first, _)) = opened.first().copied()
                        && let Some(id) = tracker.connection_id_for_dcid(&first.to_be_bytes())
                    {
                        let announced = stamp.to_be_bytes();
                        tracker.observe_new_connection_id(
                            id,
                            Endpoint::new(DST, 443),
                            stamp,
                            &announced,
                            0,
                        );
                    }
                }
                3 => {
                    if let Some(id) = tracker.connection_id_for_dcid(&cid) {
                        tracker.observe_retire_connection_id(
                            id,
                            Endpoint::new(DST, 443),
                            u64::from(which),
                        );
                    }
                }
                _ => {
                    tracker.expire_before(stamp);
                }
            }

            let stats = tracker.stats();
            prop_assert!(stats.active_connections <= MAX_CONNECTIONS);
            prop_assert!(stats.active_tuples <= MAX_TUPLES);
            prop_assert!(stats.active_cids <= MAX_CIDS);

            // Per-connection, which is what the global bounds cannot see.
            for (value, _) in &opened {
                let cid = value.to_be_bytes();
                if let Some(id) = tracker.connection_id_for_dcid(&cid) {
                    prop_assert!(
                        tracker.tuples_for_connection(id).len() <= MAX_TUPLES_PER_CONNECTION,
                        "one connection held {} addresses",
                        tracker.tuples_for_connection(id).len()
                    );
                    for issuer in [Endpoint::new(SRC, 40_000), Endpoint::new(DST, 443)] {
                        prop_assert!(
                            tracker.issued_connection_ids(id, issuer).len()
                                <= MAX_CIDS_PER_POOL,
                            "one pool held {} ids",
                            tracker.issued_connection_ids(id, issuer).len()
                        );
                    }
                }
            }
        }
    }

    /// A datagram dropped for a malformed fragment must not be resurrected by
    /// what arrives afterwards: the later fragments start a fresh datagram, and
    /// the bytes of the dropped one never reappear in it.
    #[test]
    fn a_dropped_datagram_is_not_resurrected(
        identification in any::<u32>(),
        tail in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        use std::net::Ipv6Addr;
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut reassembler = IpFragmentReassembler::new();

        // A non-final fragment of a length that cannot be placed.
        prop_assert_eq!(
            reassembler.offer_ipv6(src, dst, identification, 0, true, 6, b"1234567"),
            None
        );

        // A fresh, well formed datagram under the same identity.
        prop_assert_eq!(
            reassembler.offer_ipv6(src, dst, identification, 0, true, 6, b"12345678"),
            None
        );
        let completed = reassembler.offer_ipv6(src, dst, identification, 1, false, 6, &tail);
        let Some(bytes) = completed else {
            return Ok(());
        };
        let mut expected = b"12345678".to_vec();
        expected.extend(&tail);
        prop_assert_eq!(
            bytes,
            expected,
            "the dropped fragment's bytes came back in the new datagram"
        );
    }
}
