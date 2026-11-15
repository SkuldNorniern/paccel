//! The byte counters that enforce the reassemblers' caps.
//!
//! `total_bytes` and `total_buffered_bytes` are what stop a capture filling
//! memory. Drift upward and the cap eventually refuses traffic that should fit;
//! drift downward and it stops bounding anything. Either way nothing fails
//! loudly, so the counter has to be checked against what is actually held.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use paccel::engine::{IpFragmentReassembler, QuicStreamReassembler, TcpStreamReassembler};
use paccel::layer::network::ipv4::Ipv4Header;
use proptest::prelude::*;

fn ipv4_header(id: u16, fragment_offset: u16, more: bool) -> Ipv4Header {
    Ipv4Header {
        version: 4,
        ihl: 5,
        dscp: 0,
        ecn: 0,
        total_length: 20,
        identification: id,
        flags: u8::from(more),
        fragment_offset,
        ttl: 64,
        protocol: 17,
        checksum: 0,
        source: Ipv4Addr::new(10, 0, 0, 1),
        destination: Ipv4Addr::new(10, 0, 0, 2),
        options: None,
        options_truncated: false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Whatever sequence of fragments arrives - overlapping, mismatched,
    /// abandoned, evicted - expiring everything has to bring the counter back
    /// to zero, and the reassembler has to still work afterwards.
    #[test]
    fn fragment_bytes_return_to_zero(
        ops in prop::collection::vec(
            (0u16..4, 0u16..6, any::<bool>(), 0usize..3, any::<bool>()),
            0..40,
        ),
    ) {
        let mut reassembler = IpFragmentReassembler::new();
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        for (id, offset, more, units, v6) in ops {
            let payload = vec![0xab; units * 8];
            if v6 {
                reassembler.offer_ipv6_at(
                    src, dst, u32::from(id), offset, more, 17, &payload, 100,
                );
            } else {
                reassembler.offer_ipv4_at(&ipv4_header(id, offset, more), &payload, 100);
            }
        }

        reassembler.expire_before(u64::MAX);
        prop_assert_eq!(
            reassembler.total_bytes(),
            0,
            "expiring every datagram has to free every byte"
        );

        // A counter left high would have eaten into the cap; prove it did not.
        let header = ipv4_header(900, 0, true);
        prop_assert_eq!(reassembler.offer_ipv4_at(&header, b"abcdefgh", 200), None);
        let tail = ipv4_header(900, 1, false);
        prop_assert_eq!(
            reassembler.offer_ipv4_at(&tail, b"ijkl", 200),
            Some(b"abcdefghijkl".to_vec()),
            "the reassembler still works once the counter is back to zero"
        );
    }

    /// The same for TCP: every flow aged out means every buffered byte freed.
    #[test]
    fn tcp_buffered_bytes_return_to_zero(
        ops in prop::collection::vec(
            (0u16..4, 0u32..64, 0usize..6, any::<bool>(), any::<bool>()),
            0..40,
        ),
    ) {
        let mut reassembler = TcpStreamReassembler::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        for (port, seq, len, fin, rst) in ops {
            let payload = vec![0xcd; len];
            reassembler.offer_detailed_at(
                src, 1000 + port, dst, 80, seq, false, fin, rst, &payload, 100,
            );
        }

        reassembler.expire_before(u64::MAX);
        let stats = reassembler.stats();
        prop_assert_eq!(stats.active_flows, 0, "every flow aged out");
        prop_assert_eq!(stats.buffered_bytes, 0, "every buffered byte freed");
    }

    /// And for QUIC streams.
    #[test]
    fn quic_buffered_bytes_return_to_zero(
        ops in prop::collection::vec((0u64..4, 0u64..64, 0usize..6, any::<bool>()), 0..40),
    ) {
        let mut reassembler = QuicStreamReassembler::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        for (stream, offset, len, fin) in ops {
            let payload = vec![0xef; len];
            reassembler.offer_detailed_at(
                src, 1000, dst, 443, stream, offset, fin, &payload, 100,
            );
        }

        reassembler.expire_before(u64::MAX);
        let out = reassembler.offer_detailed_at(src, 1000, dst, 443, 99, 0, true, b"fresh", 200);
        prop_assert_eq!(out.data, b"fresh".to_vec());
    }
}
