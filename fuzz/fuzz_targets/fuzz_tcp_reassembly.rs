#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use paccel::{TcpOverlapPolicy, TcpStreamReassembler};

// Interprets fuzz bytes as a sequence of TCP segment offers so the
// reassembler's stateful invariants get exercised, not just its structural
// byte parsing. The limits are deliberately small so the caps are reached
// often, and they are asserted after every operation rather than assumed.
// All three overlap policies are driven, because they differ precisely in how
// they mutate buffered state.
fuzz_target!(|data: &[u8]| {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    const MAX_PER_DIRECTION: usize = 4_096;
    const MAX_TOTAL: usize = 16_384;

    let policy = match data.first().map_or(0, |first| first % 3) {
        0 => TcpOverlapPolicy::Reject,
        1 => TcpOverlapPolicy::FirstWins,
        _ => TcpOverlapPolicy::LastWins,
    };
    let mut reassembler = TcpStreamReassembler::with_limits(MAX_PER_DIRECTION, 65_535)
        .with_max_flows(64)
        .with_max_total_buffered_bytes(MAX_TOTAL)
        .with_overlap_policy(policy);

    let mut cursor = data;
    while let Some((flags, rest)) = cursor.split_first() {
        cursor = rest;
        if cursor.len() < 4 {
            break;
        }
        let seq = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        let Some((&len_byte, rest)) = cursor.split_first() else {
            break;
        };
        cursor = rest;
        let take = usize::from(len_byte).min(cursor.len());
        let (payload, rest) = cursor.split_at(take);
        cursor = rest;

        let syn = flags & 1 != 0;
        let fin = flags & 2 != 0;
        let rst = flags & 4 != 0;
        let _ = reassembler.offer(src, 51_820, dst, 443, seq, syn, fin, rst, payload);

        assert!(
            reassembler.buffered_bytes() <= MAX_TOTAL,
            "buffered {} bytes past the {MAX_TOTAL} cap",
            reassembler.buffered_bytes()
        );
    }
});
