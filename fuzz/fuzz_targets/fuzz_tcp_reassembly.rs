#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use paccel::TcpStreamReassembler;

// Interprets fuzz bytes as a sequence of TCP segment offers so the
// reassembler's stateful invariants (bounded buffering, FIFO eviction,
// never panics) get exercised, not just its structural byte parsing.
fuzz_target!(|data: &[u8]| {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut reassembler = TcpStreamReassembler::new().with_max_flows(64);

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
        let _ = reassembler.offer(src, 51_820, dst, 443, seq, syn, fin, payload);
    }
});
