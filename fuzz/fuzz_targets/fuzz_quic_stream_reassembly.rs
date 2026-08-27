#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use paccel::QuicStreamReassembler;

// Interprets fuzz bytes as a sequence of STREAM-frame offers so the
// reassembler's stateful invariants (bounded buffering, FIFO eviction,
// never panics) get exercised, not just its structural byte parsing.
fuzz_target!(|data: &[u8]| {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut reassembler = QuicStreamReassembler::new().with_max_streams(64);

    let mut cursor = data;
    while let Some((op, rest)) = cursor.split_first() {
        cursor = rest;
        let Some((&stream_id, rest)) = cursor.split_first() else {
            break;
        };
        cursor = rest;
        if cursor.len() < 2 {
            break;
        }
        let offset = u16::from_le_bytes([cursor[0], cursor[1]]);
        cursor = &cursor[2..];
        let Some((&len_byte, rest)) = cursor.split_first() else {
            break;
        };
        cursor = rest;
        let take = usize::from(len_byte).min(cursor.len());
        let (payload, rest) = cursor.split_at(take);
        cursor = rest;

        let fin = op & 1 != 0;
        let _ = reassembler.offer(
            src,
            4_433,
            dst,
            443,
            u64::from(stream_id),
            u64::from(offset),
            fin,
            payload,
        );
    }
});
