#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use paccel::QuicStreamReassembler;

// Interprets fuzz bytes as a sequence of STREAM-frame offers so the
// reassembler's stateful invariants get exercised, not just its structural
// byte parsing. The limits are deliberately small so the caps are reached
// often, and they are asserted after every operation rather than assumed:
// a target that only checks for panics cannot tell bounded buffering from
// unbounded.
fuzz_target!(|data: &[u8]| {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    const MAX_PER_STREAM: usize = 4_096;
    const MAX_TOTAL: usize = 16_384;

    let mut reassembler = QuicStreamReassembler::with_limits(MAX_PER_STREAM, 65_535)
        .with_max_streams(64)
        .with_max_total_buffered_bytes(MAX_TOTAL);

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
        // Both directions, so a bug that only shows when one stream is fed
        // from each side has somewhere to appear.
        let source_port = if op & 2 == 0 { 4_433 } else { 443 };
        let destination_port = if op & 2 == 0 { 443 } else { 4_433 };
        let _ = reassembler.offer(
            src,
            source_port,
            dst,
            destination_port,
            u64::from(stream_id),
            u64::from(offset),
            fin,
            payload,
        );

        assert!(
            reassembler.buffered_bytes() <= MAX_TOTAL,
            "buffered {} bytes past the {MAX_TOTAL} cap",
            reassembler.buffered_bytes()
        );
    }
});
