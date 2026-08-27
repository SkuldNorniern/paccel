#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::layer::application::quic::{
    parse_quic_long_header, parse_quic_short_header, parse_quic_version_negotiation,
    split_coalesced_packets,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_quic_long_header(data);
    let _ = parse_quic_version_negotiation(data);
    let _ = split_coalesced_packets(data);

    for dcid_len in 0..=20usize {
        let _ = parse_quic_short_header(data, dcid_len);
    }
});
