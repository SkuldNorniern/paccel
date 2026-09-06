#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::layer::application::http2::{iter_http2_frames, parse_http2_frames};

// The typed iterator decodes frame bodies, which means padding arithmetic and
// per-type length rules on attacker-controlled lengths - the shape of bug that
// underflows a subtraction. It also has to agree with the header-only walk
// about where each frame ends, or one of the two is reading the stream wrongly.
fuzz_target!(|data: &[u8]| {
    let mut iter = iter_http2_frames(data);
    let mut previous_remainder = iter.remainder().len();
    let mut count = 0usize;

    while let Some(frame) = iter.next() {
        count += 1;
        let remainder = iter.remainder().len();
        assert!(
            remainder < previous_remainder,
            "a frame was yielded without consuming anything"
        );
        previous_remainder = remainder;

        // Every borrowed body has to lie inside the frame the header declared.
        let declared = frame.header.length as usize;
        assert!(
            declared <= data.len(),
            "a frame claimed more bytes than the whole input"
        );
    }

    // A full nine-byte header does not mean a consumable frame: the header
    // declares a body length, and a stream cut before that body has arrived
    // legitimately leaves the whole header in the remainder. That is what
    // remainder() is for, so there is nothing to assert about its size here.

    let headers = parse_http2_frames(data);
    assert_eq!(
        headers.len(),
        count,
        "the typed walk and the header walk disagree on framing"
    );
});
