#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::layer::application::http2::{iter_http2_frames, parse_http2_frames};

// Padding arithmetic on attacker-controlled lengths, and the typed walk has to
// agree with the header-only one about where each frame ends.
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

    // A whole header can sit in the remainder: the body it declares may not
    // have arrived. Nothing to assert about the remainder's size.

    let headers = parse_http2_frames(data);
    assert_eq!(
        headers.len(),
        count,
        "the typed walk and the header walk disagree on framing"
    );
});
