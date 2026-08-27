#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::layer::application::quic::iter_quic_frames;

fuzz_target!(|data: &[u8]| {
    let mut iter = iter_quic_frames(data);
    let mut yielded = 0usize;
    let mut saw_err = false;

    for frame in iter.by_ref() {
        yielded += 1;
        if frame.is_err() {
            saw_err = true;
            break;
        }
        // Guard against a hypothetical zero-progress bug turning this into an
        // infinite loop under fuzzing.
        assert!(
            yielded <= data.len() + 1,
            "iter_quic_frames yielded more items than input bytes allow"
        );
    }

    if saw_err {
        // Poisoning contract: exactly one Err, then the iterator must stop.
        assert!(iter.next().is_none());
    }
});
