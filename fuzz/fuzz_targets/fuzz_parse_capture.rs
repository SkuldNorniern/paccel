#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::engine::{iter_capture_frames, parse_capture_frames};

fuzz_target!(|data: &[u8]| {
    let _ = parse_capture_frames(data);
    if let Ok(iter) = iter_capture_frames(data) {
        for frame in iter {
            let _ = frame;
        }
    }
});
