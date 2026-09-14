use std::fs;
use std::path::Path;

pub fn frames() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for dir in ["tests/frames", "fuzz/corpus/fuzz_parse_packet"] {
        let Ok(entries) = fs::read_dir(Path::new(dir)) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(data) = fs::read(entry.path()) else {
                continue;
            };
            if !data.is_empty() {
                out.push((entry.path().display().to_string(), data));
            }
        }
    }

    out
}
