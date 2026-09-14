//! Selects a small spread of corpus frames for the tracked test set.
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use paccel::engine::{BuiltinPacketParser, ParseConfig, ParsedPacket};

#[test]
#[ignore = "run by hand to refresh tests/frames"]
fn pick() {
    let corpus = Path::new("fuzz/corpus/fuzz_parse_packet");
    let out = Path::new("tests/frames");
    fs::create_dir_all(out).expect("out dir");

    // A few frames per distinct warning shape, plus a few clean ones, so the
    // set covers the properties rather than being an arbitrary sample.
    let mut buckets: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();

    for entry in fs::read_dir(corpus).expect("corpus").flatten() {
        let Ok(data) = fs::read(entry.path()) else {
            continue;
        };
        if data.is_empty() || data.len() > 400 {
            continue;
        }
        let mut parsed = ParsedPacket::default();
        if BuiltinPacketParser::parse_into(&data, ParseConfig::default(), Some(1), &mut parsed)
            .is_err()
        {
            continue;
        }
        let mut shape: Vec<String> = parsed
            .warnings
            .iter()
            .map(|w| format!("{:?}", w.code))
            .collect();
        shape.sort();
        shape.dedup();
        if parsed.inner.is_some() {
            shape.push("tunnel".to_string());
        }
        if parsed.icmp_quoted.is_some() {
            shape.push("quoted".to_string());
        }
        let key = if shape.is_empty() {
            "clean".to_string()
        } else {
            shape.join("+")
        };
        let bucket = buckets.entry(key).or_default();
        if bucket.len() < 3 {
            bucket.push(data);
        }
    }

    let mut written = 0usize;
    for (shape, frames) in &buckets {
        for (index, frame) in frames.iter().enumerate() {
            let safe: String = shape
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect();
            fs::write(out.join(format!("{safe}_{index}.bin")), frame).expect("write");
            written += 1;
        }
    }
    eprintln!("wrote {written} frames across {} shapes", buckets.len());
}
