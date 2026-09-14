use std::fs;
use std::path::Path;

use paccel::engine::{BuiltinPacketParser, ParseConfig, ParsedPacket};

/// Checks one packet and every tunnel level below it.
fn offsets_within(parsed: &ParsedPacket, len: usize, path: &mut Vec<&'static str>) -> Vec<String> {
    let mut wrong = Vec::new();

    if let Some(offset) = parsed.transport_segment_offset
        && offset > len
    {
        wrong.push(format!(
            "transport_segment_offset {offset} past {len} at {path:?}"
        ));
    }
    if let Some(ethernet) = parsed.ethernet.as_ref()
        && ethernet.payload_offset > len
    {
        wrong.push(format!(
            "ethernet payload_offset {} past {len} at {path:?}",
            ethernet.payload_offset
        ));
    }

    if let Some(inner) = parsed.inner.as_deref() {
        path.push("inner");
        wrong.extend(offsets_within(inner, len, path));
        path.pop();
    }
    if let Some(quoted) = parsed.icmp_quoted.as_deref() {
        path.push("icmp_quoted");
        wrong.extend(offsets_within(quoted, len, path));
        path.pop();
    }

    wrong
}

#[test]
fn reported_offsets_stay_inside_the_frame() {
    let corpus = Path::new("fuzz/corpus/fuzz_parse_packet");
    let Ok(entries) = fs::read_dir(corpus) else {
        return;
    };

    let config = ParseConfig::default();
    let mut wrong = Vec::new();

    for entry in entries.flatten() {
        let Ok(data) = fs::read(entry.path()) else {
            continue;
        };
        if data.is_empty() {
            continue;
        }

        let mut parsed = ParsedPacket::default();
        if BuiltinPacketParser::parse_into(&data, config, Some(1), &mut parsed).is_err() {
            continue;
        }

        let mut path = Vec::new();
        for problem in offsets_within(&parsed, data.len(), &mut path) {
            wrong.push(format!("{}: {problem}", entry.path().display()));
        }
        if wrong.len() > 3 {
            break;
        }
    }

    assert!(wrong.is_empty(), "{wrong:#?}");
}
