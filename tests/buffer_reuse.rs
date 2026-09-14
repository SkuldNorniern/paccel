mod frames_common;

use paccel::engine::{BuiltinPacketParser, ParseConfig, ParsedPacket};

#[test]
fn a_reused_buffer_reads_the_same_as_a_fresh_one() {
    let frames = frames_common::frames();

    let config = ParseConfig::default();
    // Carried across every frame, so each one meets whatever the last left.
    let mut reused = ParsedPacket::default();
    let mut differed = Vec::new();

    for (index, (_name, frame)) in frames.iter().enumerate() {
        let mut fresh = ParsedPacket::default();
        let fresh_result =
            BuiltinPacketParser::parse_into(frame, config, Some(1), &mut fresh).is_ok();
        let reused_result =
            BuiltinPacketParser::parse_into(frame, config, Some(1), &mut reused).is_ok();

        if fresh_result != reused_result || format!("{fresh:?}") != format!("{reused:?}") {
            differed.push(index);
            if differed.len() > 3 {
                break;
            }
        }
    }

    assert!(
        differed.is_empty(),
        "{} frames parsed differently into a reused buffer, first at index {:?}",
        differed.len(),
        differed.first()
    );
}
