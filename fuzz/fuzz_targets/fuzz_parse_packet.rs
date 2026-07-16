#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::engine::{BuiltinPacketParser, ParseConfig, ParseMode};

fuzz_target!(|data: &[u8]| {
    let _ = BuiltinPacketParser::parse(data);
    let strict = ParseConfig {
        mode: ParseMode::Strict,
        ..ParseConfig::default()
    };
    let _ = BuiltinPacketParser::parse_with_config(data, strict);
});
