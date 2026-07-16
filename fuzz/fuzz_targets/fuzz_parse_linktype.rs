#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::engine::BuiltinPacketParser;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let linktype = u16::from_le_bytes([data[0], data[1]]);
    let _ = BuiltinPacketParser::parse_with_linktype(&data[2..], linktype);
});
