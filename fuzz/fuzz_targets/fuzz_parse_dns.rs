#![no_main]

use libfuzzer_sys::fuzz_target;
use paccel::layer::application::dns::parse_dns_message;

fuzz_target!(|data: &[u8]| {
    let _ = parse_dns_message(data);
});
