#![no_main]

use std::net::{Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use paccel::craft::{
    EthernetHeader, IcmpHeader, Ipv4Header, Ipv6Header, PacketBuilder, TcpHeader, UdpHeader,
};
use paccel::engine::BuiltinPacketParser;

// Builds a stack out of the fuzzer's bytes, then checks three things a caller
// depends on: `encoded_len` is exactly what an encode writes, an encode never
// touches a byte past that, and a buffer one short is refused.
fuzz_target!(|data: &[u8]| {
    let Some((choices, rest)) = data.split_at_checked(4) else {
        return;
    };
    let payload = &rest[..rest.len().min(2048)];

    let mut builder = PacketBuilder::new().ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0));
    builder = if choices[0] % 2 == 0 {
        builder.ipv4(Ipv4Header::new(
            Ipv4Addr::new(choices[1], 0, 2, 1),
            Ipv4Addr::new(choices[2], 51, 100, 2),
            0,
            0,
        ))
    } else {
        builder.ipv6(Ipv6Header::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(choices[1])),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(choices[2])),
            0,
            0,
        ))
    };
    let ports = (u16::from(choices[1]) << 8 | u16::from(choices[2]), 53);
    builder = match choices[3] % 3 {
        0 => builder.udp(UdpHeader::new(ports.0, ports.1, 0)),
        1 => builder.tcp(TcpHeader::new(ports.0, ports.1, 0)),
        _ => builder.icmp(IcmpHeader::echo_request(u16::from(choices[1]), 1)),
    };

    let needed = builder.encoded_len(payload.len());

    // A byte short has to be refused, not truncated.
    if needed > 0 {
        let mut short = vec![0; needed - 1];
        assert!(builder.encode_into(&mut short, payload).is_err());
    }

    // A long buffer: everything past `needed` must still hold the sentinel.
    const SENTINEL: u8 = 0x5a;
    let mut buffer = vec![SENTINEL; needed + 16];
    let Ok(written) = builder.encode_into(&mut buffer, payload) else {
        return;
    };
    assert_eq!(written, needed, "encoded_len must be what gets written");
    assert!(
        buffer[written..].iter().all(|byte| *byte == SENTINEL),
        "the encode wrote past the frame it declared"
    );

    // What was crafted has to parse back as what was asked for.
    let frame = &buffer[..written];
    let parsed = BuiltinPacketParser::parse(frame).expect("a crafted frame parses");
    if parsed.transport.is_some() {
        assert_eq!(parsed.ports(), Some(ports));
    }
});
