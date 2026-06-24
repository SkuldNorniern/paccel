use paccel::engine::{BuiltinPacketParser, TransportSegment};

fn main() {
    // Ethernet + IPv4 + TCP SYN (40 bytes, no payload)
    let frame: &[u8] = &[
        // Ethernet: dst=ff:…, src=aa:bb:…, ethertype=IPv4
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00,
        // IPv4: v4 ihl=5, total_len=40, id, DF, ttl=64, proto=TCP, cksum=0, 10.0.0.1→10.0.0.2
        0x45, 0x00, 0x00, 0x28,
        0x12, 0x34,
        0x40, 0x00,
        0x40, 0x06,
        0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2,
        // TCP: sport=54321, dport=80, seq=1, ack=0, data_offset=5, flags=SYN, window, cksum=0, urg=0
        0xd4, 0x31,
        0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02,
        0xff, 0xff,
        0x00, 0x00,
        0x00, 0x00,
    ];

    match BuiltinPacketParser::parse(frame) {
        Ok(parsed) => {
            if let Some(eth) = &parsed.ethernet {
                let [a, b, c, d, e, f] = eth.source;
                println!("eth src: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", a, b, c, d, e, f);
            }
            if let Some(ipv4) = &parsed.ipv4 {
                println!("ipv4: {} → {}", ipv4.source, ipv4.destination);
            }
            if let Some(TransportSegment::Tcp(tcp)) = &parsed.transport {
                println!("tcp: {}→{} seq={} flags: syn={} ack={}",
                    tcp.source_port, tcp.destination_port,
                    tcp.sequence_number, tcp.flags.syn, tcp.flags.ack);
            }
        }
        Err(e) => eprintln!("parse error: {e}"),
    }
}
