//! The README's craft and slice examples, kept compiling.

use std::net::Ipv4Addr;

use paccel::craft::{EthernetHeader, Ipv4Header, PacketBuilder, UdpHeader};
use paccel::packet::PacketSlice;

#[test]
fn the_readme_craft_example_still_works() {
    let payload = b"hello";
    let builder = PacketBuilder::new()
        .ethernet(EthernetHeader::new(
            [0xff; 6],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            0x0800,
        ))
        .ipv4(Ipv4Header::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            17,
            8 + payload.len(),
        ))
        .udp(UdpHeader::new(53_000, 53, payload.len()));

    let mut buffer = [0u8; 1514];
    let written = builder
        .encode_into(&mut buffer, payload)
        .expect("the buffer is large enough");
    assert_eq!(written, builder.encoded_len(payload.len()));

    let slice = PacketSlice::new(&buffer[..written]).expect("a frame we just built");
    let (source, destination) = slice.addresses().expect("an ipv4 header");
    assert_eq!(source, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(destination, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(slice.ports(), Some((53_000, 53)));
}
