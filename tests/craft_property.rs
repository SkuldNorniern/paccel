use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use paccel::craft::{
    ChecksumAccumulator, EthernetHeader, Ipv4Header, Ipv6Header, Options, PacketBuilder,
    PseudoHeader, TcpHeader, UdpHeader, update_u16,
};
use paccel::engine::BuiltinPacketParser;
use proptest::prelude::*;

/// Sums a transport segment with its pseudo-header the way a receiver does.
/// Zero means the checksum in the segment is right.
fn verifies(source: IpAddr, destination: IpAddr, protocol: u8, segment: &[u8]) -> u16 {
    let mut sum = ChecksumAccumulator::new();
    PseudoHeader {
        source,
        destination,
        protocol,
        length: u32::try_from(segment.len()).expect("a short segment"),
    }
    .add_to(&mut sum)
    .expect("one address family");
    sum.add_bytes(segment);
    sum.finish()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Whatever goes into a builder comes back out of the parser, and the
    /// checksums verify, for any addresses, ports and payload.
    #[test]
    fn an_ipv4_udp_frame_survives_a_round_trip(
        source in any::<[u8; 4]>(),
        destination in any::<[u8; 4]>(),
        source_port in any::<u16>(),
        destination_port in any::<u16>(),
        payload in prop::collection::vec(any::<u8>(), 0..1400),
    ) {
        let source = Ipv4Addr::from(source);
        let destination = Ipv4Addr::from(destination);
        let frame = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv4(Ipv4Header::new(source, destination, 0, 0))
            .udp(UdpHeader::new(source_port, destination_port, 0))
            .build(&payload)
            .expect("the frame builds");

        let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
        let ipv4 = parsed.ipv4.as_ref().expect("the IPv4 header");
        prop_assert_eq!(ipv4.source, source);
        prop_assert_eq!(ipv4.destination, destination);
        prop_assert_eq!(parsed.ports(), Some((source_port, destination_port)));

        let at = parsed.network_offset.expect("where the header sits");
        let mut header = ChecksumAccumulator::new();
        header.add_bytes(&frame[at..at + 20]);
        prop_assert_eq!(header.finish(), 0, "the IPv4 checksum verifies");

        let segment = parsed.transport_segment_offset.expect("where UDP sits");
        prop_assert_eq!(
            verifies(source.into(), destination.into(), 17, &frame[segment..]),
            0,
            "the UDP checksum verifies"
        );
    }

    /// TCP over IPv6, with options, so the odd-length and option paths are
    /// covered too.
    #[test]
    fn an_ipv6_tcp_frame_survives_a_round_trip(
        source in any::<[u8; 16]>(),
        destination in any::<[u8; 16]>(),
        source_port in any::<u16>(),
        destination_port in any::<u16>(),
        sequence in any::<u32>(),
        option_words in 0usize..10,
        payload in prop::collection::vec(any::<u8>(), 0..1400),
    ) {
        let source = Ipv6Addr::from(source);
        let destination = Ipv6Addr::from(destination);
        let mut tcp = TcpHeader::new(source_port, destination_port, 0);
        tcp.sequence = sequence;
        // One-byte no-ops, which are legal filler and keep the length a
        // multiple of four.
        tcp.options = Options::new(&vec![1; option_words * 4]).expect("aligned");

        let frame = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv6(Ipv6Header::new(source, destination, 0, 0))
            .tcp(tcp)
            .build(&payload)
            .expect("the frame builds");

        let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
        let ipv6 = parsed.ipv6.as_ref().expect("the IPv6 header");
        prop_assert_eq!(ipv6.source, source);
        prop_assert_eq!(ipv6.destination, destination);
        prop_assert_eq!(parsed.ports(), Some((source_port, destination_port)));

        let segment = parsed.transport_segment_offset.expect("where TCP sits");
        prop_assert_eq!(
            verifies(source.into(), destination.into(), 6, &frame[segment..]),
            0,
            "the TCP checksum verifies"
        );
    }

    /// An encode writes exactly what `encoded_len` promised, never a byte more.
    #[test]
    fn an_encode_writes_exactly_what_it_declared(
        header_len in 0usize..10,
        payload in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut ipv4 = Ipv4Header::new(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 0, 0);
        ipv4.options = Options::new(&vec![1; header_len * 4]).expect("aligned");
        let builder = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0; 6], [0; 6], 0))
            .ipv4(ipv4)
            .udp(UdpHeader::new(1, 2, 0));

        let needed = builder.encoded_len(payload.len());
        const SENTINEL: u8 = 0x5a;
        let mut buffer = vec![SENTINEL; needed + 32];
        let written = builder.encode_into(&mut buffer, &payload).expect("room");

        prop_assert_eq!(written, needed);
        prop_assert!(buffer[written..].iter().all(|byte| *byte == SENTINEL));
        prop_assert!(builder.encode_into(&mut vec![0; needed - 1], &payload).is_err());
    }

    /// The incremental update has to land on the same value as summing the
    /// changed bytes from scratch, for any header and any replacement.
    #[test]
    fn an_incremental_update_agrees_with_a_fresh_sum(
        bytes in prop::collection::vec(any::<u8>(), 2..64),
        at in 0usize..31,
        new in any::<u16>(),
    ) {
        let mut bytes = bytes;
        if bytes.len() % 2 != 0 {
            bytes.pop();
        }
        prop_assume!(bytes.len() >= 2);
        let at = (at * 2) % (bytes.len() - 1);
        let at = at - at % 2;

        let mut before = ChecksumAccumulator::new();
        before.add_bytes(&bytes);
        let old = u16::from_be_bytes([bytes[at], bytes[at + 1]]);

        let mut changed = bytes.clone();
        changed[at..at + 2].copy_from_slice(&new.to_be_bytes());
        let mut after = ChecksumAccumulator::new();
        after.add_bytes(&changed);

        prop_assert_eq!(update_u16(before.finish(), old, new), after.finish());
    }
}
