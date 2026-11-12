use std::net::IpAddr;

use super::protocols::{
    EthernetPacket, IcmpPacket, Icmpv6Packet, Ipv4Packet, Ipv6Packet, Sll2Packet, SllPacket,
    TcpPacket, UdpPacket,
};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// The network header, borrowed from the frame.
#[derive(Debug, Clone, Copy)]
pub enum NetworkSlice<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
}

/// The transport header, borrowed from the frame.
#[derive(Debug, Clone, Copy)]
pub enum TransportSlice<'a> {
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Icmp(IcmpPacket<'a>),
    Icmpv6(Icmpv6Packet<'a>),
}

/// A whole L2-L4 stack read in one pass, borrowing the frame.
///
/// The fast tier: nothing is copied and nothing is allocated, so a capture
/// loop that only needs addresses, ports and offsets never touches the heap.
/// It is also strict, because a fast path that guesses is worse than one that
/// declines: a header whose declared length runs past the capture is refused
/// rather than patched up. [`crate::engine::ParsedPacket`] is the tier that
/// keeps what it can from a short capture, reads tunnels and application
/// protocols, and tracks state.
#[derive(Debug, Clone, Copy)]
pub struct PacketSlice<'a> {
    frame: &'a [u8],
    ethernet: Option<EthernetPacket<'a>>,
    network: Option<NetworkSlice<'a>>,
    transport: Option<TransportSlice<'a>>,
    network_offset: Option<usize>,
    transport_offset: Option<usize>,
}

impl<'a> PacketSlice<'a> {
    /// Reads an Ethernet frame.
    pub fn new(frame: &'a [u8]) -> Option<Self> {
        Self::with_linktype(frame, Some(1))
    }

    /// Reads a frame of a known pcap linktype.
    ///
    /// Ethernet (1), Linux cooked v1 (113) and v2 (276), and raw IP (101 and
    /// the older 12). Anything else returns `None`; the engine parser knows
    /// more link types.
    pub fn with_linktype(frame: &'a [u8], linktype: Option<u16>) -> Option<Self> {
        let mut slice = Self {
            frame,
            ethernet: None,
            network: None,
            transport: None,
            network_offset: None,
            transport_offset: None,
        };

        let (ethertype, offset) = match linktype {
            Some(1) | None => {
                let ethernet = EthernetPacket::new(frame)?;
                let offset = ethernet.payload_offset();
                slice.ethernet = Some(ethernet);
                (ethernet.ethertype(), offset)
            }
            Some(113) => (SllPacket::new(frame)?.protocol(), 16),
            Some(276) => (Sll2Packet::new(frame)?.protocol(), 20),
            Some(101 | 12) => (version_ethertype(frame)?, 0),
            Some(_) => return None,
        };

        slice.read_network(ethertype, offset);
        Some(slice)
    }

    fn read_network(&mut self, ethertype: u16, offset: usize) {
        let Some(bytes) = self.frame.get(offset..) else {
            return;
        };
        match ethertype {
            ETHERTYPE_IPV4 => {
                let Some(ipv4) = Ipv4Packet::new(bytes) else {
                    return;
                };
                self.network = Some(NetworkSlice::Ipv4(ipv4));
                self.network_offset = Some(offset);
                // RFC 791: only the fragment at offset zero carries the
                // transport header. Reading one out of a later fragment would
                // be reading payload as a header.
                if ipv4.fragment_offset() == 0 {
                    self.read_transport(
                        ipv4.protocol(),
                        offset + ipv4.header_len(),
                        ipv4.payload(),
                    );
                }
            }
            ETHERTYPE_IPV6 => {
                let Some(ipv6) = Ipv6Packet::new(bytes) else {
                    return;
                };
                self.network = Some(NetworkSlice::Ipv6(ipv6));
                self.network_offset = Some(offset);
                self.read_transport(ipv6.next_header(), offset + 40, ipv6.payload());
            }
            _ => {}
        }
    }

    /// `bytes` is the network payload, not the rest of the frame: anything
    /// past the length the IP header declared is not part of this datagram.
    fn read_transport(&mut self, protocol: u8, offset: usize, bytes: &'a [u8]) {
        let transport = match protocol {
            6 => TcpPacket::new(bytes).map(TransportSlice::Tcp),
            17 => UdpPacket::new(bytes).map(TransportSlice::Udp),
            1 => IcmpPacket::new(bytes).map(TransportSlice::Icmp),
            58 => Icmpv6Packet::new(bytes).map(TransportSlice::Icmpv6),
            _ => return,
        };
        let Some(transport) = transport else {
            return;
        };
        self.transport = Some(transport);
        self.transport_offset = Some(offset);
    }

    pub fn ethernet(&self) -> Option<EthernetPacket<'a>> {
        self.ethernet
    }

    pub fn network(&self) -> Option<NetworkSlice<'a>> {
        self.network
    }

    pub fn transport(&self) -> Option<TransportSlice<'a>> {
        self.transport
    }

    /// Where the network header sits in the frame, for a caller that rewrites
    /// it in place.
    pub fn network_offset(&self) -> Option<usize> {
        self.network_offset
    }

    pub fn transport_offset(&self) -> Option<usize> {
        self.transport_offset
    }

    pub fn addresses(&self) -> Option<(IpAddr, IpAddr)> {
        match self.network? {
            NetworkSlice::Ipv4(ipv4) => {
                Some((IpAddr::V4(ipv4.source()), IpAddr::V4(ipv4.destination())))
            }
            NetworkSlice::Ipv6(ipv6) => {
                Some((IpAddr::V6(ipv6.source()), IpAddr::V6(ipv6.destination())))
            }
        }
    }

    pub fn ports(&self) -> Option<(u16, u16)> {
        match self.transport? {
            TransportSlice::Tcp(tcp) => Some((tcp.source_port(), tcp.destination_port())),
            TransportSlice::Udp(udp) => Some((udp.source_port(), udp.destination_port())),
            TransportSlice::Icmp(_) | TransportSlice::Icmpv6(_) => None,
        }
    }
}

/// Raw-IP captures carry no ethertype, so the version nibble names the family.
fn version_ethertype(frame: &[u8]) -> Option<u16> {
    match frame.first()? >> 4 {
        4 => Some(ETHERTYPE_IPV4),
        6 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::PacketSlice;
    use crate::craft::{
        EthernetHeader, Ipv4Header, Ipv6Header, PacketBuilder, TcpHeader, UdpHeader,
    };
    use crate::engine::BuiltinPacketParser;

    /// The fast tier and the rich tier read the same frame, so they have to
    /// agree about what is in it and where.
    #[test]
    fn the_slice_agrees_with_the_engine_parser() {
        let ipv4 = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv4(Ipv4Header::new(
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(198, 51, 100, 2),
                0,
                0,
            ))
            .udp(UdpHeader::new(1234, 53, 0))
            .build(b"payload")
            .expect("builds");

        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let ipv6 = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv6(Ipv6Header::new(source, destination, 0, 0))
            .tcp(TcpHeader::new(443, 51000, 0))
            .build(b"payload")
            .expect("builds");

        for frame in [&ipv4, &ipv6] {
            let slice = PacketSlice::new(frame).expect("the frame reads");
            let parsed = BuiltinPacketParser::parse(frame).expect("the frame parses");

            assert_eq!(slice.network_offset(), parsed.network_offset);
            assert_eq!(slice.transport_offset(), parsed.transport_segment_offset);
            assert_eq!(slice.ports(), parsed.ports());

            let (slice_source, slice_destination) = slice.addresses().expect("addresses");
            let (engine_source, engine_destination): (IpAddr, IpAddr) =
                match (&parsed.ipv4, &parsed.ipv6) {
                    (Some(header), _) => (header.source.into(), header.destination.into()),
                    (_, Some(header)) => (header.source.into(), header.destination.into()),
                    _ => unreachable!("one of the two is set"),
                };
            assert_eq!(slice_source, engine_source);
            assert_eq!(slice_destination, engine_destination);
        }
    }

    /// A raw-IP capture has no link header, so the version nibble is the only
    /// thing naming the family.
    #[test]
    fn a_raw_ip_frame_reads_without_a_link_header() {
        let frame = PacketBuilder::new()
            .ipv4(Ipv4Header::new(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                0,
                0,
            ))
            .udp(UdpHeader::new(7, 9, 0))
            .build(b"x")
            .expect("builds");

        let slice = PacketSlice::with_linktype(&frame, Some(101)).expect("the frame reads");
        assert_eq!(slice.network_offset(), Some(0));
        assert_eq!(slice.ports(), Some((7, 9)));
        assert!(slice.ethernet().is_none(), "there is no link header");
    }

    /// Three ways the fast tier could report a transport header that is not
    /// there: bytes past the declared IP length, a later fragment whose
    /// payload is not a header, and a VLAN stack deep enough to saturate the
    /// tag count. In each the engine is the reference.
    #[test]
    fn the_slice_reads_no_transport_the_engine_would_not() {
        // Total length 20, so the eight bytes after the header are not in the
        // datagram at all.
        let trailing = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x7a, 0xda, 0, 0, 0, 0, 0,
            0, 0, 0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00,
        ];
        let slice = PacketSlice::with_linktype(&trailing, Some(101)).expect("reads");
        assert!(slice.network().is_some(), "the IPv4 header is there");
        assert_eq!(slice.ports(), None, "those bytes are outside the datagram");

        // Fragment offset 1: the payload starts eight bytes into the original
        // datagram, so it is not a transport header.
        let fragment = [
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x40, 0x11, 0x7a, 0xd1, 0, 0, 0, 0, 0,
            0, 0, 0, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00,
        ];
        let slice = PacketSlice::with_linktype(&fragment, Some(101)).expect("reads");
        assert!(slice.network().is_some(), "the IPv4 header is there");
        assert_eq!(slice.ports(), None, "a later fragment carries no header");

        // 256 tags, one more than a u8 depth can count.
        let mut deep = vec![0u8; 12];
        for _ in 0..256 {
            deep.extend([0x81, 0x00, 0x00, 0x00]);
        }
        deep.extend([0x08, 0x00]);
        deep.extend([
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0, 0, 10, 0, 0, 1, 10, 0,
            0, 2, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x00,
        ]);
        let slice = PacketSlice::new(&deep).expect("reads");
        let parsed = BuiltinPacketParser::parse(&deep).expect("parses");
        assert_eq!(slice.network_offset(), Some(1038));
        assert_eq!(slice.network_offset(), parsed.network_offset);
        assert_eq!(slice.ports(), Some((1, 2)));
    }

    /// The fast tier declines a header the capture cut short rather than
    /// reporting fields from bytes that are not there.
    #[test]
    fn a_truncated_header_is_declined_rather_than_guessed_at() {
        let frame = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv4(Ipv4Header::new(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                0,
                0,
            ))
            .udp(UdpHeader::new(7, 9, 0))
            .build(b"payload")
            .expect("builds");

        let short = &frame[..frame.len() - 4];
        let slice = PacketSlice::new(short).expect("the link header is whole");
        assert!(
            slice.network().is_none(),
            "the IPv4 total length runs past the capture"
        );
        assert_eq!(slice.network_offset(), None);
    }
}
