use std::net::IpAddr;

use super::{
    Encode, EncodeError, EthernetHeader, Ipv4Header, Ipv6Header, PseudoHeader, TcpHeader, UdpHeader,
};

/// The network header a builder will write.
#[derive(Debug, Clone, Copy)]
pub enum NetworkHeader {
    Ipv4(Ipv4Header),
    Ipv6(Ipv6Header),
}

/// The transport header a builder will write.
#[derive(Debug, Clone, Copy)]
pub enum TransportHeader {
    Udp(UdpHeader),
    Tcp(TcpHeader),
}

/// Writes a whole frame, deriving what the layers say about each other.
///
/// Lengths, ethertypes, protocol numbers and checksums come from the stack
/// itself, so they cannot disagree. To write a frame that does disagree, encode
/// the headers one at a time instead; nothing here makes that impossible.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketBuilder {
    ethernet: Option<EthernetHeader>,
    network: Option<NetworkHeader>,
    transport: Option<TransportHeader>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn ethernet(mut self, header: EthernetHeader) -> Self {
        self.ethernet = Some(header);
        self
    }

    #[must_use]
    pub fn ipv4(mut self, header: Ipv4Header) -> Self {
        self.network = Some(NetworkHeader::Ipv4(header));
        self
    }

    #[must_use]
    pub fn ipv6(mut self, header: Ipv6Header) -> Self {
        self.network = Some(NetworkHeader::Ipv6(header));
        self
    }

    #[must_use]
    pub fn udp(mut self, header: UdpHeader) -> Self {
        self.transport = Some(TransportHeader::Udp(header));
        self
    }

    #[must_use]
    pub fn tcp(mut self, header: TcpHeader) -> Self {
        self.transport = Some(TransportHeader::Tcp(header));
        self
    }

    pub fn encoded_len(&self, payload_len: usize) -> usize {
        let ethernet = self.ethernet.map_or(0, |header| header.encoded_len());
        let network = match self.network {
            Some(NetworkHeader::Ipv4(header)) => header.encoded_len(),
            Some(NetworkHeader::Ipv6(header)) => header.encoded_len(),
            None => 0,
        };
        ethernet + network + self.transport_len() + payload_len
    }

    fn transport_len(&self) -> usize {
        match self.transport {
            Some(TransportHeader::Udp(header)) => header.encoded_len(),
            Some(TransportHeader::Tcp(header)) => header.encoded_len(),
            None => 0,
        }
    }

    fn protocol(&self) -> Option<u8> {
        match self.transport {
            Some(TransportHeader::Udp(_)) => Some(17),
            Some(TransportHeader::Tcp(_)) => Some(6),
            None => None,
        }
    }

    fn addresses(&self) -> Option<(IpAddr, IpAddr)> {
        match self.network? {
            NetworkHeader::Ipv4(header) => {
                Some((IpAddr::V4(header.source), IpAddr::V4(header.destination)))
            }
            NetworkHeader::Ipv6(header) => {
                Some((IpAddr::V6(header.source), IpAddr::V6(header.destination)))
            }
        }
    }

    /// Writes the frame into `buffer` and returns how many bytes it took.
    pub fn encode_into(&self, buffer: &mut [u8], payload: &[u8]) -> Result<usize, EncodeError> {
        let needed = self.encoded_len(payload.len());
        if buffer.len() < needed {
            return Err(EncodeError::BufferTooSmall {
                needed,
                given: buffer.len(),
            });
        }

        let transport = self.resolved_transport(payload)?;
        let mut written = 0;

        if let Some(mut ethernet) = self.ethernet {
            ethernet.ethertype = match self.network {
                Some(NetworkHeader::Ipv4(_)) => 0x0800,
                Some(NetworkHeader::Ipv6(_)) => 0x86dd,
                None => ethernet.ethertype,
            };
            written += ethernet.encode_into(&mut buffer[written..])?;
        }

        let below = self.transport_len() + payload.len();
        match self.network {
            Some(NetworkHeader::Ipv4(mut header)) => {
                header.payload_len = below;
                if let Some(protocol) = self.protocol() {
                    header.protocol = protocol;
                }
                written += header.encode_into(&mut buffer[written..])?;
            }
            Some(NetworkHeader::Ipv6(mut header)) => {
                header.payload_len = below;
                if let Some(protocol) = self.protocol() {
                    header.next_header = protocol;
                }
                written += header.encode_into(&mut buffer[written..])?;
            }
            None => {}
        }

        match transport {
            Some(TransportHeader::Udp(header)) => {
                written += header.encode_into(&mut buffer[written..])?;
            }
            Some(TransportHeader::Tcp(header)) => {
                written += header.encode_into(&mut buffer[written..])?;
            }
            None => {}
        }

        buffer[written..written + payload.len()].copy_from_slice(payload);
        Ok(written + payload.len())
    }

    pub fn build(&self, payload: &[u8]) -> Result<Vec<u8>, EncodeError> {
        let mut buffer = vec![0; self.encoded_len(payload.len())];
        let written = self.encode_into(&mut buffer, payload)?;
        buffer.truncate(written);
        Ok(buffer)
    }

    /// The transport header with its length and checksum filled in.
    fn resolved_transport(&self, payload: &[u8]) -> Result<Option<TransportHeader>, EncodeError> {
        let Some(transport) = self.transport else {
            return Ok(None);
        };
        let Some((source, destination)) = self.addresses() else {
            // No network header, so there is no pseudo-header to sum over and
            // the checksum stays as the caller set it.
            return Ok(Some(transport));
        };
        let protocol = self.protocol().unwrap_or(0);

        Ok(Some(match transport {
            TransportHeader::Udp(mut header) => {
                header.payload_len = payload.len();
                let pseudo = PseudoHeader {
                    source,
                    destination,
                    protocol,
                    length: covered_length(header.encoded_len(), payload.len())?,
                };
                header.checksum = header.checksum_over(pseudo, payload)?;
                TransportHeader::Udp(header)
            }
            TransportHeader::Tcp(mut header) => {
                header.payload_len = payload.len();
                let pseudo = PseudoHeader {
                    source,
                    destination,
                    protocol,
                    length: covered_length(header.encoded_len(), payload.len())?,
                };
                header.checksum = header.checksum_over(pseudo, payload)?;
                TransportHeader::Tcp(header)
            }
        }))
    }
}

/// What the pseudo-header says the transport covers.
fn covered_length(header_len: usize, payload_len: usize) -> Result<u32, EncodeError> {
    u32::try_from(header_len + payload_len).map_err(|_| EncodeError::PayloadTooLong {
        max: u32::MAX as usize - header_len,
        got: payload_len,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{PacketBuilder, PseudoHeader};
    use crate::craft::{
        ChecksumAccumulator, EthernetHeader, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader,
    };
    use crate::engine::{BuiltinPacketParser, TransportSegment};

    /// Summing a transport header that already holds its checksum, together
    /// with its pseudo-header and payload, comes to zero when the checksum is
    /// right. That is what a receiver does.
    fn transport_checksum_verifies(
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        segment: &[u8],
    ) {
        let mut sum = ChecksumAccumulator::new();
        PseudoHeader {
            source,
            destination,
            protocol,
            length: u32::try_from(segment.len()).expect("a short segment"),
        }
        .add_to(&mut sum)
        .expect("one family");
        sum.add_bytes(segment);
        assert_eq!(sum.finish(), 0, "the transport checksum verifies");
    }

    #[test]
    fn an_ipv4_udp_frame_parses_back_and_its_checksums_verify() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let destination = Ipv4Addr::new(198, 51, 100, 2);
        let payload = b"paccel";

        let frame = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv4(Ipv4Header::new(source, destination, 0, 0))
            .udp(UdpHeader::new(1234, 53, 0))
            .build(payload)
            .expect("the frame builds");

        let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
        let ipv4 = parsed.ipv4.as_ref().expect("the IPv4 header");
        assert_eq!(ipv4.source, source);
        assert_eq!(ipv4.destination, destination);
        assert_eq!(ipv4.protocol, 17, "the builder derived the protocol");
        assert_eq!(parsed.ports(), Some((1234, 53)));
        let udp = parsed
            .transport
            .as_ref()
            .and_then(|segment| match segment {
                TransportSegment::Udp(udp) => Some(udp),
                _ => None,
            })
            .expect("a UDP segment");
        assert_eq!(usize::from(udp.length), 8 + payload.len());

        let at = parsed.network_offset.expect("where the header sits");
        let mut header_sum = ChecksumAccumulator::new();
        header_sum.add_bytes(&frame[at..at + 20]);
        assert_eq!(header_sum.finish(), 0, "the IPv4 checksum verifies");

        let segment = parsed.transport_segment_offset.expect("where UDP sits");
        transport_checksum_verifies(
            IpAddr::V4(source),
            IpAddr::V4(destination),
            17,
            &frame[segment..],
        );
    }

    #[test]
    fn an_ipv6_tcp_frame_parses_back_and_its_checksum_verifies() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let payload = b"an odd length";

        let mut tcp = TcpHeader::new(443, 51000, 0);
        tcp.sequence = 0xdead_beef;
        tcp.flags = 0x18;

        let frame = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv6(Ipv6Header::new(source, destination, 0, 0))
            .tcp(tcp)
            .build(payload)
            .expect("the frame builds");

        let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
        let ipv6 = parsed.ipv6.as_ref().expect("the IPv6 header");
        assert_eq!(ipv6.source, source);
        assert_eq!(ipv6.resolved_next_header, 6, "the builder derived it");
        let parsed_tcp = parsed
            .transport
            .as_ref()
            .and_then(|segment| match segment {
                TransportSegment::Tcp(tcp) => Some(tcp),
                _ => None,
            })
            .expect("a TCP segment");
        assert_eq!(parsed_tcp.sequence_number, 0xdead_beef);
        assert_eq!(parsed_tcp.source_port, 443);

        let segment = parsed.transport_segment_offset.expect("where TCP sits");
        transport_checksum_verifies(
            IpAddr::V6(source),
            IpAddr::V6(destination),
            6,
            &frame[segment..],
        );
    }

    /// `encoded_len` is what a caller sizes its buffer by, so it has to be
    /// exactly what an encode writes.
    #[test]
    fn encoded_len_is_what_gets_written() {
        let builder = PacketBuilder::new()
            .ethernet(EthernetHeader::new([0; 6], [0; 6], 0))
            .ipv4(Ipv4Header::new(
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
                0,
                0,
            ))
            .udp(UdpHeader::new(1, 2, 0));

        for payload_len in 0..40 {
            let payload = vec![0xab; payload_len];
            let needed = builder.encoded_len(payload_len);
            let mut buffer = vec![0; needed];
            assert_eq!(
                builder.encode_into(&mut buffer, &payload).expect("room"),
                needed,
                "payload of {payload_len}"
            );
            let mut short = vec![0; needed - 1];
            assert!(builder.encode_into(&mut short, &payload).is_err());
        }
    }
}
