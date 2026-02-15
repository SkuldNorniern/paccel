use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy)]
pub struct EthernetPacket<'a> {
    data: &'a [u8],
    ethertype: u16,
    payload_offset: usize,
}

impl<'a> EthernetPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        let mut offset = 12usize;
        let mut ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        while ethertype == 0x8100 || ethertype == 0x88A8 {
            if data.len() < offset + 4 {
                return None;
            }
            ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        }

        Some(Self {
            data,
            ethertype,
            payload_offset: offset,
        })
    }

    pub fn destination(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out.copy_from_slice(&self.data[0..6]);
        out
    }

    pub fn source(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out.copy_from_slice(&self.data[6..12]);
        out
    }

    pub fn ethertype(&self) -> u16 {
        self.ethertype
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.payload_offset..]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<'a> {
    data: &'a [u8],
    header_len: usize,
    total_len: usize,
}

impl<'a> Ipv4Packet<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let version = data[0] >> 4;
        let ihl = data[0] & 0x0f;
        if version != 4 || ihl < 5 {
            return None;
        }
        let header_len = (ihl as usize) * 4;
        if data.len() < header_len {
            return None;
        }
        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if total_len < header_len || data.len() < total_len {
            return None;
        }
        Some(Self {
            data,
            header_len,
            total_len,
        })
    }

    pub fn protocol(&self) -> u8 {
        self.data[9]
    }

    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[12], self.data[13], self.data[14], self.data[15])
    }

    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[16], self.data[17], self.data[18], self.data[19])
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.header_len..self.total_len]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6Packet<'a> {
    data: &'a [u8],
    total_len: usize,
}

impl<'a> Ipv6Packet<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 40 {
            return None;
        }
        let version = data[0] >> 4;
        if version != 6 {
            return None;
        }
        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let total_len = 40 + payload_len;
        if data.len() < total_len {
            return None;
        }
        Some(Self { data, total_len })
    }

    pub fn next_header(&self) -> u8 {
        self.data[6]
    }

    pub fn source(&self) -> Ipv6Addr {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.data[8..24]);
        Ipv6Addr::from(out)
    }

    pub fn destination(&self) -> Ipv6Addr {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.data[24..40]);
        Ipv6Addr::from(out)
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[40..self.total_len]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UdpPacket<'a> {
    data: &'a [u8],
    len: usize,
}

impl<'a> UdpPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if len < 8 || data.len() < len {
            return None;
        }
        Some(Self { data, len })
    }

    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[8..self.len]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpPacket<'a> {
    data: &'a [u8],
    header_len: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ArpPacket<'a> {
    data: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }
        if data[4] != 6 || data[5] != 4 {
            return None;
        }
        Some(Self { data })
    }

    pub fn operation(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    pub fn sender_hardware_addr(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out.copy_from_slice(&self.data[8..14]);
        out
    }

    pub fn sender_protocol_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[14], self.data[15], self.data[16], self.data[17])
    }

    pub fn target_hardware_addr(&self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out.copy_from_slice(&self.data[18..24]);
        out
    }

    pub fn target_protocol_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[24], self.data[25], self.data[26], self.data[27])
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DnsPacket<'a> {
    data: &'a [u8],
}

impl<'a> DnsPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        Some(Self { data })
    }

    pub fn transaction_id(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn flags(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn is_response(&self) -> bool {
        (self.flags() & 0x8000) != 0
    }

    pub fn question_count(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    pub fn answer_count(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    pub fn authority_count(&self) -> u16 {
        u16::from_be_bytes([self.data[8], self.data[9]])
    }

    pub fn additional_count(&self) -> u16 {
        u16::from_be_bytes([self.data[10], self.data[11]])
    }
}

impl<'a> TcpPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let data_offset = (data[12] >> 4) as usize;
        if data_offset < 5 {
            return None;
        }
        let header_len = data_offset * 4;
        if data.len() < header_len {
            return None;
        }
        Some(Self { data, header_len })
    }

    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.header_len..]
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArpPacket, DnsPacket, EthernetPacket, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
    };

    #[test]
    fn ethernet_ipv4_udp_views_work() {
        let frame = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, // eth
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0,
            2, // ipv4
            0x04, 0xd2, 0x16, 0x2e, 0x00, 0x08, 0x00, 0x00, // udp
        ];

        let eth = EthernetPacket::new(&frame).expect("ethernet should parse");
        assert_eq!(eth.ethertype(), 0x0800);

        let ip = Ipv4Packet::new(eth.payload()).expect("ipv4 should parse");
        assert_eq!(ip.protocol(), 17);

        let udp = UdpPacket::new(ip.payload()).expect("udp should parse");
        assert_eq!(udp.source_port(), 1234);
        assert_eq!(udp.destination_port(), 5678);
    }

    #[test]
    fn ipv6_tcp_views_work() {
        let mut packet = vec![0u8; 40 + 20];
        packet[0] = 0x60;
        packet[4] = 0;
        packet[5] = 20;
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40..60].copy_from_slice(&[
            0x00, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x10, 0x10, 0x00, 0, 0, 0, 0,
        ]);

        let ip6 = Ipv6Packet::new(&packet).expect("ipv6 should parse");
        assert_eq!(ip6.next_header(), 6);

        let tcp = TcpPacket::new(ip6.payload()).expect("tcp should parse");
        assert_eq!(tcp.source_port(), 80);
        assert_eq!(tcp.destination_port(), 443);
    }

    #[test]
    fn arp_view_works() {
        let arp = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // fixed
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, // sha
            192, 168, 1, 1, // spa
            0, 0, 0, 0, 0, 0, // tha
            192, 168, 1, 2, // tpa
        ];

        let pkt = ArpPacket::new(&arp).expect("arp should parse");
        assert_eq!(pkt.operation(), 1);
        assert_eq!(pkt.sender_protocol_addr().octets(), [192, 168, 1, 1]);
        assert_eq!(pkt.target_protocol_addr().octets(), [192, 168, 1, 2]);
    }

    #[test]
    fn dns_view_works() {
        let dns = [
            0x12, 0x34, 0x81, 0x80, // id/flags
            0x00, 0x01, 0x00, 0x02, // qd/an
            0x00, 0x00, 0x00, 0x01, // ns/ar
        ];

        let pkt = DnsPacket::new(&dns).expect("dns should parse");
        assert_eq!(pkt.transaction_id(), 0x1234);
        assert!(pkt.is_response());
        assert_eq!(pkt.question_count(), 1);
        assert_eq!(pkt.answer_count(), 2);
        assert_eq!(pkt.additional_count(), 1);
    }
}
