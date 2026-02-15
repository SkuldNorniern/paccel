use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy)]
pub struct EthernetPacket<'a> {
    data: &'a [u8],
    ethertype: u16,
    payload_offset: usize,
    vlan_depth: u8,
    outer_vlan_tag: Option<u16>,
    inner_vlan_tag: Option<u16>,
}

impl<'a> EthernetPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }

        let mut offset = 12usize;
        let mut ethertype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        let mut vlan_depth = 0u8;
        let mut outer_vlan_tag = None;
        let mut inner_vlan_tag = None;

        while ethertype == 0x8100 || ethertype == 0x88A8 {
            if data.len() < offset + 4 {
                return None;
            }
            let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
            vlan_depth = vlan_depth.saturating_add(1);
            if outer_vlan_tag.is_none() {
                outer_vlan_tag = Some(tci);
            } else if inner_vlan_tag.is_none() {
                inner_vlan_tag = Some(tci);
            }
            ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        }

        Some(Self {
            data,
            ethertype,
            payload_offset: offset,
            vlan_depth,
            outer_vlan_tag,
            inner_vlan_tag,
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

    pub fn has_vlan(&self) -> bool {
        self.vlan_depth > 0
    }

    pub fn vlan_depth(&self) -> u8 {
        self.vlan_depth
    }

    pub fn outer_vlan_tag(&self) -> Option<u16> {
        self.outer_vlan_tag
    }

    pub fn inner_vlan_tag(&self) -> Option<u16> {
        self.inner_vlan_tag
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

#[derive(Debug, Clone, Copy)]
pub struct IcmpPacket<'a> {
    data: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self { data })
    }

    pub fn icmp_type(&self) -> u8 {
        self.data[0]
    }

    pub fn code(&self) -> u8 {
        self.data[1]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[4..]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Icmpv6Packet<'a> {
    data: &'a [u8],
}

impl<'a> Icmpv6Packet<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        Some(Self { data })
    }

    pub fn icmp_type(&self) -> u8 {
        self.data[0]
    }

    pub fn code(&self) -> u8 {
        self.data[1]
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[4..]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SllPacket<'a> {
    data: &'a [u8],
}

impl<'a> SllPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        Some(Self { data })
    }

    pub fn packet_type(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn arphrd_type(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    pub fn address_length(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes([self.data[14], self.data[15]])
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[16..]
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Sll2Packet<'a> {
    data: &'a [u8],
}

impl<'a> Sll2Packet<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        Some(Self { data })
    }

    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    pub fn if_index(&self) -> u32 {
        u32::from_be_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    pub fn arphrd_type(&self) -> u16 {
        u16::from_be_bytes([self.data[8], self.data[9]])
    }

    pub fn packet_type(&self) -> u8 {
        self.data[10]
    }

    pub fn address_length(&self) -> u8 {
        self.data[11]
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[20..]
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArpPacket, DnsPacket, EthernetPacket, IcmpPacket, Icmpv6Packet, Ipv4Packet, Ipv6Packet,
        Sll2Packet, SllPacket, TcpPacket, UdpPacket,
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
        assert!(!eth.has_vlan());

        let ip = Ipv4Packet::new(eth.payload()).expect("ipv4 should parse");
        assert_eq!(ip.protocol(), 17);

        let udp = UdpPacket::new(ip.payload()).expect("udp should parse");
        assert_eq!(udp.source_port(), 1234);
        assert_eq!(udp.destination_port(), 5678);
    }

    #[test]
    fn ethernet_vlan_helpers_work() {
        let frame = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, // vlan ethertype
            0x00, 0x64, // vlan tag
            0x08, 0x00, // inner ethertype
            0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];

        let eth = EthernetPacket::new(&frame).expect("ethernet should parse");
        assert!(eth.has_vlan());
        assert_eq!(eth.vlan_depth(), 1);
        assert_eq!(eth.outer_vlan_tag(), Some(0x0064));
        assert_eq!(eth.inner_vlan_tag(), None);
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

    #[test]
    fn icmp_views_work() {
        let icmp = [8, 0, 0x12, 0x34, 1, 2, 3, 4];
        let pkt = IcmpPacket::new(&icmp).expect("icmp should parse");
        assert_eq!(pkt.icmp_type(), 8);
        assert_eq!(pkt.code(), 0);
        assert_eq!(pkt.checksum(), 0x1234);
        assert_eq!(pkt.payload(), &[1, 2, 3, 4]);

        let icmp6 = [128, 0, 0xab, 0xcd, 9, 8, 7, 6];
        let pkt6 = Icmpv6Packet::new(&icmp6).expect("icmpv6 should parse");
        assert_eq!(pkt6.icmp_type(), 128);
        assert_eq!(pkt6.code(), 0);
        assert_eq!(pkt6.checksum(), 0xabcd);
        assert_eq!(pkt6.payload(), &[9, 8, 7, 6]);
    }

    #[test]
    fn sll_view_works() {
        let frame = [
            0x00, 0x00, // packet type
            0x00, 0x01, // arphrd ethernet
            0x00, 0x06, // address length
            0, 1, 2, 3, 4, 5, 0, 0, // address (8)
            0x08, 0x00, // protocol ipv4
            0x45, 0x00, 0x00, 0x14, // payload begins
        ];

        let sll = SllPacket::new(&frame).expect("sll should parse");
        assert_eq!(sll.packet_type(), 0);
        assert_eq!(sll.arphrd_type(), 1);
        assert_eq!(sll.address_length(), 6);
        assert_eq!(sll.protocol(), 0x0800);
        assert_eq!(sll.payload()[0], 0x45);
    }

    #[test]
    fn sll2_view_works() {
        let frame = [
            0x86, 0xdd, // protocol ipv6
            0x00, 0x00, // reserved
            0x00, 0x00, 0x00, 0x02, // ifindex
            0x00, 0x01, // arphrd ethernet
            0x00, // packet type
            0x06, // address length
            0, 1, 2, 3, 4, 5, 0, 0, // address (8)
            0x60, 0x00, 0x00, 0x00, // payload begins
        ];

        let sll2 = Sll2Packet::new(&frame).expect("sll2 should parse");
        assert_eq!(sll2.protocol(), 0x86dd);
        assert_eq!(sll2.if_index(), 2);
        assert_eq!(sll2.arphrd_type(), 1);
        assert_eq!(sll2.packet_type(), 0);
        assert_eq!(sll2.address_length(), 6);
        assert_eq!(sll2.payload()[0], 0x60);
    }
}
