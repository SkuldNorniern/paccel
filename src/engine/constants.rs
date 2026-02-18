pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const VLAN_8021Q: u16 = 0x8100;
    pub const IPV6: u16 = 0x86DD;
    pub const MPLS_UNICAST: u16 = 0x8847;
    pub const MPLS_MULTICAST: u16 = 0x8848;
    pub const PPPOE_DISCOVERY: u16 = 0x8863;
    pub const PPPOE_SESSION: u16 = 0x8864;
    pub const QINQ_8021AD: u16 = 0x88A8;
    pub const LLDP: u16 = 0x88CC;
    pub const PTP_1588: u16 = 0x88F7;
}

pub mod ip_proto {
    pub const ICMP: u8 = 1;
    pub const IGMP: u8 = 2;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const GRE: u8 = 47;
    pub const ESP: u8 = 50;
    pub const AH: u8 = 51;
    pub const ICMPV6: u8 = 58;
    pub const OSPF: u8 = 89;
    pub const PIM: u8 = 103;
    pub const VRRP: u8 = 112;
    pub const L2TP: u8 = 115;
    pub const SCTP: u8 = 132;
    pub const MPLS_IN_IP: u8 = 137;
}

pub fn ethertype_name(value: u16) -> &'static str {
    match value {
        ethertype::IPV4 => "ipv4",
        ethertype::ARP => "arp",
        ethertype::VLAN_8021Q => "vlan",
        ethertype::IPV6 => "ipv6",
        ethertype::MPLS_UNICAST => "mpls-unicast",
        ethertype::MPLS_MULTICAST => "mpls-multicast",
        ethertype::PPPOE_DISCOVERY => "pppoe-discovery",
        ethertype::PPPOE_SESSION => "pppoe-session",
        ethertype::QINQ_8021AD => "qinq",
        ethertype::LLDP => "lldp",
        ethertype::PTP_1588 => "ptp",
        _ => "unknown",
    }
}

pub fn ip_protocol_name(value: u8) -> &'static str {
    match value {
        ip_proto::ICMP => "icmp",
        ip_proto::IGMP => "igmp",
        ip_proto::TCP => "tcp",
        ip_proto::UDP => "udp",
        ip_proto::GRE => "gre",
        ip_proto::ESP => "esp",
        ip_proto::AH => "ah",
        ip_proto::ICMPV6 => "icmpv6",
        ip_proto::OSPF => "ospf",
        ip_proto::PIM => "pim",
        ip_proto::VRRP => "vrrp",
        ip_proto::L2TP => "l2tp",
        ip_proto::SCTP => "sctp",
        ip_proto::MPLS_IN_IP => "mpls-in-ip",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{ethertype, ethertype_name, ip_proto, ip_protocol_name};

    #[test]
    fn ethertype_names_cover_known_values() {
        assert_eq!(ethertype_name(ethertype::IPV4), "ipv4");
        assert_eq!(ethertype_name(ethertype::MPLS_UNICAST), "mpls-unicast");
        assert_eq!(ethertype_name(0x1234), "unknown");
    }

    #[test]
    fn ip_protocol_names_cover_known_values() {
        assert_eq!(ip_protocol_name(ip_proto::TCP), "tcp");
        assert_eq!(ip_protocol_name(ip_proto::AH), "ah");
        assert_eq!(ip_protocol_name(250), "unknown");
    }
}
