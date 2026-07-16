use std::net::Ipv6Addr;

/// Basic ICMPv6 header fields.
#[derive(Debug, Default)]
pub struct Icmpv6Header {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub rest_of_header: [u8; 4],
}

impl Icmpv6Header {
    pub fn echo_identifier(&self) -> Option<u16> {
        matches!(self.icmp_type, 128 | 129)
            .then(|| u16::from_be_bytes([self.rest_of_header[0], self.rest_of_header[1]]))
    }

    pub fn echo_sequence(&self) -> Option<u16> {
        matches!(self.icmp_type, 128 | 129)
            .then(|| u16::from_be_bytes([self.rest_of_header[2], self.rest_of_header[3]]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpOption {
    pub option_type: u8,
    pub data: Vec<u8>,
}

impl NdpOption {
    pub fn source_link_addr(&self) -> Option<&[u8]> {
        (self.option_type == 1).then_some(self.data.as_slice())
    }

    pub fn target_link_addr(&self) -> Option<&[u8]> {
        (self.option_type == 2).then_some(self.data.as_slice())
    }

    pub fn prefix_information(&self) -> Option<&[u8]> {
        (self.option_type == 3).then_some(self.data.as_slice())
    }

    pub fn mtu(&self) -> Option<u32> {
        if self.option_type != 5 || self.data.len() < 6 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.data[2],
            self.data[3],
            self.data[4],
            self.data[5],
        ]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdpMessage {
    RouterSolicitation {
        options: Vec<NdpOption>,
    },
    RouterAdvertisement {
        cur_hop_limit: u8,
        flags: u8,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
        options: Vec<NdpOption>,
    },
    NeighborSolicitation {
        target: Ipv6Addr,
        options: Vec<NdpOption>,
    },
    NeighborAdvertisement {
        flags: u8,
        target: Ipv6Addr,
        options: Vec<NdpOption>,
    },
    Redirect {
        target: Ipv6Addr,
        destination: Ipv6Addr,
        options: Vec<NdpOption>,
    },
}

/// Parses an NDP message body beginning after the ICMPv6 type, code, and checksum.
pub fn parse_ndp(icmp_type: u8, body: &[u8]) -> Option<NdpMessage> {
    match icmp_type {
        133 if body.len() >= 4 => Some(NdpMessage::RouterSolicitation {
            options: parse_ndp_options(&body[4..]),
        }),
        134 if body.len() >= 12 => Some(NdpMessage::RouterAdvertisement {
            cur_hop_limit: body[0],
            flags: body[1],
            router_lifetime: u16::from_be_bytes([body[2], body[3]]),
            reachable_time: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            retrans_timer: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
            options: parse_ndp_options(&body[12..]),
        }),
        135 if body.len() >= 20 => Some(NdpMessage::NeighborSolicitation {
            target: ipv6_addr(&body[4..20]),
            options: parse_ndp_options(&body[20..]),
        }),
        136 if body.len() >= 20 => Some(NdpMessage::NeighborAdvertisement {
            flags: body[0],
            target: ipv6_addr(&body[4..20]),
            options: parse_ndp_options(&body[20..]),
        }),
        137 if body.len() >= 36 => Some(NdpMessage::Redirect {
            target: ipv6_addr(&body[4..20]),
            destination: ipv6_addr(&body[20..36]),
            options: parse_ndp_options(&body[36..]),
        }),
        _ => None,
    }
}

fn parse_ndp_options(data: &[u8]) -> Vec<NdpOption> {
    let mut options = Vec::new();
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let option_type = data[offset];
        let length_units = usize::from(data[offset + 1]);
        if length_units == 0 {
            break;
        }
        let option_len = length_units * 8;
        if option_len > data.len() - offset {
            break;
        }
        options.push(NdpOption {
            option_type,
            data: data[offset + 2..offset + option_len].to_vec(),
        });
        offset += option_len;
    }

    options
}

fn ipv6_addr(data: &[u8]) -> Ipv6Addr {
    Ipv6Addr::from(<[u8; 16]>::try_from(data).expect("fixed-length IPv6 address"))
}
