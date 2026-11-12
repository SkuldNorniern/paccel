use std::net::Ipv4Addr;

use super::{Encode, EncodeError, WriteCursor};

/// An ARP packet for IPv4 over Ethernet, the only pairing in common use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArpHeader {
    pub operation: u16,
    pub sender_hardware_addr: [u8; 6],
    pub sender_protocol_addr: Ipv4Addr,
    pub target_hardware_addr: [u8; 6],
    pub target_protocol_addr: Ipv4Addr,
}

impl ArpHeader {
    pub fn request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        Self {
            operation: 1,
            sender_hardware_addr: sender_mac,
            sender_protocol_addr: sender_ip,
            target_hardware_addr: [0; 6],
            target_protocol_addr: target_ip,
        }
    }
}

impl Encode for ArpHeader {
    fn encoded_len(&self) -> usize {
        28
    }

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let mut cursor = WriteCursor::new(buffer);
        cursor.write_u16_be(1)?;
        cursor.write_u16_be(0x0800)?;
        cursor.write_u8(6)?;
        cursor.write_u8(4)?;
        cursor.write_u16_be(self.operation)?;
        cursor.write_bytes(&self.sender_hardware_addr)?;
        cursor.write_bytes(&self.sender_protocol_addr.octets())?;
        cursor.write_bytes(&self.target_hardware_addr)?;
        cursor.write_bytes(&self.target_protocol_addr.octets())?;
        Ok(cursor.position())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{ArpHeader, Encode};
    use crate::craft::EthernetHeader;
    use crate::engine::BuiltinPacketParser;

    #[test]
    fn a_crafted_arp_request_parses_back() {
        let arp = ArpHeader::request(
            [0x11; 6],
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
        );
        let mut frame = EthernetHeader::new([0xff; 6], [0x11; 6], 0x0806)
            .build()
            .expect("room");
        frame.extend(arp.build().expect("room"));

        let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
        let parsed = parsed.arp.as_ref().expect("the ARP packet");
        assert_eq!(parsed.sender_protocol_addr, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(parsed.target_protocol_addr, Ipv4Addr::new(192, 0, 2, 2));
        assert_eq!(parsed.sender_hardware_addr, [0x11; 6]);
    }
}
