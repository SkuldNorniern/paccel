use std::net::Ipv4Addr;

/// ARP operation codes.
#[derive(Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    Unknown(u16),
}

impl ArpOperation {
    pub fn to_u16(&self) -> u16 {
        match *self {
            ArpOperation::Request => 1,
            ArpOperation::Reply => 2,
            ArpOperation::Unknown(code) => code,
        }
    }
}

/// An ARP packet for IPv4 over Ethernet.
#[derive(Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_len: u8,
    pub protocol_len: u8,
    pub operation: ArpOperation,
    pub sender_hardware_addr: [u8; 6],
    pub sender_protocol_addr: Ipv4Addr,
    pub target_hardware_addr: [u8; 6],
    pub target_protocol_addr: Ipv4Addr,
}

impl ArpPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(28);
        bytes.extend_from_slice(&self.hardware_type.to_be_bytes());
        bytes.extend_from_slice(&self.protocol_type.to_be_bytes());
        bytes.push(self.hardware_len);
        bytes.push(self.protocol_len);
        bytes.extend_from_slice(&self.operation.to_u16().to_be_bytes());
        bytes.extend_from_slice(&self.sender_hardware_addr);
        bytes.extend_from_slice(&self.sender_protocol_addr.octets());
        bytes.extend_from_slice(&self.target_hardware_addr);
        bytes.extend_from_slice(&self.target_protocol_addr.octets());
        bytes
    }
}
