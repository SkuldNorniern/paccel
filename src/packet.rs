use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub enum PacketError {
    InvalidHeader,
    UnsupportedProtocol,
    MalformedPacket,
    InvalidChecksum,
    InvalidLength,
    LayerError(String),
    // Add more specific errors as needed
}

#[derive(Debug)]
pub struct Packet {
    pub packet: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new(packet: Vec<u8>, payload: Vec<u8>) -> Self {
        Self { packet, payload }
    }
}