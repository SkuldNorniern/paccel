use std::fmt;

use super::metadata::PacketMetadata;

#[derive(Debug)]
pub enum PacketError {
    InvalidHeader,
    UnsupportedProtocol,
    MalformedPacket,
    InvalidChecksum,
    InvalidLength,
    LayerError(String),
}

#[derive(Debug)]
pub struct Packet {
    pub packet: Vec<u8>,
    pub payload: Vec<u8>,
    pub network_offset: usize,
    pub metadata: PacketMetadata,
}

impl Packet {
    pub fn new(packet: Vec<u8>) -> Self {
        Self {
            packet,
            payload: Vec::new(),
            network_offset: 0,
            metadata: PacketMetadata::default(),
        }
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut offset = 0;

        while offset < self.packet.len() {
            write!(f, "{:04x}   ", offset)?;

            let mut hex_part = String::new();
            let mut ascii_part = String::new();

            for i in 0..16 {
                if offset + i < self.packet.len() {
                    let byte = self.packet[offset + i];
                    hex_part.push_str(&format!("{:02x} ", byte));

                    ascii_part.push(if (32..=126).contains(&byte) {
                        byte as char
                    } else {
                        '.'
                    });
                } else {
                    hex_part.push_str("   ");
                }
            }

            writeln!(f, "{:<48}  {}", hex_part, ascii_part)?;
            offset += 16;
        }

        Ok(())
    }
}
