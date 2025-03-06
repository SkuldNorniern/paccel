use std::fmt;

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
    pub network_offset: usize,
}

impl Packet {
    pub fn new(packet: Vec<u8>) -> Self {
        Self {
            packet,
            payload: Vec::new(),
            network_offset: 0, // Will be set during parsing
        }
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format packet data in hex dump format similar to Wireshark
        let mut offset = 0;

        while offset < self.packet.len() {
            // Print offset in hex
            write!(f, "{:04x}   ", offset)?;

            // Print up to 16 bytes in hex
            let mut hex_part = String::new();
            let mut ascii_part = String::new();

            for i in 0..16 {
                if offset + i < self.packet.len() {
                    let byte = self.packet[offset + i];
                    hex_part.push_str(&format!("{:02x} ", byte));

                    // Add printable ASCII character or dot for non-printable
                    ascii_part.push(if (32..=126).contains(&byte) {
                        byte as char
                    } else {
                        '.'
                    });
                } else {
                    hex_part.push_str("   ");
                }
            }

            // Write the line with hex and ASCII parts
            writeln!(f, "{:<48}  {}", hex_part, ascii_part)?;

            offset += 16;
        }
        Ok(())
    }
}
