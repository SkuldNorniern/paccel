/// Basic ICMP header fields.
#[derive(Debug, Default)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub rest_of_header: [u8; 4],
}

impl IcmpHeader {
    pub fn echo_identifier(&self) -> Option<u16> {
        matches!(self.icmp_type, 0 | 8)
            .then(|| u16::from_be_bytes([self.rest_of_header[0], self.rest_of_header[1]]))
    }

    pub fn echo_sequence(&self) -> Option<u16> {
        matches!(self.icmp_type, 0 | 8)
            .then(|| u16::from_be_bytes([self.rest_of_header[2], self.rest_of_header[3]]))
    }
}
