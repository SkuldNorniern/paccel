use std::net::Ipv4Addr;

/// IPv4 header fields defined by RFC 791.
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: Option<Vec<u8>>,
    /// The header declared options the capture did not keep.
    ///
    /// The fixed twenty bytes carry both addresses, so a header cut short in
    /// its options is still worth reporting. `options` is `None` here for the
    /// same reason it is `None` when there were none at all; this says which
    /// of the two it was.
    pub options_truncated: bool,
}
