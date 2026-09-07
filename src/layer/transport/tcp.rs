/// TCP flags defined by RFC 793 and later extensions.
#[derive(Debug, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

/// TCP header fields.
#[derive(Debug)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Option<Vec<u8>>,
    /// The data offset named more header than the capture kept, so `options`
    /// holds only the bytes that survived.
    ///
    /// The twenty fixed bytes are all present regardless: only the option list
    /// is short. Mirrors the IPv4 header's own `options_truncated`.
    pub options_truncated: bool,
}
