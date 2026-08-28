use std::net::Ipv6Addr;

/// IPv6 fixed header fields defined by RFC 8200.
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    /// Fixed header's `Next Header` value. With extensions, this identifies the
    /// first extension; `resolved_next_header` identifies the transport protocol.
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    /// Transport protocol after extension headers. Defaults to `next_header`
    /// when resolution was skipped, such as at `StopLayer::Network`.
    pub resolved_next_header: u8,
    /// Transport header offset from the IPv6 header start. Defaults to `40`
    /// when extension resolution was skipped.
    pub transport_header_offset: u16,
}
