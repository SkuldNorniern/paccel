use std::net::Ipv6Addr;

/// IPv6 fixed header fields defined by RFC 8200.
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    /// `Next Header` value from the fixed header itself. When extension
    /// headers are present this identifies the first extension header, NOT
    /// the transport protocol - use `resolved_next_header` for that.
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    /// Transport-layer protocol after walking any extension headers (equal
    /// to `next_header` when there are none). Defaults to `next_header` when
    /// extension-header resolution wasn't performed (e.g. `StopLayer::Network`).
    pub resolved_next_header: u8,
    /// Byte offset from the start of this IPv6 header to the transport
    /// header, i.e. `40 + total extension header bytes`. Defaults to `40`
    /// when extension-header resolution wasn't performed.
    pub transport_header_offset: u16,
}
