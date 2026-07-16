//! Opt-in TCP session tracking and streaming application-layer probing.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::engine::{BuiltinPacketParser, ParsedPacket, TcpStreamReassembler, TransportSegment};
use crate::layer::application::http::{HttpMessage, parse_http};
use crate::layer::application::tls::{TlsClientHello, parse_tls_client_hello};
use crate::layer::transport::tcp::TcpHeader;

const DEFAULT_MAX_PROBE_BYTES: usize = 65_536;

/// An application-layer message recognized in a reassembled TCP stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamL7 {
    /// An HTTP/1.x request or response.
    Http(HttpMessage),
    /// A TLS ClientHello.
    Tls(TlsClientHello),
}

/// A message recognized in one direction of a TCP flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamEvent {
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub l7: StreamL7,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    address: IpAddr,
    port: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    first: Endpoint,
    second: Endpoint,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DirectionKey {
    flow: FlowKey,
    direction: usize,
}

#[derive(Debug, Default)]
struct ProbeState {
    bytes: Vec<u8>,
    done: bool,
}

/// Reassembles TCP payloads and probes each direction once for HTTP or TLS.
#[derive(Debug)]
pub struct SessionTracker {
    tcp: TcpStreamReassembler,
    probes: HashMap<DirectionKey, ProbeState>,
    max_probe_bytes: usize,
}

impl SessionTracker {
    /// Creates a tracker with a 65,536-byte application probe cap per direction.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_PROBE_BYTES)
    }

    /// Creates a tracker with a caller-supplied application probe cap per direction.
    #[must_use]
    pub fn with_limits(max_probe_bytes: usize) -> Self {
        Self {
            tcp: TcpStreamReassembler::new(),
            probes: HashMap::new(),
            max_probe_bytes,
        }
    }

    /// Offers an Ethernet frame and returns the first HTTP or TLS message found in its direction.
    pub fn offer_frame(&mut self, raw: &[u8]) -> Option<StreamEvent> {
        let parsed = BuiltinPacketParser::parse(raw).ok()?;
        let (src, dst) = ip_endpoints(&parsed)?;
        let tcp = match parsed.transport.as_ref()? {
            TransportSegment::Tcp(tcp) => tcp,
            TransportSegment::Udp(_) => return None,
        };
        let payload = tcp_payload(raw, &parsed, tcp)?;
        let src_port = tcp.source_port;
        let dst_port = tcp.destination_port;
        let key = direction_key(src, src_port, dst, dst_port);

        let contiguous = self.tcp.offer(
            src,
            src_port,
            dst,
            dst_port,
            tcp.sequence_number,
            tcp.flags.syn,
            tcp.flags.fin,
            payload,
        );

        let state = self.probes.entry(key).or_default();
        if state.done {
            return None;
        }
        let remaining = self.max_probe_bytes.saturating_sub(state.bytes.len());
        let append_len = remaining.min(contiguous.len());
        if let Some(bytes) = contiguous.get(..append_len) {
            state.bytes.extend_from_slice(bytes);
        }

        let l7 = probe_l7(&state.bytes)?;
        state.done = true;
        state.bytes.clear();
        state.bytes.shrink_to_fit();
        Some(StreamEvent {
            src,
            src_port,
            dst,
            dst_port,
            l7,
        })
    }

    /// Removes both directions of a flow, returning whether any state existed.
    pub fn remove_flow(&mut self, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> bool {
        let flow = normalized_flow(src, src_port, dst, dst_port);
        let previous_len = self.probes.len();
        self.probes.retain(|key, _| key.flow != flow);
        self.tcp.remove_flow(src, src_port, dst, dst_port) || self.probes.len() != previous_len
    }

    /// Releases all TCP and application probe state.
    pub fn clear(&mut self) {
        self.tcp.clear();
        self.probes.clear();
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn ip_endpoints(parsed: &ParsedPacket) -> Option<(IpAddr, IpAddr)> {
    if let Some(ipv4) = parsed.ipv4.as_ref() {
        Some((IpAddr::V4(ipv4.source), IpAddr::V4(ipv4.destination)))
    } else {
        parsed
            .ipv6
            .as_ref()
            .map(|ipv6| (IpAddr::V6(ipv6.source), IpAddr::V6(ipv6.destination)))
    }
}

fn tcp_payload<'a>(raw: &'a [u8], parsed: &ParsedPacket, tcp: &TcpHeader) -> Option<&'a [u8]> {
    let l3_offset = parsed.ethernet.as_ref()?.payload_offset;
    let (ip_header_len, ip_packet_len) = if let Some(ipv4) = parsed.ipv4.as_ref() {
        (
            usize::from(ipv4.ihl).checked_mul(4)?,
            usize::from(ipv4.total_length),
        )
    } else {
        let ipv6 = parsed.ipv6.as_ref()?;
        (40, 40usize.checked_add(usize::from(ipv6.payload_length))?)
    };
    let ip_end = l3_offset.checked_add(ip_packet_len)?.min(raw.len());
    let tcp_offset = l3_offset.checked_add(ip_header_len)?;
    let tcp_header_len = usize::from(tcp.data_offset).checked_mul(4)?;
    let payload_offset = tcp_offset.checked_add(tcp_header_len)?;
    raw.get(payload_offset..ip_end)
}

fn probe_l7(bytes: &[u8]) -> Option<StreamL7> {
    let first = *bytes.first()?;
    if first.is_ascii_uppercase()
        && http_headers_complete(bytes)
        && let Ok(http) = parse_http(bytes)
    {
        return Some(StreamL7::Http(http));
    }
    if first == 22
        && tls_record_complete(bytes)
        && let Ok(tls) = parse_tls_client_hello(bytes)
    {
        return Some(StreamL7::Tls(tls));
    }
    None
}

fn http_headers_complete(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|window| window == b"\r\n\r\n")
}

fn tls_record_complete(bytes: &[u8]) -> bool {
    let Some(length_bytes) = bytes.get(3..5) else {
        return false;
    };
    let record_length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    5usize
        .checked_add(record_length)
        .is_some_and(|record_end| record_end <= bytes.len())
}

fn direction_key(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> DirectionKey {
    let source = Endpoint {
        address: src,
        port: src_port,
    };
    let destination = Endpoint {
        address: dst,
        port: dst_port,
    };
    if source <= destination {
        DirectionKey {
            flow: FlowKey {
                first: source,
                second: destination,
            },
            direction: 0,
        }
    } else {
        DirectionKey {
            flow: FlowKey {
                first: destination,
                second: source,
            },
            direction: 1,
        }
    }
}

fn normalized_flow(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> FlowKey {
    direction_key(src, src_port, dst, dst_port).flow
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const SRC_PORT: u16 = 49_152;
    const DST_PORT: u16 = 443;

    fn tcp_frame(sequence: u32, syn: bool, payload: &[u8]) -> Vec<u8> {
        let tcp_len = 20usize.saturating_add(payload.len());
        let ip_len = 20usize.saturating_add(tcp_len);
        let ip_len = u16::try_from(ip_len).unwrap_or(u16::MAX);
        let mut frame = Vec::with_capacity(14 + usize::from(ip_len));
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.extend_from_slice(&[0x45, 0]);
        frame.extend_from_slice(&ip_len.to_be_bytes());
        frame.extend_from_slice(&0x1234u16.to_be_bytes());
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.extend_from_slice(&[64, 6, 0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&[10, 0, 0, 2]);

        frame.extend_from_slice(&SRC_PORT.to_be_bytes());
        frame.extend_from_slice(&DST_PORT.to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.push(0x50);
        frame.push(if syn { 0x02 } else { 0x18 });
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(payload);
        frame
    }

    fn tls_client_hello() -> Vec<u8> {
        let server_name = b"example.com";
        let server_name_list_len = 3usize.saturating_add(server_name.len());
        let extension_data_len = 2usize.saturating_add(server_name_list_len);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(
            &u16::try_from(extension_data_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        extensions.extend_from_slice(
            &u16::try_from(server_name_list_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        extensions.push(0);
        extensions.extend_from_slice(
            &u16::try_from(server_name.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        extensions.extend_from_slice(server_name);

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0x42; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.extend_from_slice(&[1, 0]);
        hello.extend_from_slice(
            &u16::try_from(extensions.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        hello.extend_from_slice(&extensions);

        let handshake_len = u32::try_from(hello.len()).unwrap_or(u32::MAX);
        let handshake_len_bytes = handshake_len.to_be_bytes();
        let record_len = 4usize.saturating_add(hello.len());
        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&u16::try_from(record_len).unwrap_or(u16::MAX).to_be_bytes());
        record.push(1);
        record.extend_from_slice(&handshake_len_bytes[1..]);
        record.extend_from_slice(&hello);
        record
    }

    #[test]
    fn parses_http_across_tcp_segments() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let split = 12;
        let first = tcp_frame(1_000, false, &payload[..split]);
        let second = tcp_frame(
            1_000u32.saturating_add(u32::try_from(split).unwrap_or(u32::MAX)),
            false,
            &payload[split..],
        );
        let mut tracker = SessionTracker::new();

        assert!(tracker.offer_frame(&first).is_none());
        let event = tracker.offer_frame(&second).expect("HTTP stream event");
        match event.l7 {
            StreamL7::Http(HttpMessage::Request { target, host, .. }) => {
                assert_eq!(target, "/index.html");
                assert_eq!(host.as_deref(), Some("example.com"));
            }
            _ => panic!("expected HTTP request"),
        }
    }

    #[test]
    fn parses_tls_client_hello_across_tcp_segments() {
        let payload = tls_client_hello();
        let split = 12;
        let first = tcp_frame(2_000, false, &payload[..split]);
        let second = tcp_frame(
            2_000u32.saturating_add(u32::try_from(split).unwrap_or(u32::MAX)),
            false,
            &payload[split..],
        );
        let mut tracker = SessionTracker::new();

        assert!(tracker.offer_frame(&first).is_none());
        let event = tracker.offer_frame(&second).expect("TLS stream event");
        match event.l7 {
            StreamL7::Tls(hello) => {
                assert_eq!(hello.server_name.as_deref(), Some("example.com"));
            }
            StreamL7::Http(_) => panic!("expected TLS ClientHello"),
        }
    }

    #[test]
    fn parses_out_of_order_segments_after_syn() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let split = 12;
        let syn = tcp_frame(999, true, &[]);
        let first = tcp_frame(1_000, false, &payload[..split]);
        let second = tcp_frame(
            1_000u32.saturating_add(u32::try_from(split).unwrap_or(u32::MAX)),
            false,
            &payload[split..],
        );
        let mut tracker = SessionTracker::new();

        assert!(tracker.offer_frame(&syn).is_none());
        assert!(tracker.offer_frame(&second).is_none());
        let event = tracker
            .offer_frame(&first)
            .expect("out-of-order HTTP event");
        match event.l7 {
            StreamL7::Http(HttpMessage::Request { target, host, .. }) => {
                assert_eq!(target, "/index.html");
                assert_eq!(host.as_deref(), Some("example.com"));
            }
            _ => panic!("expected HTTP request"),
        }
    }
}
