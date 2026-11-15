//! Parses Ethernet/SLL/802.11, IPv4/IPv6, TCP/UDP, common tunnels,
//! pcap/pcapng, and 40+ application protocols without panicking on malformed
//! input, and writes frames back out again.
//!
//! [`engine::BuiltinPacketParser`] is the default zero-dependency entry point:
//!
//! ```
//! use paccel::engine::BuiltinPacketParser;
//!
//! let frame: &[u8] = &[]; // replace with a real captured frame
//! match BuiltinPacketParser::parse(frame) {
//!     Ok(parsed) => {
//!         if let Some(ipv4) = parsed.ipv4 {
//!             println!("ipv4 {} -> {}", ipv4.source, ipv4.destination);
//!         }
//!     }
//!     Err(err) => println!("parse error: {err}"),
//! }
//! ```
//!
//! [`craft`] goes the other way and builds a frame into a buffer the caller
//! owns, so a caller that reuses one buffer never allocates:
//!
//! ```
//! use std::net::Ipv4Addr;
//!
//! use paccel::craft::{Ipv4Header, PacketBuilder, UdpHeader};
//!
//! let payload = b"hello";
//! let builder = PacketBuilder::new()
//!     .ipv4(Ipv4Header::new(
//!         Ipv4Addr::new(10, 0, 0, 1),
//!         Ipv4Addr::new(10, 0, 0, 2),
//!         17,
//!         8 + payload.len(),
//!     ))
//!     .udp(UdpHeader::new(53_000, 53, payload.len()));
//!
//! let mut buffer = [0u8; 1514];
//! let written = builder.encode_into(&mut buffer, payload)?;
//! assert_eq!(written, builder.encoded_len(payload.len()));
//! # Ok::<(), paccel::EncodeError>(())
//! ```
//!
//! [`packet::PacketSlice`] reads an existing frame the same way, borrowing
//! rather than copying.
//!
//! Optional [RustCrypto](https://github.com/RustCrypto) features provide QUIC
//! decryption (`quic-decrypt`) and JA3/JA4/JA3S/HASSH fingerprints
//! (`fingerprint`). See the repository README for details.
//!
//! The public API may change between `0.x` minor releases.

pub mod craft;
pub mod engine;
#[cfg(feature = "fingerprint")]
pub mod fingerprint;
pub mod layer;
pub mod packet;

pub use craft::{EncodeError, PacketBuilder};
pub use engine::{
    IpFragmentReassembler, QuicConnectionTracker, QuicStreamReassembler, SessionTracker,
    StreamEvent, StreamL7, TcpOverlapPolicy, TcpStreamReassembler,
};
pub use layer::{Confidence, Layer, LayerError, ParseError, ParseErrorKind, ProbeResult};
pub use packet::{Packet, PacketError, PacketMetadata, PacketSlice, PacketView};
