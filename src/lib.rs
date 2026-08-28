//! Parses Ethernet/SLL/802.11, IPv4/IPv6, TCP/UDP, common tunnels,
//! pcap/pcapng, and 40+ application protocols without panicking on malformed
//! input.
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
//! Optional [RustCrypto](https://github.com/RustCrypto) features provide QUIC
//! decryption (`quic-decrypt`) and JA3/JA4/JA3S/HASSH fingerprints
//! (`fingerprint`). See the repository README for details.
//!
//! The public API may change between `0.x` minor releases.

pub mod engine;
#[cfg(feature = "fingerprint")]
pub mod fingerprint;
pub mod layer;
pub mod packet;

pub use engine::{
    IpFragmentReassembler, QuicConnectionTracker, QuicStreamReassembler, SessionTracker,
    StreamEvent, StreamL7, TcpOverlapPolicy, TcpStreamReassembler,
};
pub use layer::{Layer, LayerError, ParseError, ParseErrorKind, ProbeResult};
pub use packet::{Packet, PacketError, PacketMetadata, PacketView};
