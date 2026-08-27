//! Paccel is a Rust packet parsing engine focused on practical protocol
//! visibility, correctness, and performance. It parses Ethernet/SLL/802.11
//! link-layer frames, IPv4/IPv6, TCP/UDP, common tunnels, pcap/pcapng
//! captures, and 40+ application-layer protocols, without panicking on
//! malformed input.
//!
//! The crate is zero-dependency by default. `BuiltinPacketParser` is the
//! main stateless entry point:
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
//! Two optional Cargo features add [RustCrypto](https://github.com/RustCrypto)
//! dependencies: `quic-decrypt` (QUIC Initial/Handshake/1-RTT decrypt) and
//! `fingerprint` (JA3/JA4/JA3S/HASSH). See the repository README for the
//! full capability-maturity breakdown and feature documentation.
//!
//! `0.x` versions are explicitly unstable - the public API can change
//! between minor releases before `1.0`.

pub mod engine;
#[cfg(feature = "fingerprint")]
pub mod fingerprint;
pub mod layer;
pub mod packet;

pub use engine::{
    IpFragmentReassembler, QuicConnectionTracker, QuicStreamReassembler, SessionTracker,
    StreamEvent, StreamL7, TcpStreamReassembler,
};
pub use layer::LayerError;
pub use packet::{Packet, PacketError, PacketMetadata, PacketView};
