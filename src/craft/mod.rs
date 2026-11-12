//! Building packets, the other direction from [`crate::engine`].
//!
//! Encoders write into a caller's buffer through
//! `encode_into(&mut [u8]) -> Result<usize, EncodeError>`, so a caller that
//! reuses one buffer never allocates.

mod arp;
mod builder;
mod checksum;
mod cursor;
mod encode;
mod error;
mod ethernet;
mod icmp;
mod ipv4;
mod ipv6;
mod options;
mod pseudo;
mod tcp;
mod udp;

pub use arp::ArpHeader;
pub use builder::{NetworkHeader, PacketBuilder, TransportHeader};
pub use checksum::{ChecksumAccumulator, update_u16};
pub use encode::Encode;
pub use error::EncodeError;
pub use ethernet::{EthernetHeader, VlanTag};
pub use icmp::IcmpHeader;
pub use ipv4::Ipv4Header;
pub use ipv6::Ipv6Header;
pub use options::{MAX_OPTIONS, Options};
pub use pseudo::PseudoHeader;
pub use tcp::TcpHeader;
pub use udp::UdpHeader;

pub(crate) use cursor::WriteCursor;
