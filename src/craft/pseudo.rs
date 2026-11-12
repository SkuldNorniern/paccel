use std::net::IpAddr;

use super::{ChecksumAccumulator, EncodeError};

/// The addresses and length a transport checksum covers but nobody transmits.
///
/// RFC 768 and RFC 9293 for IPv4, RFC 8200 sec 8.1 for IPv6. Fed field by
/// field into the accumulator, so no buffer is built for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PseudoHeader {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    /// Transport header plus payload.
    pub length: u32,
}

impl PseudoHeader {
    pub(crate) fn add_to(&self, sum: &mut ChecksumAccumulator) -> Result<(), EncodeError> {
        match (self.source, self.destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                sum.add_bytes(&source.octets());
                sum.add_bytes(&destination.octets());
                sum.add_u16(u16::from(self.protocol));
                let length =
                    u16::try_from(self.length).map_err(|_| EncodeError::PayloadTooLong {
                        max: usize::from(u16::MAX),
                        got: self.length as usize,
                    })?;
                sum.add_u16(length);
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                sum.add_bytes(&source.octets());
                sum.add_bytes(&destination.octets());
                sum.add_u32(self.length);
                sum.add_u16(0);
                sum.add_u16(u16::from(self.protocol));
            }
            _ => return Err(EncodeError::AddressFamilyMismatch),
        }
        Ok(())
    }
}
