use std::{error, fmt};

/// What stopped an encode.
///
/// Data only, no strings: every variant is a few integers, so a C ABI can
/// carry it as an enum plus two words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// The buffer was shorter than `encoded_len` said it had to be.
    BufferTooSmall { needed: usize, given: usize },
    /// A payload longer than the protocol's length field can describe.
    PayloadTooLong { max: usize, got: usize },
    /// Options longer than the protocol gives room for.
    OptionsTooLong { max: usize, got: usize },
    /// Options that are not the multiple of four the header length counts in.
    OptionsNotAligned { got: usize },
    /// An IPv4 header over an IPv6 address, or the other way round.
    AddressFamilyMismatch,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { needed, given } => {
                write!(f, "buffer holds {given} bytes, the frame needs {needed}")
            }
            Self::PayloadTooLong { max, got } => {
                write!(f, "payload is {got} bytes, the length field holds {max}")
            }
            Self::OptionsTooLong { max, got } => {
                write!(f, "options are {got} bytes, the header holds {max}")
            }
            Self::OptionsNotAligned { got } => {
                write!(f, "options are {got} bytes, not a multiple of four")
            }
            Self::AddressFamilyMismatch => {
                write!(f, "the addresses are not of one family")
            }
        }
    }
}

impl error::Error for EncodeError {}
