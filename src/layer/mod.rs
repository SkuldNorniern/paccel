use std::error::Error;
use std::fmt;

pub mod application;
pub mod datalink;
pub mod network;
pub mod transport;

/// Error types that can occur during packet parsing.
#[derive(Debug)]
pub enum LayerError {
    MissingField,
    InvalidLength,
    InvalidHeader,
    MalformedPacket,
    UnsupportedProtocol(u8),
    InsufficientData,
    ValidationError(String),
}

impl fmt::Display for LayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayerError::MissingField => write!(f, "Required field is missing"),
            LayerError::InvalidLength => write!(f, "Invalid packet length"),
            LayerError::InvalidHeader => write!(f, "Invalid packet header"),
            LayerError::MalformedPacket => write!(f, "Malformed packet"),
            LayerError::UnsupportedProtocol(id) => write!(f, "Unsupported protocol ID: {id}"),
            LayerError::InsufficientData => write!(f, "Insufficient data in packet"),
            LayerError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
        }
    }
}

impl Error for LayerError {}
