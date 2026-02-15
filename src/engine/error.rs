use std::fmt;

#[derive(Debug, Clone)]
pub struct DecodeWarning {
    pub code: &'static str,
    pub message: String,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone)]
pub enum DecodeError {
    MalformedHeader(&'static str),
    InsufficientBytes { needed: usize, available: usize },
    UnsupportedProtocol(&'static str),
    DepthLimitExceeded(usize),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::MalformedHeader(protocol) => {
                write!(f, "Malformed header for protocol: {}", protocol)
            }
            DecodeError::InsufficientBytes { needed, available } => {
                write!(
                    f,
                    "Insufficient bytes: needed {}, available {}",
                    needed, available
                )
            }
            DecodeError::UnsupportedProtocol(protocol) => {
                write!(f, "Unsupported protocol: {}", protocol)
            }
            DecodeError::DepthLimitExceeded(depth) => {
                write!(f, "Decode depth limit exceeded: {}", depth)
            }
        }
    }
}

impl std::error::Error for DecodeError {}
