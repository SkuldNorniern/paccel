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

/// Which decoding stage a [`ParseError`] occurred in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Link,
    Network,
    Transport,
    Application,
    Tunnel,
}

impl Layer {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Network => "network",
            Self::Transport => "transport",
            Self::Application => "application",
            Self::Tunnel => "tunnel",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The kind of parse failure, independent of which layer/protocol hit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// The buffer ended before a complete value could be read.
    Incomplete {
        /// Bytes needed to complete the value, if known at the point of failure.
        needed: Option<usize>,
        /// Bytes actually available.
        available: usize,
    },
    /// A length field's value is inconsistent with the buffer or the format.
    InvalidLength,
    /// A field's value is out of its valid range or fails a format check.
    InvalidValue,
    /// A protocol/version/type ID this parser doesn't handle.
    Unsupported,
    /// A configured resource bound (depth, flow count, buffer size) was hit.
    ResourceLimit,
    /// Doesn't fit a more specific kind above.
    Malformed,
}

/// A parse failure with enough context to act on programmatically - which
/// layer and (when known) which protocol, where in the buffer, and why -
/// unlike [`LayerError`], which carries none of that.
///
/// This is additive: existing parsers still return `LayerError`/`Result<T,
/// LayerError>` unchanged. `ParseError` is the emerging direction for
/// richer error context; construct one at a call site that has the
/// necessary offset/protocol information, or convert a `LayerError` via
/// [`ParseError::from_layer_error`] when only the coarser kind is available
/// (this loses precision - `Incomplete`'s `needed`/`available` fields come
/// back as `None`/`0` since a bare `LayerError` never carried byte counts;
/// prefer constructing `ParseError` directly wherever the real counts are
/// on hand).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub layer: Layer,
    pub protocol: Option<&'static str>,
    pub offset: usize,
    pub kind: ParseErrorKind,
}

impl ParseError {
    #[must_use]
    pub fn new(
        layer: Layer,
        protocol: Option<&'static str>,
        offset: usize,
        kind: ParseErrorKind,
    ) -> Self {
        Self {
            layer,
            protocol,
            offset,
            kind,
        }
    }

    /// Converts a coarse [`LayerError`] into a [`ParseError`], filling in the
    /// layer/protocol/offset the caller supplies. See the type-level doc for
    /// what's lost in this direction (byte counts on `Incomplete`).
    #[must_use]
    pub fn from_layer_error(
        error: &LayerError,
        layer: Layer,
        protocol: Option<&'static str>,
        offset: usize,
    ) -> Self {
        let kind = match error {
            LayerError::InvalidLength => ParseErrorKind::InvalidLength,
            LayerError::UnsupportedProtocol(_) => ParseErrorKind::Unsupported,
            LayerError::InsufficientData => ParseErrorKind::Incomplete {
                needed: None,
                available: 0,
            },
            LayerError::ValidationError(_) => ParseErrorKind::InvalidValue,
            LayerError::MissingField | LayerError::InvalidHeader | LayerError::MalformedPacket => {
                ParseErrorKind::Malformed
            }
        };
        Self::new(layer, protocol, offset, kind)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protocol = self.protocol.unwrap_or("unknown");
        match &self.kind {
            ParseErrorKind::Incomplete {
                needed: Some(needed),
                available,
            } => write!(
                f,
                "{} {protocol} @{}: incomplete, needed {needed} bytes, had {available}",
                self.layer, self.offset
            ),
            ParseErrorKind::Incomplete {
                needed: None,
                available,
            } => write!(
                f,
                "{} {protocol} @{}: incomplete, had {available} bytes",
                self.layer, self.offset
            ),
            ParseErrorKind::InvalidLength => {
                write!(
                    f,
                    "{} {protocol} @{}: invalid length",
                    self.layer, self.offset
                )
            }
            ParseErrorKind::InvalidValue => {
                write!(
                    f,
                    "{} {protocol} @{}: invalid value",
                    self.layer, self.offset
                )
            }
            ParseErrorKind::Unsupported => {
                write!(f, "{} {protocol} @{}: unsupported", self.layer, self.offset)
            }
            ParseErrorKind::ResourceLimit => {
                write!(
                    f,
                    "{} {protocol} @{}: resource limit hit",
                    self.layer, self.offset
                )
            }
            ParseErrorKind::Malformed => {
                write!(f, "{} {protocol} @{}: malformed", self.layer, self.offset)
            }
        }
    }
}

impl Error for ParseError {}

#[cfg(test)]
mod parse_error_tests {
    use super::{Layer, LayerError, ParseError, ParseErrorKind};

    #[test]
    fn maps_every_layer_error_variant() {
        let cases = [
            (LayerError::MissingField, ParseErrorKind::Malformed),
            (LayerError::InvalidLength, ParseErrorKind::InvalidLength),
            (LayerError::InvalidHeader, ParseErrorKind::Malformed),
            (LayerError::MalformedPacket, ParseErrorKind::Malformed),
            (
                LayerError::UnsupportedProtocol(0x11),
                ParseErrorKind::Unsupported,
            ),
            (
                LayerError::InsufficientData,
                ParseErrorKind::Incomplete {
                    needed: None,
                    available: 0,
                },
            ),
            (
                LayerError::ValidationError("bad checksum".to_string()),
                ParseErrorKind::InvalidValue,
            ),
        ];
        for (layer_error, expected_kind) in cases {
            let parse_error =
                ParseError::from_layer_error(&layer_error, Layer::Transport, Some("tcp"), 34);
            assert_eq!(parse_error.kind, expected_kind);
            assert_eq!(parse_error.layer, Layer::Transport);
            assert_eq!(parse_error.protocol, Some("tcp"));
            assert_eq!(parse_error.offset, 34);
        }
    }

    #[test]
    fn display_includes_layer_protocol_offset_and_kind() {
        let error = ParseError::new(
            Layer::Application,
            Some("dns"),
            128,
            ParseErrorKind::Incomplete {
                needed: Some(12),
                available: 4,
            },
        );
        let text = error.to_string();
        assert!(text.contains("application"));
        assert!(text.contains("dns"));
        assert!(text.contains("128"));
        assert!(text.contains("needed 12"));
        assert!(text.contains("had 4"));
    }

    #[test]
    fn display_falls_back_to_unknown_protocol() {
        let error = ParseError::new(Layer::Network, None, 0, ParseErrorKind::ResourceLimit);
        assert!(error.to_string().contains("unknown"));
    }
}
