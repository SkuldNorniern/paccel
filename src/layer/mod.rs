use std::error::Error;
use std::fmt;

pub mod application;
pub mod datalink;
pub mod network;
pub mod transport;

/// Packet parsing errors.
#[derive(Debug)]
#[non_exhaustive]
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

/// Decoding stage where a [`ParseError`] occurred.
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

/// Parse failure independent of layer or protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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

/// Parse failure with layer, protocol, and offset context.
///
/// [`ParseError::from_layer_error`] adds context to a [`LayerError`] but cannot
/// recover `Incomplete` byte counts. Construct this type directly when those
/// counts are known.
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

    /// Adds the given layer, protocol, and offset to a [`LayerError`].
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

/// Protocol probe result that distinguishes mismatch, truncation, and malformed
/// input.
///
/// [`Self::ok`] collapses the distinction to `Option<T>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult<T> {
    /// Buffer matched and fully parsed.
    Match(T),
    /// Wrong protocol, such as bad magic or version.
    NoMatch,
    /// Too little data to decide; more bytes may produce a match.
    Incomplete {
        /// Bytes needed to decide, if known.
        needed: Option<usize>,
        /// Bytes actually available.
        available: usize,
    },
    /// Matched (magic/version checked out) but the rest fails to parse.
    Malformed(ParseError),
}

impl<T> ProbeResult<T> {
    /// Collapses `NoMatch`, `Incomplete`, and `Malformed` to `None`.
    #[must_use]
    pub fn ok(self) -> Option<T> {
        match self {
            Self::Match(value) => Some(value),
            Self::NoMatch | Self::Incomplete { .. } | Self::Malformed(_) => None,
        }
    }

    #[must_use]
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match(_))
    }

    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }

    #[must_use]
    pub fn as_malformed(&self) -> Option<&ParseError> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::Match(_) | Self::NoMatch | Self::Incomplete { .. } => None,
        }
    }
}

/// How sure a classification is, ordered weakest to strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Port number and/or a loose byte pattern, no structural check.
    Heuristic,
    /// A structural parse succeeded (magic/version/length fields checked out).
    Structural,
    /// Confirmed against tracked connection state, not just this one packet.
    Stateful,
}

#[cfg(test)]
mod probe_result_tests {
    use super::{Layer, ParseError, ParseErrorKind, ProbeResult};

    #[test]
    fn ok_bridges_only_match_to_some() {
        assert_eq!(ProbeResult::Match(7).ok(), Some(7));
        assert_eq!(ProbeResult::<i32>::NoMatch.ok(), None);
        assert_eq!(
            ProbeResult::<i32>::Incomplete {
                needed: None,
                available: 0
            }
            .ok(),
            None
        );
        let malformed = ProbeResult::<i32>::Malformed(ParseError::new(
            Layer::Application,
            None,
            0,
            ParseErrorKind::Malformed,
        ));
        assert_eq!(malformed.ok(), None);
    }

    #[test]
    fn predicates_match_their_variant() {
        assert!(ProbeResult::Match(1).is_match());
        assert!(!ProbeResult::<i32>::NoMatch.is_match());
        assert!(
            ProbeResult::<i32>::Incomplete {
                needed: Some(4),
                available: 1
            }
            .is_incomplete()
        );
        assert!(!ProbeResult::Match(1).is_incomplete());

        let error = ParseError::new(Layer::Transport, Some("dnp3"), 3, ParseErrorKind::Malformed);
        let malformed = ProbeResult::<i32>::Malformed(error.clone());
        assert_eq!(malformed.as_malformed(), Some(&error));
        assert_eq!(ProbeResult::<i32>::NoMatch.as_malformed(), None);
    }
}

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
