mod frames_common;

use paccel::engine::{BuiltinPacketParser, ParseConfig, ParseMode, ParseWarningCode, ParsedPacket};

/// Warnings that mean part of the frame did not survive the capture.
fn says_something_went_missing(code: ParseWarningCode) -> bool {
    matches!(
        code,
        ParseWarningCode::LinkPayloadTruncated
            | ParseWarningCode::NetworkHeaderUnreadable
            | ParseWarningCode::TcpOptionsTruncated
            | ParseWarningCode::Ipv6ExtensionTruncated
            | ParseWarningCode::Ipv6Truncated
            | ParseWarningCode::Ipv4Truncated
            | ParseWarningCode::Ipv4OptionsTruncated
            | ParseWarningCode::TransportTruncated
    )
}

#[test]
fn strict_refuses_every_frame_permissive_only_partly_read() {
    let frames = frames_common::frames();

    let mut checked = 0usize;
    let mut escaped = Vec::new();

    for (name, data) in &frames {
        let permissive = ParseConfig {
            mode: ParseMode::Permissive,
            ..ParseConfig::default()
        };
        let mut parsed = ParsedPacket::default();
        if BuiltinPacketParser::parse_into(data, permissive, Some(1), &mut parsed).is_err() {
            continue;
        }
        let missing: Vec<_> = parsed
            .warnings
            .iter()
            .filter(|warning| says_something_went_missing(warning.code))
            .map(|warning| warning.code)
            .collect();
        if missing.is_empty() {
            continue;
        }
        checked += 1;

        let strict = ParseConfig {
            mode: ParseMode::Strict,
            ..ParseConfig::default()
        };
        let mut strict_parsed = ParsedPacket::default();
        if BuiltinPacketParser::parse_into(data, strict, Some(1), &mut strict_parsed).is_ok() {
            escaped.push((name.clone(), missing));
        }
    }

    assert!(
        escaped.is_empty(),
        "{} of {checked} frames were kept by strict though permissive said data went missing: {:?}",
        escaped.len(),
        escaped.iter().take(3).collect::<Vec<_>>()
    );
}
