#![allow(clippy::cognitive_complexity, clippy::panic)]

use paccel::engine::{BuiltinPacketParser, ParseConfig, ParseMode, parse_capture_frames};
use paccel::layer::application::dns::parse_dns_message;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn builtin_parser_handles_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(parsed) = BuiltinPacketParser::parse(&bytes) {
            for warning in parsed.warnings {
                prop_assert!(warning.offset <= bytes.len());
            }
        }
    }

    #[test]
    fn strict_builtin_parser_handles_arbitrary_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let config = ParseConfig {
            mode: ParseMode::Strict,
            ..ParseConfig::default()
        };
        let _ = BuiltinPacketParser::parse_with_config(&bytes, config);
    }

    #[test]
    fn capture_parser_handles_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(frames) = parse_capture_frames(&bytes) {
            for frame in frames {
                prop_assert!(frame.data.len() <= bytes.len());
            }
        }
    }

    #[test]
    fn dns_parser_handles_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        if let Ok(message) = parse_dns_message(&bytes) {
            prop_assert!(message.questions.len() <= 65_535);
        }
    }

    #[test]
    fn builtin_parser_handles_ethernet_ipv4_packets(
        total_length in 20_u16..=u16::MAX,
        protocol in any::<u8>(),
        source in any::<[u8; 4]>(),
        destination in any::<[u8; 4]>(),
        payload in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut bytes = Vec::with_capacity(14 + 20 + payload.len());

        bytes.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        bytes.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        bytes.extend_from_slice(&[0x08, 0x00]);

        bytes.extend_from_slice(&[0x45, 0]);
        bytes.extend_from_slice(&total_length.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&destination);
        bytes.extend_from_slice(&payload);

        let _ = BuiltinPacketParser::parse(&bytes);
    }
}
