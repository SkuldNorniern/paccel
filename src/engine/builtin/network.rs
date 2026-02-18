use crate::engine::constants::ip_proto;
use crate::layer::network::ipv4::Ipv4Header;
use crate::layer::network::ipv6::Ipv6Header;
use crate::layer::LayerError;

#[derive(Debug, Clone, Copy)]
pub(super) struct Ipv6TransportState {
    pub next_header: u8,
    pub l4_offset: usize,
    pub non_initial_fragment: bool,
    pub depth_limit_hit: bool,
}

pub(super) fn parse_ipv4_header(data: &[u8]) -> Result<Ipv4Header, LayerError> {
    if data.len() < 20 {
        return Err(LayerError::InvalidLength);
    }

    let first = data[0];
    let version = first >> 4;
    let ihl = first & 0x0f;
    if version != 4 || ihl < 5 {
        return Err(LayerError::InvalidHeader);
    }

    let header_len = (ihl as usize) * 4;
    if data.len() < header_len {
        return Err(LayerError::InvalidLength);
    }

    let dscp = data[1] >> 2;
    let ecn = data[1] & 0x03;
    let total_length = u16::from_be_bytes([data[2], data[3]]);

    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_fragment = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_fragment >> 13) as u8;
    let fragment_offset = flags_fragment & 0x1fff;
    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);
    let source = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let destination = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let options = if ihl > 5 {
        Some(data[20..header_len].to_vec())
    } else {
        None
    };

    Ok(Ipv4Header {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        source,
        destination,
        options,
    })
}

pub(super) fn parse_ipv6_header(data: &[u8]) -> Result<Ipv6Header, LayerError> {
    if data.len() < 40 {
        return Err(LayerError::InvalidLength);
    }

    let first_word = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let version = ((first_word >> 28) & 0x0f) as u8;
    if version != 6 {
        return Err(LayerError::InvalidHeader);
    }

    let traffic_class = ((first_word >> 20) & 0xff) as u8;
    let flow_label = first_word & 0x000f_ffff;
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    let source = std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&data[8..24]).map_err(|_| LayerError::InvalidHeader)?,
    );
    let destination = std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&data[24..40]).map_err(|_| LayerError::InvalidHeader)?,
    );

    Ok(Ipv6Header {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        source,
        destination,
    })
}

pub(super) fn resolve_ipv6_transport(
    packet: &[u8],
    initial_next_header: u8,
    max_ext_headers: usize,
) -> Result<Ipv6TransportState, LayerError> {
    let mut state = Ipv6TransportState {
        next_header: initial_next_header,
        l4_offset: 40,
        non_initial_fragment: false,
        depth_limit_hit: false,
    };
    let mut depth = 0usize;

    loop {
        if depth >= max_ext_headers {
            state.depth_limit_hit = true;
            return Ok(state);
        }

        match state.next_header {
            0 | 43 | 60 => {
                if state.l4_offset + 2 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[state.l4_offset];
                let ext_len = packet[state.l4_offset + 1] as usize;
                let header_len = (ext_len + 1) * 8;
                if state.l4_offset + header_len > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                state.next_header = ext_next;
                state.l4_offset += header_len;
                depth += 1;
            }
            44 => {
                if state.l4_offset + 8 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[state.l4_offset];
                let frag_off_flags =
                    u16::from_be_bytes([packet[state.l4_offset + 2], packet[state.l4_offset + 3]]);
                let frag_offset = (frag_off_flags & 0xFFF8) >> 3;

                state.next_header = ext_next;
                state.l4_offset += 8;
                depth += 1;

                if frag_offset != 0 {
                    state.non_initial_fragment = true;
                    return Ok(state);
                }
            }
            ip_proto::AH => {
                if state.l4_offset + 2 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[state.l4_offset];
                let payload_len = packet[state.l4_offset + 1] as usize;
                let header_len = (payload_len + 2) * 4;
                if state.l4_offset + header_len > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                state.next_header = ext_next;
                state.l4_offset += header_len;
                depth += 1;
            }
            ip_proto::ESP | 59 => return Ok(state),
            _ => return Ok(state),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::builtin::{BuiltinPacketParser, ParseWarningCode, TransportSegment};

    #[test]
    fn parses_ipv4_icmp() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0x00, 0x01,
            0x40, 0x00, 64, 1, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 8, 0, 0xf7, 0xff, 0x00, 0x00,
            0x00, 0x00,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(parsed.icmp.is_some());
        assert_eq!(parsed.icmp.as_ref().unwrap().icmp_type, 8);
        assert_eq!(parsed.icmp.as_ref().unwrap().icmp_code, 0);
    }

    #[test]
    fn parses_ipv6_icmpv6() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x08,
            58, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 128, 0, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv6.is_some());
        assert!(parsed.icmpv6.is_some());
        assert_eq!(parsed.icmpv6.as_ref().unwrap().icmp_type, 128);
        assert_eq!(parsed.icmpv6.as_ref().unwrap().icmp_code, 0);
    }

    #[test]
    fn parses_ipv4_igmp() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0x00, 0x01,
            0x00, 0x00, 64, 2, 0, 0, 192, 168, 1, 1, 224, 0, 0, 1, 0x11, 0x00, 0x00, 0x00, 224, 0,
            0, 1,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(parsed.igmp.is_some());
        assert_eq!(parsed.igmp.as_ref().unwrap().msg_type, 0x11);
        assert_eq!(
            parsed.igmp.as_ref().unwrap().group_address,
            Some(std::net::Ipv4Addr::new(224, 0, 0, 1))
        );
    }

    #[test]
    fn ipv4_fragmented_adds_warning() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x24, 0x12, 0x34,
            0x20, 0x01, 64, 17, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x04, 0xd2, 0x00, 0x35, 0x00,
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(frame.len(), 14 + 36);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::Ipv4Fragmented)));
    }

    #[test]
    fn ipv4_truncated_adds_warning_and_parses_available_l4() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x64, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];
        let full_packet_len = 14 + 100;
        assert!(frame.len() < full_packet_len);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert_eq!(parsed.ipv4.as_ref().unwrap().total_length, 100);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::Ipv4Truncated)));
        assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));
    }

    #[test]
    fn skips_l4_on_ipv6_non_initial_fragment() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x10,
            44, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 17, 0, 0x00, 0x09, 0x12, 0x34, 0x56, 0x78, 0x00, 0x35, 0x30, 0x39,
            0x00, 0x10, 0x00, 0x00,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv6.is_some());
        assert!(parsed.transport.is_none());
        assert_eq!(parsed.warnings.len(), 1);
        assert_eq!(
            parsed.warnings[0].code,
            ParseWarningCode::Ipv6NonInitialFragment
        );
    }
}
