mod link;
mod network;
mod transport;
mod types;

use crate::layer::LayerError;

use self::link::{parse_arp_packet, parse_link, parse_pppoe_minimal};
use self::network::{parse_ipv4_header, parse_ipv6_header, resolve_ipv6_transport};
use self::transport::parse_transport;

pub use self::types::{
    EthernetFrame, GreInfo, IgmpInfo, ParseConfig, ParseWarning, ParseWarningCode, ParsedPacket,
    PppoeInfo, TcpOptionsParsed, TransportSegment, UdpAppHint, VxlanInfo,
};

pub struct BuiltinPacketParser;

impl BuiltinPacketParser {
    pub fn parse(raw: &[u8]) -> Result<ParsedPacket, LayerError> {
        Self::parse_with_config(raw, ParseConfig::default())
    }

    pub fn parse_with_config(raw: &[u8], config: ParseConfig) -> Result<ParsedPacket, LayerError> {
        let (eth, l3_offset) = parse_link(raw)?;
        let mut parsed = ParsedPacket {
            ethernet: Some(eth.clone()),
            ..ParsedPacket::default()
        };

        if l3_offset >= raw.len() {
            return Err(LayerError::InvalidLength);
        }

        let l3_bytes = &raw[l3_offset..];

        match eth.ethertype {
            0x0806 => {
                let arp = parse_arp_packet(l3_bytes)?;
                parsed.arp = Some(arp);
                Ok(parsed)
            }
            0x0800 => {
                let ipv4 = parse_ipv4_header(l3_bytes)?;

                let ip_header_len = (ipv4.ihl as usize) * 4;
                let total_len = ipv4.total_length as usize;
                if total_len < ip_header_len {
                    return Err(LayerError::InvalidLength);
                }

                let truncated = total_len > l3_bytes.len();
                if truncated {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv4Truncated,
                        message: "IPv4 total length exceeds capture; L4 may be truncated",
                    });
                }

                if (ipv4.flags & 1) != 0 || ipv4.fragment_offset != 0 {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv4Fragmented,
                        message: "IPv4 fragment; no reassembly, L4 may be incomplete",
                    });
                }

                let l4_end = total_len.min(l3_bytes.len());
                let l4_bytes = &l3_bytes[ip_header_len..l4_end];
                let transport_parse = parse_transport(ipv4.protocol, l4_bytes)?;
                apply_transport_parse(&mut parsed, transport_parse);
                if parsed.gre.is_some() {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::GreInner,
                        message: "GRE inner payload; no nested decode yet",
                    });
                }
                if parsed.vxlan.is_some() {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::VxlanInner,
                        message: "VXLAN inner payload; no nested decode yet",
                    });
                }
                parsed.ipv4 = Some(ipv4);
                Ok(parsed)
            }
            0x86DD => {
                let ipv6 = parse_ipv6_header(l3_bytes)?;

                let payload_len = ipv6.payload_length as usize;
                let l4_end = 40 + payload_len;
                if l4_end > l3_bytes.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ipv6_payload = &l3_bytes[..l4_end];
                let state = resolve_ipv6_transport(
                    ipv6_payload,
                    ipv6.next_header,
                    config.max_ipv6_extension_headers,
                )?;

                if state.l4_offset > ipv6_payload.len() {
                    return Err(LayerError::InvalidLength);
                }

                if state.depth_limit_hit {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6ExtensionDepthLimit,
                        message: "IPv6 extension header depth limit reached; skipping L4/L7 parse",
                    });
                }

                if state.non_initial_fragment {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6NonInitialFragment,
                        message:
                            "IPv6 non-initial fragment encountered; skipping L4/L7 parse without reassembly",
                    });
                }

                if !state.non_initial_fragment && !state.depth_limit_hit {
                    let l4_bytes = &ipv6_payload[state.l4_offset..];
                    let transport_parse = parse_transport(state.next_header, l4_bytes)?;
                    apply_transport_parse(&mut parsed, transport_parse);
                    if parsed.vxlan.is_some() {
                        parsed.warnings.push(ParseWarning {
                            code: ParseWarningCode::VxlanInner,
                            message: "VXLAN inner payload; no nested decode yet",
                        });
                    }
                }

                parsed.ipv6 = Some(ipv6);
                Ok(parsed)
            }
            0x8863 | 0x8864 => {
                let pppoe = parse_pppoe_minimal(l3_bytes)?;
                parsed.pppoe = Some(pppoe);
                parsed.warnings.push(ParseWarning {
                    code: ParseWarningCode::PppoeNoPayload,
                    message: "PPPoE header only; payload not decoded",
                });
                Ok(parsed)
            }
            other => {
                parsed.warnings.push(ParseWarning {
                    code: ParseWarningCode::UnsupportedEthertype(other),
                    message: "L2 only; unsupported ethertype, L3+ not parsed",
                });
                Ok(parsed)
            }
        }
    }
}

fn apply_transport_parse(parsed: &mut ParsedPacket, transport_parse: transport::TransportParse) {
    parsed.transport = transport_parse.transport;
    parsed.icmp = transport_parse.icmp;
    parsed.icmpv6 = transport_parse.icmpv6;
    parsed.igmp = transport_parse.igmp;
    parsed.tcp_options = transport_parse.tcp_options;
    parsed.gre = transport_parse.gre;
    parsed.vxlan = transport_parse.vxlan;
    parsed.dns = transport_parse.dns;
    parsed.udp_hints = transport_parse.hints;
}
