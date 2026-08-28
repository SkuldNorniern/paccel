mod link;
mod network;
mod transport;
mod types;

use crate::engine::constants::{ethertype, ip_proto};
use crate::layer::LayerError;
pub use crate::layer::application::bgp::{BgpMessage, BgpMessageType};
pub use crate::layer::application::cdp::CdpHeader;
use crate::layer::application::cdp::parse_cdp_header;
pub use crate::layer::application::coap::{CoapMessage, CoapType};
pub use crate::layer::application::dhcp6::{Dhcp6Message, Dhcp6Option};
pub use crate::layer::application::dnp3::{
    Dnp3AppFunctionCode, Dnp3Application, Dnp3FunctionCode, Dnp3Message, Dnp3Transport,
};
pub use crate::layer::application::eigrp::EigrpHeader;
pub use crate::layer::application::ftp::FtpMessage;
pub use crate::layer::application::hsrp::HsrpHeader;
pub use crate::layer::application::imap::ImapMessage;
pub use crate::layer::application::isakmp::IsakmpHeader;
pub use crate::layer::application::kerberos::{KerberosMessage, KerberosMessageType};
pub use crate::layer::application::lacp::LacpHeader;
use crate::layer::application::lacp::parse_lacp_header;
pub use crate::layer::application::ldap::{LdapMessage, LdapProtocolOp};
pub use crate::layer::application::modbus::ModbusMessage;
pub use crate::layer::application::mqtt::{MqttMessage, MqttPacketType};
pub use crate::layer::application::nat_pmp::NatPmpMessage;
pub use crate::layer::application::nntp::NntpMessage;
pub use crate::layer::application::ospf::OspfHeader;
pub use crate::layer::application::pcp::PcpHeader;
pub use crate::layer::application::pim::PimHeader;
pub use crate::layer::application::radius::{RadiusAttribute, RadiusMessage};
pub use crate::layer::application::rip::RipHeader;
pub use crate::layer::application::rpc::RpcMessage;
pub use crate::layer::application::rtcp::RtcpHeader;
pub use crate::layer::application::rtp::RtpHeader;
pub use crate::layer::application::sip::SipMessage;
pub use crate::layer::application::smb1::Smb1Header;
pub use crate::layer::application::smb2::Smb2Header;
pub use crate::layer::application::smtp::SmtpMessage;
pub use crate::layer::application::snmp::{SnmpMessage, SnmpPduType};
pub use crate::layer::application::ssdp::SsdpMessage;
pub use crate::layer::application::ssh::{SshBanner, SshKexInit};
pub use crate::layer::application::stun::StunMessage;
pub use crate::layer::application::syslog::SyslogMessage;
pub use crate::layer::application::telnet::TelnetCommand;
pub use crate::layer::application::tftp::TftpMessage;
pub use crate::layer::application::vrrp::VrrpHeader;
use crate::layer::datalink::dot11::{parse_dot11, parse_radiotap};

use self::link::{
    parse_arp_packet, parse_link_with_linktype, parse_mpls_stack, parse_pppoe_minimal,
};
use self::network::{parse_ipv4_header, parse_ipv6_header, resolve_ipv6_transport};
use self::transport::parse_transport;

pub use self::network::Ipv6FragmentHeader;

pub use self::types::{
    AhInfo, ApplicationLayer, EspInfo, EthernetFrame, FlowKey, GeneveInfo, GreInfo, IgmpInfo,
    L2tpInfo, LldpInfo, LldpTlv, MplsInfo, MplsLabel, OpenVpnInfo, OpenVpnOpcode, ParseConfig,
    ParseMode, ParseWarning, ParseWarningCode, ParseWarningProtocol, ParseWarningSubcode,
    ParsedPacket, PppoeInfo, SctpChunk, SctpInfo, StopLayer, StpBpdu, TcpOptionsParsed,
    TransportSegment, UdpAppHint, VxlanInfo, WireGuardInfo, WireGuardMessageType,
};

pub struct BuiltinPacketParser;

impl BuiltinPacketParser {
    pub fn parse(raw: &[u8]) -> Result<ParsedPacket, LayerError> {
        Self::parse_with_config(raw, ParseConfig::default())
    }

    pub fn parse_with_config(raw: &[u8], config: ParseConfig) -> Result<ParsedPacket, LayerError> {
        Self::parse_l2(raw, config, 0)
    }

    pub fn parse_with_linktype(raw: &[u8], linktype: u16) -> Result<ParsedPacket, LayerError> {
        Self::parse_with_config_and_linktype(raw, ParseConfig::default(), Some(linktype))
    }

    pub fn parse_with_config_and_linktype(
        raw: &[u8],
        config: ParseConfig,
        linktype: Option<u16>,
    ) -> Result<ParsedPacket, LayerError> {
        Self::parse_l2_with_linktype(raw, config, 0, linktype)
    }

    fn parse_l2(raw: &[u8], config: ParseConfig, depth: usize) -> Result<ParsedPacket, LayerError> {
        Self::parse_l2_with_linktype(raw, config, depth, None)
    }

    fn parse_l2_with_linktype(
        raw: &[u8],
        config: ParseConfig,
        depth: usize,
        linktype: Option<u16>,
    ) -> Result<ParsedPacket, LayerError> {
        match linktype {
            Some(127) => {
                let (radiotap, dot11_offset) = match parse_radiotap(raw) {
                    Ok(value) => value,
                    Err(LayerError::InvalidLength) if config.mode == ParseMode::Permissive => {
                        return Ok(ParsedPacket::default());
                    }
                    Err(error) => return Err(error),
                };
                let mut parsed =
                    Self::parse_dot11_l2(&raw[dot11_offset..], config, depth, dot11_offset)?;
                parsed.radiotap = Some(radiotap);
                return Ok(parsed);
            }
            Some(105) => return Self::parse_dot11_l2(raw, config, depth, 0),
            _ => {}
        }

        let (eth, l3_offset) = if linktype == Some(10) {
            parse_fddi_snap(raw)?
        } else {
            parse_link_with_linktype(raw, linktype)?
        };
        let parsed = ParsedPacket {
            ethernet: Some(eth.clone()),
            ..ParsedPacket::default()
        };

        if l3_offset >= raw.len() {
            return Err(LayerError::InvalidLength);
        }

        if eth.ethertype == 0 && eth.payload_offset == 17 {
            let mut parsed = parsed;
            parsed.stp = Some(parse_stp(&raw[l3_offset..])?);
            return Ok(parsed);
        }

        if eth.ethertype == 0 && eth.payload_offset == 22 {
            let mut parsed = parsed;
            parsed.cdp = parse_cdp_header(&raw[l3_offset..]).ok();
            return Ok(parsed);
        }

        Self::parse_ethertype(
            &raw[l3_offset..],
            eth.ethertype,
            config,
            depth,
            l3_offset,
            parsed,
        )
    }

    fn parse_dot11_l2(
        raw: &[u8],
        config: ParseConfig,
        depth: usize,
        frame_offset: usize,
    ) -> Result<ParsedPacket, LayerError> {
        let dot11 = match parse_dot11(raw) {
            Ok(dot11) => dot11,
            Err(LayerError::InvalidLength) if config.mode == ParseMode::Permissive => {
                return Ok(ParsedPacket::default());
            }
            Err(error) => return Err(error),
        };
        let mut parsed = ParsedPacket {
            dot11: Some(dot11),
            ..ParsedPacket::default()
        };

        if dot11.frame_type != 2 {
            return Ok(parsed);
        }

        let Some(snap) = raw.get(dot11.header_len..dot11.header_len.saturating_add(8)) else {
            return Ok(parsed);
        };
        if snap[..6] != [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00] {
            return Ok(parsed);
        }

        let ethertype = u16::from_be_bytes([snap[6], snap[7]]);
        let l3_frame_offset = dot11.header_len + 8;
        let Some(l3_bytes) = raw.get(l3_frame_offset..) else {
            return Ok(parsed);
        };
        let l3_offset = frame_offset.saturating_add(l3_frame_offset);
        match Self::parse_ethertype(l3_bytes, ethertype, config, depth, l3_offset, parsed) {
            Err(LayerError::InvalidLength) if config.mode == ParseMode::Permissive => {
                parsed = ParsedPacket {
                    dot11: Some(dot11),
                    ..ParsedPacket::default()
                };
                Ok(parsed)
            }
            result => result,
        }
    }

    fn parse_l3(
        l3_bytes: &[u8],
        ethertype: u16,
        config: ParseConfig,
        depth: usize,
    ) -> Result<ParsedPacket, LayerError> {
        Self::parse_ethertype(
            l3_bytes,
            ethertype,
            config,
            depth,
            0,
            ParsedPacket::default(),
        )
    }

    #[allow(clippy::cognitive_complexity)]
    fn parse_ethertype(
        l3_bytes: &[u8],
        ethertype: u16,
        config: ParseConfig,
        depth: usize,
        l3_offset: usize,
        mut parsed: ParsedPacket,
    ) -> Result<ParsedPacket, LayerError> {
        match ethertype {
            ethertype::ARP => {
                let arp = parse_arp_packet(l3_bytes)?;
                parsed.arp = Some(arp);
                Ok(parsed)
            }
            ethertype::IPV4 => {
                let ipv4 = parse_ipv4_header(l3_bytes)?;

                let ip_header_len = (ipv4.ihl as usize) * 4;
                let total_len = ipv4.total_length as usize;
                if total_len < ip_header_len || ip_header_len > l3_bytes.len() {
                    return Err(LayerError::InvalidLength);
                }

                let truncated = total_len > l3_bytes.len();
                if truncated {
                    if config.mode == ParseMode::Strict {
                        return Err(LayerError::InvalidLength);
                    }
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv4Truncated,
                        protocol: ParseWarningProtocol::Network,
                        subcode: ParseWarningSubcode::Ipv4Truncated,
                        offset: l3_offset,
                        message: "IPv4 total length exceeds capture; L4 may be truncated",
                    });
                }

                if (ipv4.flags & 1) != 0 || ipv4.fragment_offset != 0 {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv4Fragmented,
                        protocol: ParseWarningProtocol::Network,
                        subcode: ParseWarningSubcode::Ipv4Fragmented,
                        offset: l3_offset + 6,
                        message: "IPv4 fragment; no reassembly, L4 may be incomplete",
                    });
                }

                if config.stop_after == StopLayer::Network {
                    parsed.ipv4 = Some(ipv4);
                    return Ok(parsed);
                }

                if ipv4.fragment_offset == 0 {
                    let l4_end = total_len.min(l3_bytes.len());
                    let l4_bytes = &l3_bytes[ip_header_len..l4_end];
                    let transport_parse = parse_transport(ipv4.protocol, l4_bytes, config)?;
                    apply_transport_parse(&mut parsed, transport_parse);
                    parsed.transport_segment_offset = Some(l3_offset + ip_header_len);
                    recurse_transport_tunnel(
                        &mut parsed,
                        ipv4.protocol,
                        l4_bytes,
                        config,
                        depth,
                        l3_offset + ip_header_len,
                    );
                }
                parsed.ipv4 = Some(ipv4);
                Ok(parsed)
            }
            ethertype::IPV6 => {
                let mut ipv6 = parse_ipv6_header(l3_bytes)?;

                let payload_len = ipv6.payload_length as usize;
                let declared_l4_end = 40 + payload_len;
                if declared_l4_end > l3_bytes.len() {
                    if config.mode == ParseMode::Strict {
                        return Err(LayerError::InvalidLength);
                    }
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6Truncated,
                        protocol: ParseWarningProtocol::Network,
                        subcode: ParseWarningSubcode::Ipv6Truncated,
                        offset: l3_offset,
                        message: "IPv6 payload length exceeds capture; L4 may be truncated",
                    });
                }

                let l4_end = declared_l4_end.min(l3_bytes.len());
                if config.stop_after == StopLayer::Network {
                    parsed.ipv6 = Some(ipv6);
                    return Ok(parsed);
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

                ipv6.resolved_next_header = state.next_header;
                ipv6.transport_header_offset = u16::try_from(state.l4_offset).unwrap_or(u16::MAX);
                parsed.ipv6_fragment = state.fragment_header;

                if state.depth_limit_hit {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6ExtensionDepthLimit,
                        protocol: ParseWarningProtocol::Network,
                        subcode: ParseWarningSubcode::Ipv6ExtensionDepthLimit,
                        offset: l3_offset + state.l4_offset,
                        message: "IPv6 extension header depth limit reached; skipping L4/L7 parse",
                    });
                }

                if state.non_initial_fragment {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6NonInitialFragment,
                        protocol: ParseWarningProtocol::Network,
                        subcode: ParseWarningSubcode::Ipv6NonInitialFragment,
                        offset: l3_offset + state.l4_offset,
                        message:
                            "IPv6 non-initial fragment encountered; skipping L4/L7 parse without reassembly",
                    });
                }

                if !state.non_initial_fragment && !state.depth_limit_hit {
                    let l4_bytes = &ipv6_payload[state.l4_offset..];
                    let transport_parse = parse_transport(state.next_header, l4_bytes, config)?;
                    apply_transport_parse(&mut parsed, transport_parse);
                    parsed.transport_segment_offset = Some(l3_offset + state.l4_offset);
                    recurse_transport_tunnel(
                        &mut parsed,
                        state.next_header,
                        l4_bytes,
                        config,
                        depth,
                        l3_offset + state.l4_offset,
                    );
                }

                parsed.ipv6 = Some(ipv6);
                Ok(parsed)
            }
            ethertype::PPPOE_DISCOVERY => {
                let pppoe = parse_pppoe_minimal(l3_bytes)?;
                parsed.pppoe = Some(pppoe);
                parsed.warnings.push(ParseWarning {
                    code: ParseWarningCode::PppoeNoPayload,
                    protocol: ParseWarningProtocol::Tunnel,
                    subcode: ParseWarningSubcode::PppoeNoPayload,
                    offset: l3_offset,
                    message: "PPPoE header only; payload not decoded",
                });
                Ok(parsed)
            }
            ethertype::PPPOE_SESSION => {
                let pppoe = parse_pppoe_minimal(l3_bytes)?;
                parsed.pppoe = Some(pppoe);
                decode_pppoe_session(&mut parsed, l3_bytes, config, depth, l3_offset)?;
                Ok(parsed)
            }
            ethertype::MPLS_UNICAST | ethertype::MPLS_MULTICAST => {
                let (mpls, mpls_payload_offset, depth_limit_hit) =
                    parse_mpls_stack(l3_bytes, config.max_mpls_labels)?;
                parsed.mpls = Some(mpls);
                if depth_limit_hit {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::MplsLabelDepthLimit,
                        protocol: ParseWarningProtocol::Tunnel,
                        subcode: ParseWarningSubcode::MplsLabelDepthLimit,
                        offset: l3_offset + mpls_payload_offset,
                        message: "MPLS label depth limit reached; skipping inner payload decode",
                    });
                }
                if mpls_payload_offset < l3_bytes.len() {
                    let inner_bytes = &l3_bytes[mpls_payload_offset..];
                    let inner_ethertype = match inner_bytes.first().map(|byte| byte >> 4) {
                        Some(4) => Some(ethertype::IPV4),
                        Some(6) => Some(ethertype::IPV6),
                        _ => None,
                    };
                    if !depth_limit_hit {
                        let tunnel_depth_limited =
                            inner_ethertype.is_some() && depth >= config.max_tunnel_depth;
                        let result = inner_ethertype.and_then(|inner_ethertype| {
                            if tunnel_depth_limited {
                                None
                            } else {
                                Some(Self::parse_l3(
                                    inner_bytes,
                                    inner_ethertype,
                                    config,
                                    depth + 1,
                                ))
                            }
                        });
                        recurse_or_warn(
                            &mut parsed,
                            result,
                            tunnel_depth_limited,
                            ParseWarningCode::MplsInner,
                            ParseWarningSubcode::MplsInner,
                            l3_offset + mpls_payload_offset,
                            "MPLS inner payload; nested decode failed",
                        );
                    } else {
                        push_inner_warning(
                            &mut parsed,
                            ParseWarningCode::MplsInner,
                            ParseWarningSubcode::MplsInner,
                            l3_offset + mpls_payload_offset,
                            "MPLS inner payload; nested decode skipped",
                        );
                    }
                }
                Ok(parsed)
            }
            ethertype::LLDP => {
                parsed.lldp = Some(parse_lldp(l3_bytes));
                Ok(parsed)
            }
            ethertype::SLOW_PROTOCOLS => {
                parsed.lacp = parse_lacp_header(l3_bytes).ok();
                Ok(parsed)
            }
            other => {
                if config.mode == ParseMode::Strict {
                    return Err(LayerError::ValidationError(format!(
                        "unsupported ethertype: 0x{other:04x}"
                    )));
                }
                parsed.warnings.push(ParseWarning {
                    code: ParseWarningCode::UnsupportedEthertype(other),
                    protocol: ParseWarningProtocol::Link,
                    subcode: ParseWarningSubcode::UnsupportedEthertype,
                    offset: 12,
                    message: "L2 only; unsupported ethertype, L3+ not parsed",
                });
                Ok(parsed)
            }
        }
    }
}

fn decode_pppoe_session(
    parsed: &mut ParsedPacket,
    data: &[u8],
    config: ParseConfig,
    depth: usize,
    offset: usize,
) -> Result<(), LayerError> {
    const PPPOE_HEADER_LEN: usize = 6;

    let declared_end = PPPOE_HEADER_LEN.saturating_add(
        parsed
            .pppoe
            .as_ref()
            .map_or(0, |pppoe| usize::from(pppoe.length)),
    );
    let payload_end = declared_end.min(data.len());
    let Some(first) = data
        .get(PPPOE_HEADER_LEN)
        .copied()
        .filter(|_| payload_end > 6)
    else {
        if config.mode == ParseMode::Strict {
            return Err(LayerError::InvalidLength);
        }
        push_inner_warning(
            parsed,
            ParseWarningCode::PppoeNoPayload,
            ParseWarningSubcode::PppoeNoPayload,
            offset + PPPOE_HEADER_LEN,
            "PPPoE session has no complete PPP protocol field",
        );
        return Ok(());
    };

    let (protocol, protocol_len) = if first & 1 != 0 {
        (u16::from(first), 1)
    } else {
        let Some(second) = data
            .get(PPPOE_HEADER_LEN + 1)
            .copied()
            .filter(|_| payload_end > 7)
        else {
            if config.mode == ParseMode::Strict {
                return Err(LayerError::InvalidLength);
            }
            push_inner_warning(
                parsed,
                ParseWarningCode::PppoeNoPayload,
                ParseWarningSubcode::PppoeNoPayload,
                offset + PPPOE_HEADER_LEN,
                "PPPoE session has a truncated PPP protocol field",
            );
            return Ok(());
        };
        (u16::from_be_bytes([first, second]), 2)
    };

    let inner_offset = PPPOE_HEADER_LEN + protocol_len;
    let inner_ethertype = match protocol {
        0x0021 => Some(ethertype::IPV4),
        0x0057 => Some(ethertype::IPV6),
        _ => None,
    };
    let Some(inner_ethertype) = inner_ethertype else {
        push_inner_warning(
            parsed,
            ParseWarningCode::PppoeNoPayload,
            ParseWarningSubcode::PppoeNoPayload,
            offset + PPPOE_HEADER_LEN,
            "PPPoE PPP control or unsupported protocol; payload not decoded",
        );
        return Ok(());
    };

    let inner = data
        .get(inner_offset..payload_end)
        .filter(|bytes| !bytes.is_empty());
    let depth_limited = inner.is_some() && depth >= config.max_tunnel_depth;
    let result = inner.and_then(|bytes| {
        if depth_limited {
            None
        } else {
            Some(BuiltinPacketParser::parse_ethertype(
                bytes,
                inner_ethertype,
                config,
                depth + 1,
                offset + inner_offset,
                ParsedPacket::default(),
            ))
        }
    });
    recurse_or_warn(
        parsed,
        result,
        depth_limited,
        ParseWarningCode::PppoeNoPayload,
        ParseWarningSubcode::PppoeNoPayload,
        offset + inner_offset,
        "PPPoE PPP payload; nested decode failed",
    );
    Ok(())
}

fn recurse_transport_tunnel(
    parsed: &mut ParsedPacket,
    protocol: u8,
    l4_bytes: &[u8],
    config: ParseConfig,
    depth: usize,
    offset: usize,
) {
    let candidate = if let Some(gre) = parsed.gre {
        let inner = l4_bytes.get(gre.header_len..);
        Some((
            inner,
            gre.protocol_type,
            gre.protocol_type == ethertype::TRANSPARENT_ETHERNET_BRIDGING,
            ParseWarningCode::GreInner,
            ParseWarningSubcode::GreInner,
            offset + gre.header_len,
            "GRE inner payload; nested decode failed",
        ))
    } else if parsed.vxlan.is_some() {
        let udp_end = udp_payload_end(parsed, l4_bytes.len());
        Some((
            udp_end.and_then(|end| l4_bytes.get(16..end)),
            0,
            true,
            ParseWarningCode::VxlanInner,
            ParseWarningSubcode::VxlanInner,
            offset + 16,
            "VXLAN inner payload; nested decode failed",
        ))
    } else if let Some(geneve) = parsed.geneve {
        let inner_offset = 8 + geneve.header_len;
        let udp_end = udp_payload_end(parsed, l4_bytes.len());
        Some((
            udp_end.and_then(|end| l4_bytes.get(inner_offset..end)),
            geneve.protocol_type,
            geneve.protocol_type == ethertype::TRANSPARENT_ETHERNET_BRIDGING,
            ParseWarningCode::GeneveInner,
            ParseWarningSubcode::GeneveInner,
            offset + inner_offset,
            "GENEVE inner payload; nested decode failed",
        ))
    } else if protocol == ip_proto::IPV4_ENCAP {
        Some((
            Some(l4_bytes),
            ethertype::IPV4,
            false,
            ParseWarningCode::IpipInner,
            ParseWarningSubcode::IpipInner,
            offset,
            "IP-in-IP inner payload; nested decode failed",
        ))
    } else if protocol == ip_proto::IPV6_ENCAP {
        Some((
            Some(l4_bytes),
            ethertype::IPV6,
            false,
            ParseWarningCode::IpipInner,
            ParseWarningSubcode::IpipInner,
            offset,
            "IP-in-IP inner payload; nested decode failed",
        ))
    } else if protocol == ip_proto::MPLS_IN_IP {
        Some((
            Some(l4_bytes),
            ethertype::MPLS_UNICAST,
            false,
            ParseWarningCode::MplsInner,
            ParseWarningSubcode::MplsInner,
            offset,
            "MPLS-in-IP inner payload; nested decode failed",
        ))
    } else {
        None
    };

    if let Some((inner, inner_ethertype, is_l2, code, subcode, inner_offset, message)) = candidate {
        let has_payload = inner.is_some_and(|bytes| !bytes.is_empty());
        let depth_limited = has_payload && depth >= config.max_tunnel_depth;
        let result = inner.filter(|bytes| !bytes.is_empty()).and_then(|bytes| {
            if depth_limited {
                None
            } else if is_l2 {
                Some(BuiltinPacketParser::parse_l2(bytes, config, depth + 1))
            } else {
                Some(BuiltinPacketParser::parse_l3(
                    bytes,
                    inner_ethertype,
                    config,
                    depth + 1,
                ))
            }
        });
        recurse_or_warn(
            parsed,
            result,
            depth_limited,
            code,
            subcode,
            inner_offset,
            message,
        );
    }

    if parsed.ah.is_some() {
        parsed.warnings.push(ParseWarning {
            code: ParseWarningCode::AhInner,
            protocol: ParseWarningProtocol::Tunnel,
            subcode: ParseWarningSubcode::AhInner,
            offset,
            message: "AH payload present; no nested decode yet",
        });
    }
    if parsed.esp.is_some() {
        parsed.warnings.push(ParseWarning {
            code: ParseWarningCode::EspInner,
            protocol: ParseWarningProtocol::Tunnel,
            subcode: ParseWarningSubcode::EspInner,
            offset,
            message: "ESP payload present; no nested decode yet",
        });
    }
}

fn udp_payload_end(parsed: &ParsedPacket, captured_len: usize) -> Option<usize> {
    match parsed.transport.as_ref()? {
        TransportSegment::Udp(udp) => Some((udp.length as usize).min(captured_len)),
        TransportSegment::Tcp(_) | TransportSegment::Sctp(_) => None,
    }
}

fn recurse_or_warn(
    parsed: &mut ParsedPacket,
    result: Option<Result<ParsedPacket, LayerError>>,
    depth_limited: bool,
    code: ParseWarningCode,
    subcode: ParseWarningSubcode,
    offset: usize,
    message: &'static str,
) {
    if depth_limited {
        parsed.warnings.push(ParseWarning {
            code: ParseWarningCode::TunnelDepthLimit,
            protocol: ParseWarningProtocol::Tunnel,
            subcode: ParseWarningSubcode::TunnelDepthLimit,
            offset,
            message: "tunnel depth limit reached; skipping inner payload decode",
        });
    } else if let Some(Ok(inner)) = result {
        parsed.inner = Some(Box::new(inner));
    } else {
        push_inner_warning(parsed, code, subcode, offset, message);
    }
}

fn push_inner_warning(
    parsed: &mut ParsedPacket,
    code: ParseWarningCode,
    subcode: ParseWarningSubcode,
    offset: usize,
    message: &'static str,
) {
    parsed.warnings.push(ParseWarning {
        code,
        protocol: ParseWarningProtocol::Tunnel,
        subcode,
        offset,
        message,
    });
}

fn apply_transport_parse(parsed: &mut ParsedPacket, transport_parse: transport::TransportParse) {
    parsed.transport = transport_parse.transport;
    parsed.icmp = transport_parse.icmp;
    parsed.icmpv6 = transport_parse.icmpv6;
    parsed.ndp = transport_parse.ndp;
    parsed.igmp = transport_parse.igmp;
    parsed.ospf = transport_parse.ospf;
    parsed.eigrp = transport_parse.eigrp;
    parsed.pim = transport_parse.pim;
    parsed.vrrp = transport_parse.vrrp;
    parsed.sctp = transport_parse.sctp;
    parsed.tcp_options = transport_parse.tcp_options;
    parsed.gre = transport_parse.gre;
    parsed.vxlan = transport_parse.vxlan;
    parsed.geneve = transport_parse.geneve;
    parsed.l2tp = transport_parse.l2tp;
    parsed.ah = transport_parse.ah;
    parsed.esp = transport_parse.esp;
    parsed.wireguard = transport_parse.wireguard;
    parsed.openvpn = transport_parse.openvpn;
    parsed.dnp3 = transport_parse.dnp3;
    parsed.dns = transport_parse.dns;
    parsed.dhcp = transport_parse.dhcp;
    parsed.dhcp6 = transport_parse.dhcp6;
    parsed.tftp = transport_parse.tftp;
    parsed.radius = transport_parse.radius;
    parsed.snmp = transport_parse.snmp;
    parsed.ntp = transport_parse.ntp;
    parsed.tls = transport_parse.tls;
    parsed.tls_server_hello = transport_parse.tls_server_hello;
    parsed.http = transport_parse.http;
    parsed.ssdp = transport_parse.ssdp;
    parsed.nat_pmp = transport_parse.nat_pmp;
    parsed.pcp = transport_parse.pcp;
    parsed.sip = transport_parse.sip;
    parsed.rtcp = transport_parse.rtcp;
    parsed.rtp = transport_parse.rtp;
    parsed.quic = transport_parse.quic;
    parsed.bgp = transport_parse.bgp;
    parsed.ldap = transport_parse.ldap;
    parsed.nntp = transport_parse.nntp;
    parsed.imap = transport_parse.imap;
    parsed.ftp = transport_parse.ftp;
    parsed.smb1 = transport_parse.smb1;
    parsed.smb2 = transport_parse.smb2;
    parsed.smtp = transport_parse.smtp;
    parsed.telnet = transport_parse.telnet;
    parsed.mqtt = transport_parse.mqtt;
    parsed.modbus = transport_parse.modbus;
    parsed.ssh = transport_parse.ssh;
    parsed.ssh_kex_init = transport_parse.ssh_kex_init;
    parsed.coap = transport_parse.coap;
    parsed.kerberos = transport_parse.kerberos;
    parsed.stun = transport_parse.stun;
    parsed.rip = transport_parse.rip;
    parsed.isakmp = transport_parse.isakmp;
    parsed.rpc = transport_parse.rpc;
    parsed.syslog = transport_parse.syslog;
    parsed.hsrp = transport_parse.hsrp;
    parsed.udp_hints = transport_parse.hints;
}

fn parse_fddi_snap(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    const FDDI_HEADER_LEN: usize = 13;
    const SNAP_HEADER_LEN: usize = 8;
    const PAYLOAD_OFFSET: usize = FDDI_HEADER_LEN + SNAP_HEADER_LEN;

    let Some(header) = raw.get(..PAYLOAD_OFFSET) else {
        return Err(LayerError::InvalidLength);
    };
    if header[FDDI_HEADER_LEN..FDDI_HEADER_LEN + 6] != [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00] {
        return Err(LayerError::InvalidHeader);
    }
    let mut destination = [0; 6];
    destination.copy_from_slice(&header[1..7]);
    let mut source = [0; 6];
    source.copy_from_slice(&header[7..13]);

    Ok((
        EthernetFrame {
            destination,
            source,
            ethertype: u16::from_be_bytes([header[19], header[20]]),
            vlan_tags: Vec::new(),
            payload_offset: PAYLOAD_OFFSET,
        },
        PAYLOAD_OFFSET,
    ))
}

fn parse_lldp(data: &[u8]) -> LldpInfo {
    let mut info = LldpInfo {
        chassis_id: None,
        port_id: None,
        ttl: None,
        tlvs: Vec::new(),
    };
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let header = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        let tlv_type = (header >> 9) as u8;
        if tlv_type == 0 {
            break;
        }
        let declared_len = usize::from(header & 0x01ff);
        let truncated = declared_len > data.len().saturating_sub(offset);
        let end = offset.saturating_add(declared_len).min(data.len());
        let value = data[offset..end].to_vec();

        match tlv_type {
            1 => info.chassis_id = value.get(1..).map(<[u8]>::to_vec),
            2 => info.port_id = value.get(1..).map(<[u8]>::to_vec),
            3 if value.len() >= 2 => {
                info.ttl = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            _ => {}
        }
        info.tlvs.push(LldpTlv { tlv_type, value });
        offset = end;
        if truncated {
            break;
        }
    }

    info
}

fn parse_stp(data: &[u8]) -> Result<StpBpdu, LayerError> {
    if data.len() < 35 {
        return Err(LayerError::InvalidLength);
    }
    let protocol_id = u16::from_be_bytes([data[0], data[1]]);
    if protocol_id != 0 {
        return Err(LayerError::InvalidHeader);
    }
    Ok(StpBpdu {
        protocol_id,
        version: data[2],
        bpdu_type: data[3],
        flags: data[4],
        root_id: u64::from_be_bytes(data[5..13].try_into().expect("fixed-length slice")),
        root_path_cost: u32::from_be_bytes(data[13..17].try_into().expect("fixed-length slice")),
        bridge_id: u64::from_be_bytes(data[17..25].try_into().expect("fixed-length slice")),
        port_id: u16::from_be_bytes([data[25], data[26]]),
    })
}

#[cfg(test)]
#[allow(clippy::absolute_paths)]
mod tests {
    use super::{
        BuiltinPacketParser, ParseConfig, ParseMode, ParseWarningCode, ParseWarningProtocol,
        ParseWarningSubcode, TransportSegment,
    };

    fn truncated_ipv4_udp_frame() -> Vec<u8> {
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01,
            0x40, 0x00, 64, 17, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x04, 0xd2, 0x00, 0x35, 0x00,
            0x14, 0x00, 0x00,
        ]
    }

    fn truncated_ipv6_udp_frame() -> Vec<u8> {
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd, 0x60, 0x00, 0x00, 0x00, 0x00, 0x14,
            17, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 2, 0x04, 0xd2, 0x00, 0x35, 0x00, 0x14, 0x00, 0x00,
        ]
    }

    #[test]
    fn parses_bare_dot11_beacon() {
        let frame = vec![
            0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x10, 0x00,
        ];

        let parsed = BuiltinPacketParser::parse_with_linktype(&frame, 105)
            .expect("802.11 beacon should parse");
        let dot11 = parsed.dot11.as_ref().expect("802.11 frame");

        assert_eq!(dot11.frame_type, 0);
        assert_eq!(dot11.frame_subtype, 8);
        assert_eq!(dot11.addr1, [0xff; 6]);
    }

    #[test]
    fn parses_radiotap_dot11_snap_ipv4_udp() {
        let mut frame = vec![0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&[
            0x08, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x10, 0x00,
        ]);
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00, 192, 0, 2, 1, 198,
            51, 100, 2, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x08, 0x00, 0x00,
        ]);

        let parsed = BuiltinPacketParser::parse_with_linktype(&frame, 127)
            .expect("radiotap 802.11 IPv4/UDP should parse");

        assert!(parsed.radiotap.is_some());
        assert_eq!(parsed.dot11.as_ref().map(|frame| frame.frame_type), Some(2));
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn mpls_label_limit_in_config_emits_depth_warning() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x47, 0x00, 0x01, 0x00, 0x40, 0x00, 0x02,
            0x01, 0x40, 0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];

        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                max_mpls_labels: 1,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        let mpls = parsed.mpls.as_ref().expect("mpls parsed");
        assert_eq!(mpls.labels.len(), 1);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::MplsLabelDepthLimit))
        );
    }

    #[test]
    fn strict_mode_rejects_unknown_ethertype() {
        let frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x12, 0x34, 0x00, 0x00];
        let err = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                mode: ParseMode::Strict,
                ..ParseConfig::default()
            },
        )
        .expect_err("strict mode should reject unsupported ethertype");

        assert!(matches!(err, crate::layer::LayerError::ValidationError(_)));
    }

    #[test]
    fn strict_mode_rejects_ipv4_truncated_frame() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x64, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00,
        ];

        let err = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                mode: ParseMode::Strict,
                ..ParseConfig::default()
            },
        )
        .expect_err("strict mode should reject truncated IPv4");

        assert!(matches!(err, crate::layer::LayerError::InvalidLength));
    }

    #[test]
    fn lenient_mode_parses_truncated_ipv4_udp() {
        let parsed = BuiltinPacketParser::parse(&truncated_ipv4_udp_frame())
            .expect("lenient mode should parse truncated IPv4 UDP");

        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.code == ParseWarningCode::Ipv4Truncated)
        );
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn strict_mode_rejects_truncated_ipv4_udp() {
        let err = BuiltinPacketParser::parse_with_config(
            &truncated_ipv4_udp_frame(),
            ParseConfig {
                mode: ParseMode::Strict,
                ..ParseConfig::default()
            },
        )
        .expect_err("strict mode should reject truncated IPv4 UDP");

        assert!(matches!(err, crate::layer::LayerError::InvalidLength));
    }

    #[test]
    fn lenient_mode_parses_truncated_ipv6_udp() {
        let parsed = BuiltinPacketParser::parse(&truncated_ipv6_udp_frame())
            .expect("lenient mode should parse truncated IPv6 UDP");

        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.code == ParseWarningCode::Ipv6Truncated)
        );
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn strict_mode_rejects_truncated_ipv6_udp() {
        let err = BuiltinPacketParser::parse_with_config(
            &truncated_ipv6_udp_frame(),
            ParseConfig {
                mode: ParseMode::Strict,
                ..ParseConfig::default()
            },
        )
        .expect_err("strict mode should reject truncated IPv6 UDP");

        assert!(matches!(err, crate::layer::LayerError::InvalidLength));
    }

    #[test]
    fn warning_metadata_contains_protocol_subcode_and_offset() {
        let frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x12, 0x34, 0x00, 0x00];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let warning = parsed.warnings.first().expect("warning expected");

        assert_eq!(warning.protocol, ParseWarningProtocol::Link);
        assert_eq!(warning.subcode, ParseWarningSubcode::UnsupportedEthertype);
        assert_eq!(warning.offset, 12);
    }

    #[test]
    fn parses_lldp_mandatory_tlvs() {
        let frame = vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x88, 0xcc,
            0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x04, 0x05, 0x05, b'e', b't',
            b'h', b'0', 0x06, 0x02, 0x00, 0x78, 0x00, 0x00,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let lldp = parsed.lldp.as_ref().expect("lldp");

        assert_eq!(lldp.ttl, Some(120));
        assert_eq!(
            lldp.chassis_id.as_deref(),
            Some(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55][..])
        );
        assert_eq!(lldp.port_id.as_deref(), Some(&b"eth0"[..]));
        assert_eq!(lldp.tlvs.len(), 3);
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn parses_lacp_and_silently_skips_marker_protocol() {
        let mut frame = vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x02, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x88, 0x09, 1,
            1, 1, 20, 0, 1, 0, 1, 2, 3, 4, 5, 0, 2, 0, 3, 0, 18,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("LACP frame should parse");
        let lacp = parsed.lacp.expect("LACP header");
        assert_eq!(lacp.subtype, 1);
        assert_eq!(lacp.version, 1);
        assert_eq!(lacp.actor_port, 18);

        frame[14] = 2;
        let marker = BuiltinPacketParser::parse(&frame).expect("Marker frame should parse");
        assert!(marker.lacp.is_none());
    }

    #[test]
    fn parses_stp_config_bpdu_in_802_3_llc_frame() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&[0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]);
        frame.extend_from_slice(&38u16.to_be_bytes());
        frame.extend_from_slice(&[0x42, 0x42, 0x03]);
        frame.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00,
            0x00, 0x00, 0x04, 0x80, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x80, 0x01, 0x00,
            0x00, 0x14, 0x00, 0x02, 0x00, 0x0f, 0x00,
        ]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let stp = parsed.stp.as_ref().expect("stp");

        assert_eq!(stp.protocol_id, 0);
        assert_eq!(stp.bpdu_type, 0);
        assert_eq!(stp.root_path_cost, 4);
        assert_eq!(parsed.ethernet.as_ref().expect("ethernet").ethertype, 0);
        assert_eq!(
            parsed.ethernet.as_ref().expect("ethernet").payload_offset,
            17
        );
    }

    #[test]
    fn parses_cdp_from_llc_snap_ethernet_frame() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]);
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x03]);
        frame.extend_from_slice(&12u16.to_be_bytes());
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00]);
        frame.extend_from_slice(&[1, 180, 0xc6, 0x5e]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let cdp = parsed.cdp.as_ref().expect("CDP header");

        assert_eq!(cdp.version, 1);
        assert_eq!(cdp.ttl, 180);
        assert_eq!(cdp.checksum, 0xc65e);
        assert_eq!(parsed.ethernet.as_ref().expect("ethernet").ethertype, 0);
        assert_eq!(
            parsed.ethernet.as_ref().expect("ethernet").payload_offset,
            22
        );
    }
}
