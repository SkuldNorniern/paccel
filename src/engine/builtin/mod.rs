mod link;
mod network;
mod transport;
mod types;

use crate::engine::constants::{ethertype, ip_proto};
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
use crate::layer::{Layer, LayerError, ParseError};

use self::link::{
    parse_arp_packet, parse_link_with_linktype, parse_mpls_stack, parse_pppoe_minimal,
};
use self::network::{parse_ipv4_header, parse_ipv6_header, resolve_ipv6_transport};
use self::transport::parse_transport;

pub use self::network::Ipv6FragmentHeader;

pub use self::types::{
    AhInfo, ApplicationLayer, ApplicationLayers, EspInfo, EthernetFrame, FlowKey, GeneveInfo,
    GreInfo, IgmpInfo, L2tpInfo, LldpInfo, LldpTlv, MplsInfo, MplsLabel, OpenVpnInfo,
    OpenVpnOpcode, ParseConfig, ParseMode, ParseWarning, ParseWarningCode, ParseWarningProtocol,
    ParsedPacket, PppoeInfo, SctpChunk, SctpInfo, StopLayer, StpBpdu, TcpOptionsParsed,
    TransportSegment, UdpAppHint, VxlanInfo, WireGuardInfo, WireGuardMessageType,
};

pub struct BuiltinPacketParser;

impl BuiltinPacketParser {
    /// # Errors
    /// Returns the layer the parse stopped at and why. See [`ParseError`].
    pub fn parse(raw: &[u8]) -> Result<ParsedPacket, ParseError> {
        Self::parse_with_config(raw, ParseConfig::default())
    }

    /// # Errors
    /// Returns the layer the parse stopped at and why. See [`ParseError`].
    pub fn parse_with_config(raw: &[u8], config: ParseConfig) -> Result<ParsedPacket, ParseError> {
        Self::parse_with_config_and_linktype(raw, config, None)
    }

    /// # Errors
    /// Returns the layer the parse stopped at and why. See [`ParseError`].
    pub fn parse_with_linktype(raw: &[u8], linktype: u16) -> Result<ParsedPacket, ParseError> {
        Self::parse_with_config_and_linktype(raw, ParseConfig::default(), Some(linktype))
    }

    /// # Errors
    /// Returns the layer the parse stopped at and why. See [`ParseError`].
    pub fn parse_with_config_and_linktype(
        raw: &[u8],
        config: ParseConfig,
        linktype: Option<u16>,
    ) -> Result<ParsedPacket, ParseError> {
        // Built once here and filled in by the chain below, so a packet is
        // moved exactly as many times as the public signature demands: once,
        // on the way out.
        let mut parsed = ParsedPacket::default();
        match Self::parse_l2_with_linktype(raw, config, 0, linktype, &mut parsed) {
            Ok(()) => Ok(parsed),
            Err(error) => Err(Self::describe_failure(&error, &parsed)),
        }
    }

    /// Which layer a [`LayerError`] came from, read off how far the parse got.
    ///
    /// The chain keeps the smaller [`LayerError`]; context is recovered here so
    /// the well-formed path pays nothing. `offset` reads 0 above the transport.
    #[cold]
    #[inline(never)]
    fn describe_failure(error: &LayerError, parsed: &ParsedPacket) -> ParseError {
        let reached_link =
            parsed.ethernet.is_some() || parsed.dot11.is_some() || parsed.radiotap.is_some();
        if !reached_link {
            return ParseError::from_layer_error(error, Layer::Link, None, 0);
        }

        let network = if parsed.ipv4.is_some() {
            Some("ipv4")
        } else if parsed.ipv6.is_some() {
            Some("ipv6")
        } else if parsed.arp.is_some() {
            Some("arp")
        } else {
            None
        };
        let Some(network) = network else {
            return ParseError::from_layer_error(error, Layer::Network, None, 0);
        };

        // A tunnel that opened but never produced an inner packet failed as a
        // tunnel, not as the transport it would have carried.
        if parsed.gre.is_some() || parsed.vxlan.is_some() || parsed.geneve.is_some() {
            if parsed.inner.is_none() {
                return ParseError::from_layer_error(error, Layer::Tunnel, None, 0);
            }
            return ParseError::from_layer_error(error, Layer::Application, None, 0);
        }

        let offset = parsed.transport_segment_offset.unwrap_or(0);
        if parsed.transport.is_none() {
            return ParseError::from_layer_error(error, Layer::Transport, Some(network), offset);
        }
        ParseError::from_layer_error(error, Layer::Application, None, offset)
    }

    /// Parse into a packet the caller owns, moving nothing.
    ///
    /// The other entry points return a `ParsedPacket` by value, which is a
    /// large struct to move for every packet. A caller in a loop can keep one
    /// of these and hand it back each time instead.
    ///
    /// `out` is reset first, so a reused buffer never carries a field over
    /// from the packet before it. What the reuse saves is the move and the two
    /// growable vectors; a tunnelled packet still allocates its inner chain.
    /// See [`ParsedPacket::reset`].
    ///
    /// # Errors
    /// Returns the layer the parse stopped at and why. See [`ParseError`].
    pub fn parse_into(
        raw: &[u8],
        config: ParseConfig,
        linktype: Option<u16>,
        out: &mut ParsedPacket,
    ) -> Result<(), ParseError> {
        out.reset();
        match Self::parse_l2_with_linktype(raw, config, 0, linktype, out) {
            Ok(()) => Ok(()),
            Err(error) => Err(Self::describe_failure(&error, out)),
        }
    }

    fn parse_l2(
        raw: &[u8],
        config: ParseConfig,
        depth: usize,
        parsed: &mut ParsedPacket,
    ) -> Result<(), LayerError> {
        Self::parse_l2_with_linktype(raw, config, depth, None, parsed)
    }

    /// Parse the transport header, or in permissive mode say why there is none.
    ///
    /// A capture taken with a short snaplen keeps the addresses and drops the
    /// ports, and headers-only captures are a deliberate practice rather than
    /// corruption. `Permissive` promises to return what was parsed, so a
    /// transport header that did not survive leaves `transport` as `None` with
    /// a warning, exactly as a truncated network header already does. `Strict`
    /// keeps failing.
    /// Returns whether a transport header was parsed and applied.
    ///
    /// The parse is applied here rather than handed back, so `TransportParse`
    /// never crosses a second call boundary. It is a large struct, and
    /// returning it wrapped in an `Option` cost a measurable copy on every
    /// well-formed packet.
    #[inline]
    fn apply_transport_or_warn(
        parsed: &mut ParsedPacket,
        protocol: u8,
        l4_bytes: &[u8],
        config: ParseConfig,
        offset: usize,
    ) -> Result<bool, LayerError> {
        match parse_transport(parsed, protocol, l4_bytes, config) {
            Ok(()) => Ok(true),
            // Kept out of line: a truncated transport header is the rare case,
            // and leaving the warning construction inline slows every
            // well-formed packet down.
            Err(error) => {
                Self::transport_did_not_survive(parsed, protocol, l4_bytes, config, offset, error)
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn transport_did_not_survive(
        parsed: &mut ParsedPacket,
        protocol: u8,
        l4_bytes: &[u8],
        config: ParseConfig,
        offset: usize,
        error: LayerError,
    ) -> Result<bool, LayerError> {
        if config.mode != ParseMode::Permissive {
            return Err(error);
        }

        // TCP, UDP and SCTP all carry their ports in the first four bytes. A
        // snaplen that cut the header short usually left those, and they are
        // the part a flow is keyed on, so keep them rather than throwing away
        // the whole header for want of the rest of it.
        if matches!(protocol, ip_proto::TCP | ip_proto::UDP | ip_proto::SCTP)
            && let Some(ports) = l4_bytes.get(..4)
        {
            parsed.truncated_ports = Some((
                u16::from_be_bytes([ports[0], ports[1]]),
                u16::from_be_bytes([ports[2], ports[3]]),
            ));
        }

        parsed.warnings.push(ParseWarning {
            code: ParseWarningCode::TransportTruncated,
            protocol: ParseWarningProtocol::Transport,
            offset,
            message: "transport header did not survive the capture; \
                      addresses are still valid",
        });
        Ok(false)
    }

    fn parse_l2_with_linktype(
        raw: &[u8],
        config: ParseConfig,
        depth: usize,
        linktype: Option<u16>,
        parsed: &mut ParsedPacket,
    ) -> Result<(), LayerError> {
        match linktype {
            Some(127) => {
                let (radiotap, dot11_offset) = match parse_radiotap(raw) {
                    Ok(value) => value,
                    Err(LayerError::InvalidLength) if config.mode == ParseMode::Permissive => {
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                Self::parse_dot11_l2(&raw[dot11_offset..], config, depth, dot11_offset, parsed)?;
                parsed.radiotap = Some(radiotap);
                return Ok(());
            }
            Some(105) => return Self::parse_dot11_l2(raw, config, depth, 0, parsed),
            _ => {}
        }

        let (eth, l3_offset) = if linktype == Some(10) {
            parse_fddi_snap(raw)?
        } else {
            parse_link_with_linktype(raw, linktype)?
        };
        parsed.ethernet = Some(eth.clone());

        if l3_offset >= raw.len() {
            // Addresses and VLAN tags are good; there is just nothing after
            // them. Permissive keeps them, as it does a truncated IPv4 or
            // transport header.
            if config.mode == ParseMode::Strict {
                return Err(LayerError::InvalidLength);
            }
            parsed.warnings.push(ParseWarning {
                code: ParseWarningCode::LinkPayloadTruncated,
                protocol: ParseWarningProtocol::Link,
                offset: l3_offset,
                message: "link header is complete but nothing follows it; \
                          addresses and vlan tags are still valid",
            });
            return Ok(());
        }

        if eth.ethertype == 0 && eth.payload_offset == 17 {
            parsed.stp = Some(parse_stp(&raw[l3_offset..])?);
            return Ok(());
        }

        if eth.ethertype == 0 && eth.payload_offset == 22 {
            parsed.cdp = parse_cdp_header(&raw[l3_offset..]).ok();
            return Ok(());
        }

        let result = Self::parse_ethertype(
            &raw[l3_offset..],
            eth.ethertype,
            config,
            depth,
            l3_offset,
            parsed,
        );

        // A network header too short to parse was the one failure that still
        // discarded the link addresses and VLAN tags with it.
        match result {
            Err(_) if config.mode == ParseMode::Permissive => {
                parsed.warnings.push(ParseWarning {
                    code: ParseWarningCode::NetworkHeaderUnreadable,
                    protocol: ParseWarningProtocol::Network,
                    offset: l3_offset,
                    message: "network header could not be read; \
                              link addresses and vlan tags are still valid",
                });
                Ok(())
            }
            other => other,
        }
    }

    fn parse_dot11_l2(
        raw: &[u8],
        config: ParseConfig,
        depth: usize,
        frame_offset: usize,
        parsed: &mut ParsedPacket,
    ) -> Result<(), LayerError> {
        let dot11 = match parse_dot11(raw) {
            Ok(dot11) => dot11,
            Err(LayerError::InvalidLength) if config.mode == ParseMode::Permissive => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        parsed.dot11 = Some(dot11);

        if dot11.frame_type != 2 {
            return Ok(());
        }

        let Some(snap) = raw.get(dot11.header_len..dot11.header_len.saturating_add(8)) else {
            return Ok(());
        };
        if snap[..6] != [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00] {
            return Ok(());
        }

        let ethertype = u16::from_be_bytes([snap[6], snap[7]]);
        let l3_frame_offset = dot11.header_len + 8;
        let Some(l3_bytes) = raw.get(l3_frame_offset..) else {
            return Ok(());
        };
        let l3_offset = frame_offset.saturating_add(l3_frame_offset);
        match Self::parse_ethertype(l3_bytes, ethertype, config, depth, l3_offset, parsed) {
            // A truncated payload leaves whatever the inner parse managed to
            // write; reset to just the frame that was definitely read.
            Err(LayerError::InvalidLength) if config.mode == ParseMode::Permissive => {
                *parsed = ParsedPacket {
                    dot11: Some(dot11),
                    ..ParsedPacket::default()
                };
                Ok(())
            }
            other => other,
        }
    }

    fn parse_l3(
        l3_bytes: &[u8],
        ethertype: u16,
        config: ParseConfig,
        depth: usize,
    ) -> Result<ParsedPacket, LayerError> {
        let mut parsed = ParsedPacket::default();
        Self::parse_ethertype(l3_bytes, ethertype, config, depth, 0, &mut parsed)?;
        Ok(parsed)
    }

    #[allow(clippy::cognitive_complexity)]
    fn parse_ethertype(
        l3_bytes: &[u8],
        ethertype: u16,
        config: ParseConfig,
        depth: usize,
        l3_offset: usize,
        parsed: &mut ParsedPacket,
    ) -> Result<(), LayerError> {
        match ethertype {
            ethertype::ARP => {
                let arp = parse_arp_packet(l3_bytes)?;
                parsed.arp = Some(arp);
                Ok(())
            }
            ethertype::IPV4 => {
                let ipv4 = parse_ipv4_header(l3_bytes)?;

                let ip_header_len = (ipv4.ihl as usize) * 4;
                let total_len = ipv4.total_length as usize;
                if total_len < ip_header_len {
                    return Err(LayerError::InvalidLength);
                }

                // The capture stopped inside the options, so the addresses are
                // good and there is nothing after them to read. Permissive
                // keeps the frame and says so; Strict refuses it, the same way
                // both already treat a payload the capture cut short.
                if ipv4.options_truncated {
                    if config.mode == ParseMode::Strict {
                        return Err(LayerError::InvalidLength);
                    }
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv4OptionsTruncated,
                        protocol: ParseWarningProtocol::Network,
                        offset: l3_offset,
                        message: "IPv4 options did not survive the capture; \
                                  addresses are still valid",
                    });
                    parsed.ipv4 = Some(ipv4);
                    return Ok(());
                }

                let truncated = total_len > l3_bytes.len();
                if truncated {
                    if config.mode == ParseMode::Strict {
                        return Err(LayerError::InvalidLength);
                    }
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv4Truncated,
                        protocol: ParseWarningProtocol::Network,
                        offset: l3_offset,
                        message: "IPv4 total length exceeds capture; L4 may be truncated",
                    });
                }

                if (ipv4.flags & 1) != 0 || ipv4.fragment_offset != 0 {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv4Fragmented,
                        protocol: ParseWarningProtocol::Network,
                        offset: l3_offset + 6,
                        message: "IPv4 fragment; no reassembly, L4 may be incomplete",
                    });
                }

                if config.stop_after == StopLayer::Network {
                    parsed.ipv4 = Some(ipv4);
                    return Ok(());
                }

                // Before the transport parse: a strict refusal returns from
                // inside the block below, and this header is what says the
                // failure was the transport's.
                let protocol = ipv4.protocol;
                let fragment_offset = ipv4.fragment_offset;
                parsed.ipv4 = Some(ipv4);

                if fragment_offset == 0 {
                    let l4_end = total_len.min(l3_bytes.len());
                    let l4_bytes = &l3_bytes[ip_header_len..l4_end];
                    // One exit, so a transport header that did not survive
                    // takes the same path out as one that did.
                    if Self::apply_transport_or_warn(
                        parsed,
                        protocol,
                        l4_bytes,
                        config,
                        l3_offset + ip_header_len,
                    )? {
                        parsed.transport_segment_offset = Some(l3_offset + ip_header_len);
                        recurse_transport_tunnel(
                            parsed,
                            protocol,
                            l4_bytes,
                            config,
                            depth,
                            l3_offset + ip_header_len,
                        );
                    }
                }
                Ok(())
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
                        offset: l3_offset,
                        message: "IPv6 payload length exceeds capture; L4 may be truncated",
                    });
                }

                let l4_end = declared_l4_end.min(l3_bytes.len());
                if config.stop_after == StopLayer::Network {
                    parsed.ipv6 = Some(ipv6);
                    return Ok(());
                }

                let ipv6_payload = &l3_bytes[..l4_end];
                let state = resolve_ipv6_transport(
                    ipv6_payload,
                    ipv6.next_header,
                    config.max_ipv6_extension_headers,
                )?;

                // A chain the capture cut short leaves the addresses intact
                // and nothing after them to read. Permissive keeps the frame
                // and says so, the way a truncated transport header does;
                // Strict still refuses it.
                if state.truncated {
                    if config.mode != ParseMode::Permissive {
                        return Err(LayerError::InvalidLength);
                    }
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6ExtensionTruncated,
                        protocol: ParseWarningProtocol::Network,
                        offset: l3_offset + state.l4_offset,
                        message: "IPv6 extension header chain did not survive the \
                                  capture; addresses are still valid",
                    });
                }

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
                        offset: l3_offset + state.l4_offset,
                        message: "IPv6 extension header depth limit reached; skipping L4/L7 parse",
                    });
                }

                if state.non_initial_fragment {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::Ipv6NonInitialFragment,
                        protocol: ParseWarningProtocol::Network,
                        offset: l3_offset + state.l4_offset,
                        message:
                            "IPv6 non-initial fragment encountered; skipping L4/L7 parse without reassembly",
                    });
                }

                // Recorded before the transport parse, for the reason given in
                // the IPv4 branch above.
                parsed.ipv6 = Some(ipv6);

                if !state.non_initial_fragment && !state.depth_limit_hit {
                    let l4_bytes = &ipv6_payload[state.l4_offset..];
                    if Self::apply_transport_or_warn(
                        parsed,
                        state.next_header,
                        l4_bytes,
                        config,
                        l3_offset + state.l4_offset,
                    )? {
                        parsed.transport_segment_offset = Some(l3_offset + state.l4_offset);
                        recurse_transport_tunnel(
                            parsed,
                            state.next_header,
                            l4_bytes,
                            config,
                            depth,
                            l3_offset + state.l4_offset,
                        );
                    }
                }

                Ok(())
            }
            ethertype::PPPOE_DISCOVERY => {
                let pppoe = parse_pppoe_minimal(l3_bytes)?;
                parsed.pppoe = Some(pppoe);
                parsed.warnings.push(ParseWarning {
                    code: ParseWarningCode::PppoeNoPayload,
                    protocol: ParseWarningProtocol::Tunnel,
                    offset: l3_offset,
                    message: "PPPoE header only; payload not decoded",
                });
                Ok(())
            }
            ethertype::PPPOE_SESSION => {
                let pppoe = parse_pppoe_minimal(l3_bytes)?;
                parsed.pppoe = Some(pppoe);
                decode_pppoe_session(parsed, l3_bytes, config, depth, l3_offset)?;
                Ok(())
            }
            ethertype::MPLS_UNICAST | ethertype::MPLS_MULTICAST => {
                let (mpls, mpls_payload_offset, depth_limit_hit) =
                    parse_mpls_stack(l3_bytes, config.max_mpls_labels)?;
                parsed.mpls = Some(mpls);
                if depth_limit_hit {
                    parsed.warnings.push(ParseWarning {
                        code: ParseWarningCode::MplsLabelDepthLimit,
                        protocol: ParseWarningProtocol::Tunnel,
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
                            parsed,
                            result,
                            tunnel_depth_limited,
                            ParseWarningCode::MplsInner,
                            l3_offset + mpls_payload_offset,
                            "MPLS inner payload; nested decode failed",
                        );
                    } else {
                        push_inner_warning(
                            parsed,
                            ParseWarningCode::MplsInner,
                            l3_offset + mpls_payload_offset,
                            "MPLS inner payload; nested decode skipped",
                        );
                    }
                }
                Ok(())
            }
            ethertype::LLDP => {
                parsed.lldp = Some(parse_lldp(l3_bytes));
                Ok(())
            }
            ethertype::SLOW_PROTOCOLS => {
                parsed.lacp = parse_lacp_header(l3_bytes).ok();
                Ok(())
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
                    offset: 12,
                    message: "L2 only; unsupported ethertype, L3+ not parsed",
                });
                Ok(())
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
            // The inner packet is its own value: a tunnel hangs it off
            // `inner`, so it cannot share the outer buffer.
            let mut inner_parsed = ParsedPacket::default();
            Some(
                BuiltinPacketParser::parse_ethertype(
                    bytes,
                    inner_ethertype,
                    config,
                    depth + 1,
                    offset + inner_offset,
                    &mut inner_parsed,
                )
                .map(|()| inner_parsed),
            )
        }
    });
    recurse_or_warn(
        parsed,
        result,
        depth_limited,
        ParseWarningCode::PppoeNoPayload,
        offset + inner_offset,
        "PPPoE PPP payload; nested decode failed",
    );
    Ok(())
}

/// Where a GRE payload starts, or `None` when it cannot be located.
///
/// With the routing bit set, RFC 1701 sec 4.1 puts a source-route list after
/// the fixed fields, so the payload is not at `header_len`. RFC 2784 sec 2.3.1
/// deprecates routing and says discard.
type GreInnerCandidate<'a> = (
    Option<&'a [u8]>,
    u16,
    bool,
    ParseWarningCode,
    usize,
    &'static str,
);

fn gre_inner(gre: GreInfo, l4_bytes: &[u8], offset: usize) -> Option<GreInnerCandidate<'_>> {
    if gre.routing_present {
        return None;
    }
    Some((
        l4_bytes.get(gre.header_len..),
        gre.protocol_type,
        gre.protocol_type == ethertype::TRANSPARENT_ETHERNET_BRIDGING,
        ParseWarningCode::GreInner,
        offset + gre.header_len,
        "GRE inner payload; nested decode failed",
    ))
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
        let Some(candidate) = gre_inner(gre, l4_bytes, offset) else {
            return;
        };
        Some(candidate)
    } else if parsed.vxlan.is_some() {
        let udp_end = udp_payload_end(parsed, l4_bytes.len());
        Some((
            udp_end.and_then(|end| l4_bytes.get(16..end)),
            0,
            true,
            ParseWarningCode::VxlanInner,
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
            offset + inner_offset,
            "GENEVE inner payload; nested decode failed",
        ))
    } else if protocol == ip_proto::IPV4_ENCAP {
        Some((
            Some(l4_bytes),
            ethertype::IPV4,
            false,
            ParseWarningCode::IpipInner,
            offset,
            "IP-in-IP inner payload; nested decode failed",
        ))
    } else if protocol == ip_proto::IPV6_ENCAP {
        Some((
            Some(l4_bytes),
            ethertype::IPV6,
            false,
            ParseWarningCode::IpipInner,
            offset,
            "IP-in-IP inner payload; nested decode failed",
        ))
    } else if protocol == ip_proto::MPLS_IN_IP {
        Some((
            Some(l4_bytes),
            ethertype::MPLS_UNICAST,
            false,
            ParseWarningCode::MplsInner,
            offset,
            "MPLS-in-IP inner payload; nested decode failed",
        ))
    } else {
        None
    };

    if let Some((inner, inner_ethertype, is_l2, code, inner_offset, message)) = candidate {
        let has_payload = inner.is_some_and(|bytes| !bytes.is_empty());
        let depth_limited = has_payload && depth >= config.max_tunnel_depth;
        let result = inner.filter(|bytes| !bytes.is_empty()).and_then(|bytes| {
            if depth_limited {
                None
            } else if is_l2 {
                let mut inner_parsed = ParsedPacket::default();
                Some(
                    BuiltinPacketParser::parse_l2(bytes, config, depth + 1, &mut inner_parsed)
                        .map(|()| inner_parsed),
                )
            } else {
                Some(BuiltinPacketParser::parse_l3(
                    bytes,
                    inner_ethertype,
                    config,
                    depth + 1,
                ))
            }
        });
        recurse_or_warn(parsed, result, depth_limited, code, inner_offset, message);
    }

    if parsed.ah.is_some() {
        parsed.warnings.push(ParseWarning {
            code: ParseWarningCode::AhInner,
            protocol: ParseWarningProtocol::Tunnel,
            offset,
            message: "AH payload present; no nested decode yet",
        });
    }
    if parsed.esp.is_some() {
        parsed.warnings.push(ParseWarning {
            code: ParseWarningCode::EspInner,
            protocol: ParseWarningProtocol::Tunnel,
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
    offset: usize,
    message: &'static str,
) {
    if depth_limited {
        parsed.warnings.push(ParseWarning {
            code: ParseWarningCode::TunnelDepthLimit,
            protocol: ParseWarningProtocol::Tunnel,
            offset,
            message: "tunnel depth limit reached; skipping inner payload decode",
        });
    } else if let Some(Ok(inner)) = result {
        parsed.inner = Some(Box::new(inner));
    } else {
        push_inner_warning(parsed, code, offset, message);
    }
}

fn push_inner_warning(
    parsed: &mut ParsedPacket,
    code: ParseWarningCode,
    offset: usize,
    message: &'static str,
) {
    parsed.warnings.push(ParseWarning {
        code,
        protocol: ParseWarningProtocol::Tunnel,
        offset,
        message,
    });
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
mod parse_into_tests {
    use super::*;

    fn ethernet_ipv4(protocol: u8, l4: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let total = u16::try_from(20 + l4.len()).expect("test frame fits");
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0];
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.extend_from_slice(&[192, 0, 2, 10]);
        ip.extend_from_slice(&[198, 51, 100, 20]);
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(l4);
        frame
    }

    #[test]
    fn parse_into_matches_parsing_by_value() {
        let mut tcp = vec![0u8; 20];
        tcp[12] = 5 << 4;
        let frame = ethernet_ipv4(6, &tcp);
        let config = ParseConfig::default();

        let owned = BuiltinPacketParser::parse_with_config_and_linktype(&frame, config, Some(1))
            .expect("parses");
        let mut into = ParsedPacket::default();
        BuiltinPacketParser::parse_into(&frame, config, Some(1), &mut into).expect("parses");

        assert_eq!(format!("{owned:?}"), format!("{into:?}"));
    }

    /// The whole point of the API is reusing one buffer, so a field set by one
    /// packet must not still be there for the next.
    #[test]
    fn a_reused_buffer_carries_nothing_over() {
        let config = ParseConfig::default();
        let mut buffer = ParsedPacket::default();

        let mut tcp = vec![0u8; 20];
        tcp[12] = 5 << 4;
        BuiltinPacketParser::parse_into(&ethernet_ipv4(6, &tcp), config, Some(1), &mut buffer)
            .expect("parses");
        assert!(buffer.transport.is_some(), "the TCP packet set a transport");

        // ICMP next: it has no transport segment, so the previous one must go.
        BuiltinPacketParser::parse_into(
            &ethernet_ipv4(1, &[8, 0, 0, 0, 0, 0, 0, 0]),
            config,
            Some(1),
            &mut buffer,
        )
        .expect("parses");

        assert!(buffer.icmp.is_some(), "the ICMP header was read");
        assert!(
            buffer.transport.is_none(),
            "the previous packet's transport segment is still there"
        );
    }

    #[test]
    fn reset_keeps_the_capacity_it_has_grown() {
        let mut packet = ParsedPacket::default();
        packet.warnings.push(ParseWarning {
            code: ParseWarningCode::Ipv4Truncated,
            protocol: ParseWarningProtocol::Network,
            offset: 0,
            message: "test",
        });
        let capacity = packet.warnings.capacity();

        packet.reset();

        assert!(packet.warnings.is_empty());
        assert_eq!(packet.warnings.capacity(), capacity, "allocation is reused");
    }
}

#[cfg(test)]
#[allow(clippy::absolute_paths)]
mod tests {
    use super::{
        BuiltinPacketParser, ParseConfig, ParseMode, ParseWarningCode, ParseWarningProtocol,
        TransportSegment,
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

        // An unhandled ethertype arrives as ValidationError, which maps to
        // InvalidValue. Unsupported would read better, but LayerError's
        // UnsupportedProtocol carries a u8 and an ethertype is a u16.
        assert_eq!(err.kind, crate::layer::ParseErrorKind::InvalidValue);
        assert_eq!(
            err.layer,
            crate::layer::Layer::Network,
            "the ethernet header parsed, so the ethertype is a network-layer refusal"
        );
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

        assert_eq!(err.kind, crate::layer::ParseErrorKind::InvalidLength);
        assert_eq!(err.layer, crate::layer::Layer::Network);
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

    /// An IPv4 header whose total_length is honest, followed by only half a
    /// UDP header. Nothing overruns, so the network layer is satisfied and the
    /// transport header is the one that cannot be read.
    fn ipv4_with_half_a_udp_header() -> Vec<u8> {
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, // ethernet
            0x45, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, 64, 17, 0, 0, // ipv4, total 24
            192, 168, 1, 1, 192, 168, 1, 2, 0x04, 0xd2, 0x00, 0x35, // 4 of udp's 8 bytes
        ]
    }

    #[test]
    fn a_failure_names_the_layer_that_actually_failed() {
        let err = BuiltinPacketParser::parse_with_config(
            &ipv4_with_half_a_udp_header(),
            ParseConfig {
                mode: ParseMode::Strict,
                ..ParseConfig::default()
            },
        )
        .expect_err("half a udp header cannot be parsed strictly");

        assert_eq!(
            err.layer,
            crate::layer::Layer::Transport,
            "the ipv4 header is complete and consistent, so the failure is the transport's"
        );
        assert_eq!(err.protocol, Some("ipv4"));
        assert_eq!(err.kind, crate::layer::ParseErrorKind::InvalidLength);
    }

    #[test]
    fn a_frame_too_short_for_a_link_header_fails_at_the_link_layer() {
        let err =
            BuiltinPacketParser::parse(&[0, 1, 2, 3]).expect_err("four bytes are not a frame");

        assert_eq!(err.layer, crate::layer::Layer::Link);
        assert_eq!(err.protocol, None);
        assert_eq!(err.offset, 0);
    }

    /// The same bytes are kept by a permissive parse, which is what makes the
    /// strict refusal above a choice rather than the only outcome.
    #[test]
    fn permissive_keeps_the_addresses_when_the_transport_header_is_cut() {
        let parsed = BuiltinPacketParser::parse(&ipv4_with_half_a_udp_header())
            .expect("permissive keeps what survived");

        assert!(parsed.ipv4.is_some(), "the addresses are still good");
        assert!(parsed.transport.is_none(), "nothing is invented");
        assert_eq!(
            parsed.ports(),
            Some((1234, 53)),
            "the ports were in the four bytes that did survive"
        );
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

        // The UDP header is whole; the IPv4 total_length of 40 overruns the 28
        // captured bytes. Network failing, not transport, despite the name.
        assert_eq!(err.kind, crate::layer::ParseErrorKind::InvalidLength);
        assert_eq!(err.layer, crate::layer::Layer::Network);
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

        // As with IPv4 above: the declared payload length overruns the
        // capture, so the refusal belongs to the network layer.
        assert_eq!(err.kind, crate::layer::ParseErrorKind::InvalidLength);
        assert_eq!(err.layer, crate::layer::Layer::Network);
    }

    #[test]
    fn warning_metadata_contains_protocol_code_and_offset() {
        let frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x12, 0x34, 0x00, 0x00];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let warning = parsed.warnings.first().expect("warning expected");

        assert_eq!(warning.protocol, ParseWarningProtocol::Link);
        assert!(matches!(
            warning.code,
            ParseWarningCode::UnsupportedEthertype(_)
        ));
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
