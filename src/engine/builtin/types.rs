use crate::layer::application::dns::DnsMessage;
use crate::layer::datalink::arp::ArpPacket;
use crate::layer::network::icmp::IcmpHeader;
use crate::layer::network::icmpv6::Icmpv6Header;
use crate::layer::network::ipv4::Ipv4Header;
use crate::layer::network::ipv6::Ipv6Header;
use crate::layer::transport::tcp::TcpHeader;
use crate::layer::transport::udp::UdpHeader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseWarningCode {
    Ipv6NonInitialFragment,
    Ipv6ExtensionDepthLimit,
    UnsupportedEthertype(u16),
    Ipv4Truncated,
    Ipv4Fragmented,
    GreInner,
    PppoeNoPayload,
    VxlanInner,
    GeneveInner,
    AhInner,
    EspInner,
    MplsInner,
    MplsLabelDepthLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseWarningProtocol {
    Link,
    Network,
    Transport,
    Tunnel,
}

impl ParseWarningProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Network => "network",
            Self::Transport => "transport",
            Self::Tunnel => "tunnel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseWarningSubcode {
    UnsupportedEthertype,
    Ipv4Truncated,
    Ipv4Fragmented,
    Ipv6ExtensionDepthLimit,
    Ipv6NonInitialFragment,
    PppoeNoPayload,
    MplsInner,
    MplsLabelDepthLimit,
    GreInner,
    VxlanInner,
    GeneveInner,
    AhInner,
    EspInner,
}

impl ParseWarningSubcode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedEthertype => "unsupported-ethertype",
            Self::Ipv4Truncated => "ipv4-truncated",
            Self::Ipv4Fragmented => "ipv4-fragmented",
            Self::Ipv6ExtensionDepthLimit => "ipv6-ext-depth-limit",
            Self::Ipv6NonInitialFragment => "ipv6-non-initial-fragment",
            Self::PppoeNoPayload => "pppoe-no-payload",
            Self::MplsInner => "mpls-inner",
            Self::MplsLabelDepthLimit => "mpls-label-depth-limit",
            Self::GreInner => "gre-inner",
            Self::VxlanInner => "vxlan-inner",
            Self::GeneveInner => "geneve-inner",
            Self::AhInner => "ah-inner",
            Self::EspInner => "esp-inner",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgmpInfo {
    pub msg_type: u8,
    pub group_address: Option<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpOptionsParsed {
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub ts_val: Option<u32>,
    pub ts_ecr: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GreInfo {
    pub protocol_type: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PppoeInfo {
    pub code: u8,
    pub session_id: u16,
    pub length: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VxlanInfo {
    pub vni: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneveInfo {
    pub version: u8,
    pub protocol_type: u16,
    pub vni: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhInfo {
    pub next_header: u8,
    pub payload_len: u8,
    pub spi: u32,
    pub sequence: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspInfo {
    pub spi: u32,
    pub sequence: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardMessageType {
    HandshakeInitiation,
    HandshakeResponse,
    CookieReply,
    TransportData,
}

impl WireGuardMessageType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HandshakeInitiation => "handshake-initiation",
            Self::HandshakeResponse => "handshake-response",
            Self::CookieReply => "cookie-reply",
            Self::TransportData => "transport-data",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireGuardInfo {
    pub message_type: WireGuardMessageType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MplsLabel {
    pub label: u32,
    pub exp: u8,
    pub bottom_of_stack: bool,
    pub ttl: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MplsInfo {
    pub labels: Vec<MplsLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseWarning {
    pub code: ParseWarningCode,
    pub protocol: ParseWarningProtocol,
    pub subcode: ParseWarningSubcode,
    pub offset: usize,
    pub message: &'static str,
}

impl ParseWarning {
    pub fn new(
        code: ParseWarningCode,
        protocol: ParseWarningProtocol,
        subcode: ParseWarningSubcode,
        offset: usize,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            protocol,
            subcode,
            offset,
            message,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    Permissive,
    Strict,
}

impl ParseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permissive => "permissive",
            Self::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ParseConfig {
    pub max_ipv6_extension_headers: usize,
    pub max_mpls_labels: usize,
    pub mode: ParseMode,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self {
            max_ipv6_extension_headers: 8,
            max_mpls_labels: 8,
            mode: ParseMode::Permissive,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAppHint {
    Dns,
    Mdns,
    Dhcp,
    Ntp,
    WireGuard,
}

impl UdpAppHint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Mdns => "mdns",
            Self::Dhcp => "dhcp",
            Self::Ntp => "ntp",
            Self::WireGuard => "wireguard",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EthernetFrame {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
    pub vlan_tags: Vec<u16>,
    pub payload_offset: usize,
}

#[derive(Debug)]
pub enum TransportSegment {
    Tcp(TcpHeader),
    Udp(UdpHeader),
}

#[derive(Debug, Default)]
pub struct ParsedPacket {
    pub ethernet: Option<EthernetFrame>,
    pub arp: Option<ArpPacket>,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub transport: Option<TransportSegment>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
    pub igmp: Option<IgmpInfo>,
    pub tcp_options: Option<TcpOptionsParsed>,
    pub gre: Option<GreInfo>,
    pub pppoe: Option<PppoeInfo>,
    pub vxlan: Option<VxlanInfo>,
    pub geneve: Option<GeneveInfo>,
    pub ah: Option<AhInfo>,
    pub esp: Option<EspInfo>,
    pub wireguard: Option<WireGuardInfo>,
    pub mpls: Option<MplsInfo>,
    pub dns: Option<DnsMessage>,
    pub udp_hints: Vec<UdpAppHint>,
    pub warnings: Vec<ParseWarning>,
}

impl ParsedPacket {
    pub fn link_protocol_name(&self) -> Option<&'static str> {
        self.ethernet
            .as_ref()
            .map(|eth| crate::engine::constants::ethertype_name(eth.ethertype))
    }

    pub fn network_protocol_name(&self) -> Option<&'static str> {
        if self.arp.is_some() {
            Some("arp")
        } else if self.ipv4.is_some() {
            Some("ipv4")
        } else if self.ipv6.is_some() {
            Some("ipv6")
        } else {
            None
        }
    }

    pub fn transport_protocol_name(&self) -> Option<&'static str> {
        match self.transport {
            Some(TransportSegment::Tcp(_)) => Some("tcp"),
            Some(TransportSegment::Udp(_)) => Some("udp"),
            None => None,
        }
    }

    pub fn warning_subcode_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.warnings.iter().map(|w| w.subcode.as_str())
    }

    pub fn tunnel_protocol_names(&self) -> impl Iterator<Item = &'static str> {
        [
            self.gre.as_ref().map(|_| "gre"),
            self.vxlan.as_ref().map(|_| "vxlan"),
            self.geneve.as_ref().map(|_| "geneve"),
            self.mpls.as_ref().map(|_| "mpls"),
            self.pppoe.as_ref().map(|_| "pppoe"),
            self.ah.as_ref().map(|_| "ah"),
            self.esp.as_ref().map(|_| "esp"),
            self.wireguard.as_ref().map(|_| "wireguard"),
        ]
        .into_iter()
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ParseMode, ParseWarningProtocol, ParseWarningSubcode, UdpAppHint, WireGuardMessageType,
    };

    #[test]
    fn stable_name_helpers_are_exposed() {
        assert_eq!(ParseMode::Permissive.as_str(), "permissive");
        assert_eq!(ParseWarningProtocol::Tunnel.as_str(), "tunnel");
        assert_eq!(ParseWarningSubcode::VxlanInner.as_str(), "vxlan-inner");
        assert_eq!(UdpAppHint::WireGuard.as_str(), "wireguard");
        assert_eq!(
            WireGuardMessageType::HandshakeInitiation.as_str(),
            "handshake-initiation"
        );
    }
}
