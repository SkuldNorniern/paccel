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
