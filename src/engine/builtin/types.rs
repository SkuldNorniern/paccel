use std::net::{IpAddr, Ipv4Addr};

use crate::engine::constants::ethertype_name;
use crate::layer::application::bgp::BgpMessage;
use crate::layer::application::coap::CoapMessage;
use crate::layer::application::dhcp::DhcpMessage;
use crate::layer::application::dhcp6::Dhcp6Message;
use crate::layer::application::dnp3::Dnp3Message;
use crate::layer::application::dns::DnsMessage;
use crate::layer::application::ftp::FtpMessage;
use crate::layer::application::http::HttpMessage;
use crate::layer::application::isakmp::IsakmpHeader;
use crate::layer::application::kerberos::KerberosMessage;
use crate::layer::application::ldap::LdapMessage;
use crate::layer::application::modbus::ModbusMessage;
use crate::layer::application::mqtt::MqttMessage;
use crate::layer::application::nat_pmp::NatPmpMessage;
use crate::layer::application::nntp::NntpMessage;
use crate::layer::application::ntp::NtpMessage;
use crate::layer::application::ospf::OspfHeader;
use crate::layer::application::pcp::PcpHeader;
use crate::layer::application::quic::QuicLongHeader;
use crate::layer::application::radius::RadiusMessage;
use crate::layer::application::rip::RipHeader;
use crate::layer::application::rtcp::RtcpHeader;
use crate::layer::application::rtp::RtpHeader;
use crate::layer::application::sip::SipMessage;
use crate::layer::application::smtp::SmtpMessage;
use crate::layer::application::snmp::SnmpMessage;
use crate::layer::application::ssdp::SsdpMessage;
use crate::layer::application::ssh::SshBanner;
use crate::layer::application::stun::StunMessage;
use crate::layer::application::telnet::TelnetCommand;
use crate::layer::application::tftp::TftpMessage;
use crate::layer::application::tls::TlsClientHello;
use crate::layer::datalink::arp::ArpPacket;
use crate::layer::datalink::dot11::{Dot11Frame, RadiotapHeader};
use crate::layer::network::icmp::IcmpHeader;
use crate::layer::network::icmpv6::{Icmpv6Header, NdpMessage};
use crate::layer::network::ipv4::Ipv4Header;
use crate::layer::network::ipv6::Ipv6Header;
use crate::layer::transport::tcp::TcpHeader;
use crate::layer::transport::udp::UdpHeader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseWarningCode {
    Ipv6NonInitialFragment,
    Ipv6ExtensionDepthLimit,
    Ipv6Truncated,
    UnsupportedEthertype(u16),
    Ipv4Truncated,
    Ipv4Fragmented,
    IpipInner,
    GreInner,
    PppoeNoPayload,
    VxlanInner,
    GeneveInner,
    AhInner,
    EspInner,
    MplsInner,
    MplsLabelDepthLimit,
    TunnelDepthLimit,
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
    Ipv6Truncated,
    Ipv6ExtensionDepthLimit,
    Ipv6NonInitialFragment,
    IpipInner,
    PppoeNoPayload,
    MplsInner,
    MplsLabelDepthLimit,
    TunnelDepthLimit,
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
            Self::Ipv6Truncated => "ipv6-truncated",
            Self::Ipv6ExtensionDepthLimit => "ipv6-ext-depth-limit",
            Self::Ipv6NonInitialFragment => "ipv6-non-initial-fragment",
            Self::IpipInner => "ipip-inner",
            Self::PppoeNoPayload => "pppoe-no-payload",
            Self::MplsInner => "mpls-inner",
            Self::MplsLabelDepthLimit => "mpls-label-depth-limit",
            Self::TunnelDepthLimit => "tunnel-depth-limit",
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
    pub group_address: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SctpChunk {
    pub chunk_type: u8,
    pub flags: u8,
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpInfo {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
    pub chunks: Vec<SctpChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LldpTlv {
    pub tlv_type: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LldpInfo {
    pub chassis_id: Option<Vec<u8>>,
    pub port_id: Option<Vec<u8>>,
    pub ttl: Option<u16>,
    pub tlvs: Vec<LldpTlv>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StpBpdu {
    pub protocol_id: u16,
    pub version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: u64,
    pub root_path_cost: u32,
    pub bridge_id: u64,
    pub port_id: u16,
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
    pub checksum_present: bool,
    pub key_present: bool,
    pub sequence_present: bool,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
    pub header_len: usize,
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
    pub opt_len: u8,
    pub protocol_type: u16,
    pub vni: u32,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2tpInfo {
    pub flags: u16,
    pub version: u8,
    pub tunnel_id: Option<u16>,
    pub session_id: Option<u16>,
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
pub enum OpenVpnOpcode {
    ControlHardResetClientV1,
    ControlHardResetServerV1,
    ControlSoftResetV1,
    ControlV1,
    AckV1,
    DataV1,
    ControlHardResetClientV2,
    ControlHardResetServerV2,
    DataV2,
    ControlHardResetClientV3,
    ControlWrappedKeyV1,
}

impl OpenVpnOpcode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlHardResetClientV1 => "control-hard-reset-client-v1",
            Self::ControlHardResetServerV1 => "control-hard-reset-server-v1",
            Self::ControlSoftResetV1 => "control-soft-reset-v1",
            Self::ControlV1 => "control-v1",
            Self::AckV1 => "ack-v1",
            Self::DataV1 => "data-v1",
            Self::ControlHardResetClientV2 => "control-hard-reset-client-v2",
            Self::ControlHardResetServerV2 => "control-hard-reset-server-v2",
            Self::DataV2 => "data-v2",
            Self::ControlHardResetClientV3 => "control-hard-reset-client-v3",
            Self::ControlWrappedKeyV1 => "control-wrapped-key-v1",
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::ControlHardResetClientV1),
            2 => Some(Self::ControlHardResetServerV1),
            3 => Some(Self::ControlSoftResetV1),
            4 => Some(Self::ControlV1),
            5 => Some(Self::AckV1),
            6 => Some(Self::DataV1),
            7 => Some(Self::ControlHardResetClientV2),
            8 => Some(Self::ControlHardResetServerV2),
            9 => Some(Self::DataV2),
            10 => Some(Self::ControlHardResetClientV3),
            11 => Some(Self::ControlWrappedKeyV1),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenVpnInfo {
    pub opcode: OpenVpnOpcode,
    pub key_id: u8,
    pub session_id: Option<u64>,
    pub peer_id: Option<u32>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopLayer {
    Network,
    Transport,
    Application,
}

#[derive(Debug, Clone, Copy)]
pub struct ParseConfig {
    pub max_ipv6_extension_headers: usize,
    pub max_mpls_labels: usize,
    pub max_tunnel_depth: usize,
    pub mode: ParseMode,
    pub stop_after: StopLayer,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self {
            max_ipv6_extension_headers: 8,
            max_mpls_labels: 8,
            max_tunnel_depth: 4,
            mode: ParseMode::Permissive,
            stop_after: StopLayer::Application,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAppHint {
    Dns,
    Mdns,
    Dhcp,
    Dhcpv6,
    Tftp,
    Radius,
    Snmp,
    Ntp,
    L2tp,
    WireGuard,
    OpenVpn,
    Sip,
    Rtcp,
    Rtp,
    Coap,
    Ssdp,
    NatPmp,
    Pcp,
    Kerberos,
    Stun,
    Rip,
    Isakmp,
    Llmnr,
    Nbns,
    QuicShort,
}

impl UdpAppHint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Mdns => "mdns",
            Self::Dhcp => "dhcp",
            Self::Dhcpv6 => "dhcpv6",
            Self::Tftp => "tftp",
            Self::Radius => "radius",
            Self::Snmp => "snmp",
            Self::Ntp => "ntp",
            Self::L2tp => "l2tp",
            Self::WireGuard => "wireguard",
            Self::OpenVpn => "openvpn",
            Self::Sip => "sip",
            Self::Rtcp => "rtcp",
            Self::Rtp => "rtp",
            Self::Coap => "coap",
            Self::Ssdp => "ssdp",
            Self::NatPmp => "nat-pmp",
            Self::Pcp => "pcp",
            Self::Kerberos => "kerberos",
            Self::Stun => "stun",
            Self::Rip => "rip",
            Self::Isakmp => "isakmp",
            Self::Llmnr => "llmnr",
            Self::Nbns => "nbns",
            Self::QuicShort => "quic-short",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

#[derive(Debug, Default)]
pub struct ParsedPacket {
    pub ethernet: Option<EthernetFrame>,
    pub radiotap: Option<RadiotapHeader>,
    pub dot11: Option<Dot11Frame>,
    pub arp: Option<ArpPacket>,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub transport: Option<TransportSegment>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
    pub ndp: Option<NdpMessage>,
    pub igmp: Option<IgmpInfo>,
    pub ospf: Option<OspfHeader>,
    pub sctp: Option<SctpInfo>,
    pub tcp_options: Option<TcpOptionsParsed>,
    pub gre: Option<GreInfo>,
    pub pppoe: Option<PppoeInfo>,
    pub vxlan: Option<VxlanInfo>,
    pub geneve: Option<GeneveInfo>,
    pub l2tp: Option<L2tpInfo>,
    pub ah: Option<AhInfo>,
    pub esp: Option<EspInfo>,
    pub wireguard: Option<WireGuardInfo>,
    pub openvpn: Option<OpenVpnInfo>,
    pub dnp3: Option<Dnp3Message>,
    pub mpls: Option<MplsInfo>,
    pub lldp: Option<LldpInfo>,
    pub stp: Option<StpBpdu>,
    pub dns: Option<DnsMessage>,
    pub dhcp: Option<DhcpMessage>,
    pub dhcp6: Option<Dhcp6Message>,
    pub tftp: Option<TftpMessage>,
    pub radius: Option<RadiusMessage>,
    pub snmp: Option<SnmpMessage>,
    pub ntp: Option<NtpMessage>,
    pub tls: Option<TlsClientHello>,
    pub http: Option<HttpMessage>,
    pub ssdp: Option<SsdpMessage>,
    pub nat_pmp: Option<NatPmpMessage>,
    pub pcp: Option<PcpHeader>,
    pub sip: Option<SipMessage>,
    pub rtcp: Option<RtcpHeader>,
    pub rtp: Option<RtpHeader>,
    pub quic: Option<QuicLongHeader>,
    pub bgp: Option<BgpMessage>,
    pub ldap: Option<LdapMessage>,
    pub nntp: Option<NntpMessage>,
    pub ftp: Option<FtpMessage>,
    pub smtp: Option<SmtpMessage>,
    pub telnet: Option<TelnetCommand>,
    pub mqtt: Option<MqttMessage>,
    pub modbus: Option<ModbusMessage>,
    pub ssh: Option<SshBanner>,
    pub coap: Option<CoapMessage>,
    pub kerberos: Option<KerberosMessage>,
    pub stun: Option<StunMessage>,
    pub rip: Option<RipHeader>,
    pub isakmp: Option<IsakmpHeader>,
    pub udp_hints: Vec<UdpAppHint>,
    pub warnings: Vec<ParseWarning>,
    pub inner: Option<Box<ParsedPacket>>,
}

impl ParsedPacket {
    pub fn flow_key(&self) -> Option<FlowKey> {
        if let Some(inner) = self.inner.as_deref() {
            return inner.flow_key();
        }

        let (src_ip, dst_ip, protocol) = if let Some(ipv4) = self.ipv4.as_ref() {
            (
                IpAddr::V4(ipv4.source),
                IpAddr::V4(ipv4.destination),
                ipv4.protocol,
            )
        } else if let Some(ipv6) = self.ipv6.as_ref() {
            (
                IpAddr::V6(ipv6.source),
                IpAddr::V6(ipv6.destination),
                ipv6.next_header,
            )
        } else {
            return None;
        };

        let (src_port, dst_port) = match self.transport.as_ref() {
            Some(TransportSegment::Tcp(tcp)) => (tcp.source_port, tcp.destination_port),
            Some(TransportSegment::Udp(udp)) => (udp.source_port, udp.destination_port),
            None => (0, 0),
        };

        Some(FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        })
    }

    pub fn reverse_flow_key(&self) -> Option<FlowKey> {
        self.flow_key().map(|key| FlowKey {
            src_ip: key.dst_ip,
            dst_ip: key.src_ip,
            src_port: key.dst_port,
            dst_port: key.src_port,
            protocol: key.protocol,
        })
    }

    pub fn link_protocol_name(&self) -> Option<&'static str> {
        self.ethernet
            .as_ref()
            .map(|eth| ethertype_name(eth.ethertype))
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
            None if self.sctp.is_some() => Some("sctp"),
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
            self.l2tp.as_ref().map(|_| "l2tp"),
            self.mpls.as_ref().map(|_| "mpls"),
            self.pppoe.as_ref().map(|_| "pppoe"),
            self.ah.as_ref().map(|_| "ah"),
            self.esp.as_ref().map(|_| "esp"),
            self.wireguard.as_ref().map(|_| "wireguard"),
            self.openvpn.as_ref().map(|_| "openvpn"),
        ]
        .into_iter()
        .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OpenVpnOpcode, ParseMode, ParseWarningProtocol, ParseWarningSubcode, UdpAppHint,
        WireGuardMessageType,
    };

    #[test]
    fn stable_name_helpers_are_exposed() {
        assert_eq!(ParseMode::Permissive.as_str(), "permissive");
        assert_eq!(ParseWarningProtocol::Tunnel.as_str(), "tunnel");
        assert_eq!(ParseWarningSubcode::VxlanInner.as_str(), "vxlan-inner");
        assert_eq!(UdpAppHint::L2tp.as_str(), "l2tp");
        assert_eq!(UdpAppHint::Dhcpv6.as_str(), "dhcpv6");
        assert_eq!(UdpAppHint::WireGuard.as_str(), "wireguard");
        assert_eq!(UdpAppHint::OpenVpn.as_str(), "openvpn");
        assert_eq!(
            WireGuardMessageType::HandshakeInitiation.as_str(),
            "handshake-initiation"
        );
        assert_eq!(OpenVpnOpcode::DataV2.as_str(), "data-v2");
    }

    #[test]
    fn tftp_hint_has_stable_name() {
        assert_eq!(UdpAppHint::Tftp.as_str(), "tftp");
    }

    #[test]
    fn discovery_hints_have_stable_names() {
        assert_eq!(UdpAppHint::Ssdp.as_str(), "ssdp");
        assert_eq!(UdpAppHint::NatPmp.as_str(), "nat-pmp");
        assert_eq!(UdpAppHint::Pcp.as_str(), "pcp");
    }
}
