use std::iter::from_fn;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};

use crate::engine::constants::ethertype_name;
use crate::layer::application::bgp::BgpMessage;
use crate::layer::application::cdp::CdpHeader;
use crate::layer::application::coap::CoapMessage;
use crate::layer::application::dhcp::DhcpMessage;
use crate::layer::application::dhcp6::Dhcp6Message;
use crate::layer::application::dnp3::Dnp3Message;
use crate::layer::application::dns::DnsMessage;
use crate::layer::application::eigrp::EigrpHeader;
use crate::layer::application::ftp::FtpMessage;
use crate::layer::application::hsrp::HsrpHeader;
use crate::layer::application::http::HttpMessage;
use crate::layer::application::imap::ImapMessage;
use crate::layer::application::isakmp::IsakmpHeader;
use crate::layer::application::kerberos::KerberosMessage;
use crate::layer::application::lacp::LacpHeader;
use crate::layer::application::ldap::LdapMessage;
use crate::layer::application::modbus::ModbusMessage;
use crate::layer::application::mqtt::MqttMessage;
use crate::layer::application::nat_pmp::NatPmpMessage;
use crate::layer::application::nntp::NntpMessage;
use crate::layer::application::ntp::NtpMessage;
use crate::layer::application::ospf::OspfHeader;
use crate::layer::application::pcp::PcpHeader;
use crate::layer::application::pim::PimHeader;
use crate::layer::application::quic::QuicLongHeader;
use crate::layer::application::radius::RadiusMessage;
use crate::layer::application::rip::RipHeader;
use crate::layer::application::rpc::RpcMessage;
use crate::layer::application::rtcp::RtcpHeader;
use crate::layer::application::rtp::RtpHeader;
use crate::layer::application::sip::SipMessage;
use crate::layer::application::smb1::Smb1Header;
use crate::layer::application::smb2::Smb2Header;
use crate::layer::application::smtp::SmtpMessage;
use crate::layer::application::snmp::SnmpMessage;
use crate::layer::application::ssdp::SsdpMessage;
use crate::layer::application::ssh::{SshBanner, SshKexInit};
use crate::layer::application::stun::StunMessage;
use crate::layer::application::syslog::SyslogMessage;
use crate::layer::application::telnet::TelnetCommand;
use crate::layer::application::tftp::TftpMessage;
use crate::layer::application::tls::{TlsClientHello, TlsServerHello};
use crate::layer::application::vrrp::VrrpHeader;
use crate::layer::datalink::arp::ArpPacket;
use crate::layer::datalink::dot11::{Dot11Frame, RadiotapHeader};
use crate::layer::network::icmp::IcmpHeader;
use crate::layer::network::icmpv6::{Icmpv6Header, NdpMessage};
use crate::layer::network::ipv4::Ipv4Header;
use crate::layer::network::ipv6::Ipv6Header;
use crate::layer::transport::tcp::TcpHeader;
use crate::layer::transport::udp::UdpHeader;

use super::network::Ipv6FragmentHeader;

/// Why a parse could not go further, or went further with a caveat.
///
/// Marked non-exhaustive: this enumerates diagnostics, and new ones will be
/// added as more can go wrong. Match with a wildcard arm so that adding one is
/// not a breaking change for you.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    TransportTruncated,
}

impl ParseWarningCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransportTruncated => "transport-truncated",
            Self::Ipv6NonInitialFragment => "ipv6-non-initial-fragment",
            Self::Ipv6ExtensionDepthLimit => "ipv6-ext-depth-limit",
            Self::Ipv6Truncated => "ipv6-truncated",
            Self::UnsupportedEthertype(_) => "unsupported-ethertype",
            Self::Ipv4Truncated => "ipv4-truncated",
            Self::Ipv4Fragmented => "ipv4-fragmented",
            Self::IpipInner => "ipip-inner",
            Self::GreInner => "gre-inner",
            Self::PppoeNoPayload => "pppoe-no-payload",
            Self::VxlanInner => "vxlan-inner",
            Self::GeneveInner => "geneve-inner",
            Self::AhInner => "ah-inner",
            Self::EspInner => "esp-inner",
            Self::MplsInner => "mpls-inner",
            Self::MplsLabelDepthLimit => "mpls-label-depth-limit",
            Self::TunnelDepthLimit => "tunnel-depth-limit",
        }
    }
}

/// Which layer a warning came from. Non-exhaustive on the same reasoning as
/// [`ParseWarningCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    pub offset: usize,
    pub message: &'static str,
}

impl ParseWarning {
    pub fn new(
        code: ParseWarningCode,
        protocol: ParseWarningProtocol,
        offset: usize,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            protocol,
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
    Rpc,
    Syslog,
    Hsrp,
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
            Self::Rpc => "rpc",
            Self::Syslog => "syslog",
            Self::Hsrp => "hsrp",
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
    Sctp(SctpInfo),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

/// The application-layer results of a parse.
///
/// Held behind a pointer on [`ParsedPacket`] rather than inline. These are 39
/// of the packet's 75 fields and two thirds of its bytes, and they are only
/// ever filled when the caller asks for [`StopLayer::Application`]. Inline,
/// every caller paid to clear and move them: a parse that stops at the
/// transport layer spent a third of its time on fields it never touched.
#[derive(Debug, Default)]
pub struct ApplicationLayers {
    pub dnp3: Option<Dnp3Message>,
    pub dns: Option<DnsMessage>,
    pub dhcp: Option<DhcpMessage>,
    pub dhcp6: Option<Dhcp6Message>,
    pub tftp: Option<TftpMessage>,
    pub radius: Option<RadiusMessage>,
    pub snmp: Option<SnmpMessage>,
    pub ntp: Option<NtpMessage>,
    pub tls: Option<TlsClientHello>,
    pub tls_server_hello: Option<TlsServerHello>,
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
    pub imap: Option<ImapMessage>,
    pub ftp: Option<FtpMessage>,
    pub smb1: Option<Smb1Header>,
    pub smb2: Option<Smb2Header>,
    pub smtp: Option<SmtpMessage>,
    pub telnet: Option<TelnetCommand>,
    pub mqtt: Option<MqttMessage>,
    pub modbus: Option<ModbusMessage>,
    pub ssh: Option<SshBanner>,
    pub ssh_kex_init: Option<SshKexInit>,
    pub coap: Option<CoapMessage>,
    pub kerberos: Option<KerberosMessage>,
    pub stun: Option<StunMessage>,
    pub rip: Option<RipHeader>,
    pub isakmp: Option<IsakmpHeader>,
    pub rpc: Option<RpcMessage>,
    pub syslog: Option<SyslogMessage>,
    pub hsrp: Option<HsrpHeader>,
}

#[derive(Debug, Default)]
pub struct ParsedPacket {
    pub ethernet: Option<EthernetFrame>,
    pub radiotap: Option<RadiotapHeader>,
    pub dot11: Option<Dot11Frame>,
    pub arp: Option<ArpPacket>,
    pub ipv4: Option<Ipv4Header>,
    pub ipv6: Option<Ipv6Header>,
    pub ipv6_fragment: Option<Ipv6FragmentHeader>,
    pub transport: Option<TransportSegment>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
    pub ndp: Option<NdpMessage>,
    pub igmp: Option<IgmpInfo>,
    pub ospf: Option<OspfHeader>,
    pub eigrp: Option<EigrpHeader>,
    pub pim: Option<PimHeader>,
    pub vrrp: Option<VrrpHeader>,
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
    pub mpls: Option<MplsInfo>,
    pub lldp: Option<LldpInfo>,
    pub lacp: Option<LacpHeader>,
    pub stp: Option<StpBpdu>,
    pub cdp: Option<CdpHeader>,
    pub udp_hints: Vec<UdpAppHint>,
    pub warnings: Vec<ParseWarning>,
    pub inner: Option<Box<ParsedPacket>>,
    /// Byte offset of `transport` in the parsed buffer. UDP payload starts at
    /// `transport_segment_offset + 8`. Nested offsets are relative to the inner
    /// packet's buffer.
    pub transport_segment_offset: Option<usize>,
    /// What the parse found above the transport layer, if it looked and found
    /// anything. Allocated on first use, so a parse that stops below the
    /// application layer never allocates at all.
    ///
    /// The per-protocol accessors, such as [`Self::dns`], read through this.
    pub application: Option<Box<ApplicationLayers>>,
}

/// Application protocol returned by [`ParsedPacket::application`]. Protocols
/// also remain available through their named `Option<T>` fields.
#[derive(Debug, Clone, Copy)]
pub enum ApplicationLayer<'a> {
    Dnp3(&'a Dnp3Message),
    Dns(&'a DnsMessage),
    Dhcp(&'a DhcpMessage),
    Dhcp6(&'a Dhcp6Message),
    Tftp(&'a TftpMessage),
    Radius(&'a RadiusMessage),
    Snmp(&'a SnmpMessage),
    Ntp(&'a NtpMessage),
    TlsClientHello(&'a TlsClientHello),
    TlsServerHello(&'a TlsServerHello),
    Http(&'a HttpMessage),
    Ssdp(&'a SsdpMessage),
    NatPmp(&'a NatPmpMessage),
    Pcp(&'a PcpHeader),
    Sip(&'a SipMessage),
    Rtcp(&'a RtcpHeader),
    Rtp(&'a RtpHeader),
    Quic(&'a QuicLongHeader),
    Bgp(&'a BgpMessage),
    Ldap(&'a LdapMessage),
    Nntp(&'a NntpMessage),
    Imap(&'a ImapMessage),
    Ftp(&'a FtpMessage),
    Smb1(&'a Smb1Header),
    Smb2(&'a Smb2Header),
    Smtp(&'a SmtpMessage),
    Telnet(&'a TelnetCommand),
    Mqtt(&'a MqttMessage),
    Modbus(&'a ModbusMessage),
    Ssh(&'a SshBanner),
    SshKexInit(&'a SshKexInit),
    Coap(&'a CoapMessage),
    Kerberos(&'a KerberosMessage),
    Stun(&'a StunMessage),
    Rip(&'a RipHeader),
    Isakmp(&'a IsakmpHeader),
    Rpc(&'a RpcMessage),
    Syslog(&'a SyslogMessage),
    Hsrp(&'a HsrpHeader),
}

impl ParsedPacket {
    /// Clear every field, ready for the next packet.
    ///
    /// Written as a whole-struct assignment rather than field by field so that
    /// adding a protocol cannot leave a stale value behind from the packet
    /// before. The two vectors keep the capacity they have already grown to,
    /// which is the point of reusing the buffer at all.
    ///
    /// `inner` is not kept. A reused buffer therefore still allocates one box
    /// per tunnel level on every tunnelled packet, the same as parsing by
    /// value does; keeping it would need somewhere to park the allocation that
    /// `inner.is_some()` does not read as "this packet was tunnelled".
    pub fn reset(&mut self) {
        let udp_hints = mem::take(&mut self.udp_hints);
        let warnings = mem::take(&mut self.warnings);
        *self = ParsedPacket::default();
        self.udp_hints = udp_hints;
        self.warnings = warnings;
        self.udp_hints.clear();
        self.warnings.clear();
    }

    /// The application layer, creating it if this is the first field to be
    /// filled. Only the parser needs this; readers use the per-protocol
    /// accessors.
    pub fn application_mut(&mut self) -> &mut ApplicationLayers {
        self.application.get_or_insert_with(Box::default)
    }

    /// The parsed `dnp3` layer, if the packet carried one.
    #[must_use]
    pub fn dnp3(&self) -> Option<&Dnp3Message> {
        self.application.as_ref()?.dnp3.as_ref()
    }

    /// The parsed `dns` layer, if the packet carried one.
    #[must_use]
    pub fn dns(&self) -> Option<&DnsMessage> {
        self.application.as_ref()?.dns.as_ref()
    }

    /// The parsed `dhcp` layer, if the packet carried one.
    #[must_use]
    pub fn dhcp(&self) -> Option<&DhcpMessage> {
        self.application.as_ref()?.dhcp.as_ref()
    }

    /// The parsed `dhcp6` layer, if the packet carried one.
    #[must_use]
    pub fn dhcp6(&self) -> Option<&Dhcp6Message> {
        self.application.as_ref()?.dhcp6.as_ref()
    }

    /// The parsed `tftp` layer, if the packet carried one.
    #[must_use]
    pub fn tftp(&self) -> Option<&TftpMessage> {
        self.application.as_ref()?.tftp.as_ref()
    }

    /// The parsed `radius` layer, if the packet carried one.
    #[must_use]
    pub fn radius(&self) -> Option<&RadiusMessage> {
        self.application.as_ref()?.radius.as_ref()
    }

    /// The parsed `snmp` layer, if the packet carried one.
    #[must_use]
    pub fn snmp(&self) -> Option<&SnmpMessage> {
        self.application.as_ref()?.snmp.as_ref()
    }

    /// The parsed `ntp` layer, if the packet carried one.
    #[must_use]
    pub fn ntp(&self) -> Option<&NtpMessage> {
        self.application.as_ref()?.ntp.as_ref()
    }

    /// The parsed `tls` layer, if the packet carried one.
    #[must_use]
    pub fn tls(&self) -> Option<&TlsClientHello> {
        self.application.as_ref()?.tls.as_ref()
    }

    /// The parsed `tls_server_hello` layer, if the packet carried one.
    #[must_use]
    pub fn tls_server_hello(&self) -> Option<&TlsServerHello> {
        self.application.as_ref()?.tls_server_hello.as_ref()
    }

    /// The parsed `http` layer, if the packet carried one.
    #[must_use]
    pub fn http(&self) -> Option<&HttpMessage> {
        self.application.as_ref()?.http.as_ref()
    }

    /// The parsed `ssdp` layer, if the packet carried one.
    #[must_use]
    pub fn ssdp(&self) -> Option<&SsdpMessage> {
        self.application.as_ref()?.ssdp.as_ref()
    }

    /// The parsed `nat_pmp` layer, if the packet carried one.
    #[must_use]
    pub fn nat_pmp(&self) -> Option<&NatPmpMessage> {
        self.application.as_ref()?.nat_pmp.as_ref()
    }

    /// The parsed `pcp` layer, if the packet carried one.
    #[must_use]
    pub fn pcp(&self) -> Option<&PcpHeader> {
        self.application.as_ref()?.pcp.as_ref()
    }

    /// The parsed `sip` layer, if the packet carried one.
    #[must_use]
    pub fn sip(&self) -> Option<&SipMessage> {
        self.application.as_ref()?.sip.as_ref()
    }

    /// The parsed `rtcp` layer, if the packet carried one.
    #[must_use]
    pub fn rtcp(&self) -> Option<&RtcpHeader> {
        self.application.as_ref()?.rtcp.as_ref()
    }

    /// The parsed `rtp` layer, if the packet carried one.
    #[must_use]
    pub fn rtp(&self) -> Option<&RtpHeader> {
        self.application.as_ref()?.rtp.as_ref()
    }

    /// The parsed `quic` layer, if the packet carried one.
    #[must_use]
    pub fn quic(&self) -> Option<&QuicLongHeader> {
        self.application.as_ref()?.quic.as_ref()
    }

    /// The parsed `bgp` layer, if the packet carried one.
    #[must_use]
    pub fn bgp(&self) -> Option<&BgpMessage> {
        self.application.as_ref()?.bgp.as_ref()
    }

    /// The parsed `ldap` layer, if the packet carried one.
    #[must_use]
    pub fn ldap(&self) -> Option<&LdapMessage> {
        self.application.as_ref()?.ldap.as_ref()
    }

    /// The parsed `nntp` layer, if the packet carried one.
    #[must_use]
    pub fn nntp(&self) -> Option<&NntpMessage> {
        self.application.as_ref()?.nntp.as_ref()
    }

    /// The parsed `imap` layer, if the packet carried one.
    #[must_use]
    pub fn imap(&self) -> Option<&ImapMessage> {
        self.application.as_ref()?.imap.as_ref()
    }

    /// The parsed `ftp` layer, if the packet carried one.
    #[must_use]
    pub fn ftp(&self) -> Option<&FtpMessage> {
        self.application.as_ref()?.ftp.as_ref()
    }

    /// The parsed `smb1` layer, if the packet carried one.
    #[must_use]
    pub fn smb1(&self) -> Option<&Smb1Header> {
        self.application.as_ref()?.smb1.as_ref()
    }

    /// The parsed `smb2` layer, if the packet carried one.
    #[must_use]
    pub fn smb2(&self) -> Option<&Smb2Header> {
        self.application.as_ref()?.smb2.as_ref()
    }

    /// The parsed `smtp` layer, if the packet carried one.
    #[must_use]
    pub fn smtp(&self) -> Option<&SmtpMessage> {
        self.application.as_ref()?.smtp.as_ref()
    }

    /// The parsed `telnet` layer, if the packet carried one.
    #[must_use]
    pub fn telnet(&self) -> Option<&TelnetCommand> {
        self.application.as_ref()?.telnet.as_ref()
    }

    /// The parsed `mqtt` layer, if the packet carried one.
    #[must_use]
    pub fn mqtt(&self) -> Option<&MqttMessage> {
        self.application.as_ref()?.mqtt.as_ref()
    }

    /// The parsed `modbus` layer, if the packet carried one.
    #[must_use]
    pub fn modbus(&self) -> Option<&ModbusMessage> {
        self.application.as_ref()?.modbus.as_ref()
    }

    /// The parsed `ssh` layer, if the packet carried one.
    #[must_use]
    pub fn ssh(&self) -> Option<&SshBanner> {
        self.application.as_ref()?.ssh.as_ref()
    }

    /// The parsed `ssh_kex_init` layer, if the packet carried one.
    #[must_use]
    pub fn ssh_kex_init(&self) -> Option<&SshKexInit> {
        self.application.as_ref()?.ssh_kex_init.as_ref()
    }

    /// The parsed `coap` layer, if the packet carried one.
    #[must_use]
    pub fn coap(&self) -> Option<&CoapMessage> {
        self.application.as_ref()?.coap.as_ref()
    }

    /// The parsed `kerberos` layer, if the packet carried one.
    #[must_use]
    pub fn kerberos(&self) -> Option<&KerberosMessage> {
        self.application.as_ref()?.kerberos.as_ref()
    }

    /// The parsed `stun` layer, if the packet carried one.
    #[must_use]
    pub fn stun(&self) -> Option<&StunMessage> {
        self.application.as_ref()?.stun.as_ref()
    }

    /// The parsed `rip` layer, if the packet carried one.
    #[must_use]
    pub fn rip(&self) -> Option<&RipHeader> {
        self.application.as_ref()?.rip.as_ref()
    }

    /// The parsed `isakmp` layer, if the packet carried one.
    #[must_use]
    pub fn isakmp(&self) -> Option<&IsakmpHeader> {
        self.application.as_ref()?.isakmp.as_ref()
    }

    /// The parsed `rpc` layer, if the packet carried one.
    #[must_use]
    pub fn rpc(&self) -> Option<&RpcMessage> {
        self.application.as_ref()?.rpc.as_ref()
    }

    /// The parsed `syslog` layer, if the packet carried one.
    #[must_use]
    pub fn syslog(&self) -> Option<&SyslogMessage> {
        self.application.as_ref()?.syslog.as_ref()
    }

    /// The parsed `hsrp` layer, if the packet carried one.
    #[must_use]
    pub fn hsrp(&self) -> Option<&HsrpHeader> {
        self.application.as_ref()?.hsrp.as_ref()
    }

    /// Returns the first populated application field in declaration order.
    #[must_use]
    pub fn application_layer(&self) -> Option<ApplicationLayer<'_>> {
        let app = self.application.as_ref()?;

        None.or_else(|| app.dnp3.as_ref().map(ApplicationLayer::Dnp3))
            .or_else(|| app.dns.as_ref().map(ApplicationLayer::Dns))
            .or_else(|| app.dhcp.as_ref().map(ApplicationLayer::Dhcp))
            .or_else(|| app.dhcp6.as_ref().map(ApplicationLayer::Dhcp6))
            .or_else(|| app.tftp.as_ref().map(ApplicationLayer::Tftp))
            .or_else(|| app.radius.as_ref().map(ApplicationLayer::Radius))
            .or_else(|| app.snmp.as_ref().map(ApplicationLayer::Snmp))
            .or_else(|| app.ntp.as_ref().map(ApplicationLayer::Ntp))
            .or_else(|| app.tls.as_ref().map(ApplicationLayer::TlsClientHello))
            .or_else(|| {
                app.tls_server_hello
                    .as_ref()
                    .map(ApplicationLayer::TlsServerHello)
            })
            .or_else(|| app.http.as_ref().map(ApplicationLayer::Http))
            .or_else(|| app.ssdp.as_ref().map(ApplicationLayer::Ssdp))
            .or_else(|| app.nat_pmp.as_ref().map(ApplicationLayer::NatPmp))
            .or_else(|| app.pcp.as_ref().map(ApplicationLayer::Pcp))
            .or_else(|| app.sip.as_ref().map(ApplicationLayer::Sip))
            .or_else(|| app.rtcp.as_ref().map(ApplicationLayer::Rtcp))
            .or_else(|| app.rtp.as_ref().map(ApplicationLayer::Rtp))
            .or_else(|| app.quic.as_ref().map(ApplicationLayer::Quic))
            .or_else(|| app.bgp.as_ref().map(ApplicationLayer::Bgp))
            .or_else(|| app.ldap.as_ref().map(ApplicationLayer::Ldap))
            .or_else(|| app.nntp.as_ref().map(ApplicationLayer::Nntp))
            .or_else(|| app.imap.as_ref().map(ApplicationLayer::Imap))
            .or_else(|| app.ftp.as_ref().map(ApplicationLayer::Ftp))
            .or_else(|| app.smb1.as_ref().map(ApplicationLayer::Smb1))
            .or_else(|| app.smb2.as_ref().map(ApplicationLayer::Smb2))
            .or_else(|| app.smtp.as_ref().map(ApplicationLayer::Smtp))
            .or_else(|| app.telnet.as_ref().map(ApplicationLayer::Telnet))
            .or_else(|| app.mqtt.as_ref().map(ApplicationLayer::Mqtt))
            .or_else(|| app.modbus.as_ref().map(ApplicationLayer::Modbus))
            .or_else(|| app.ssh.as_ref().map(ApplicationLayer::Ssh))
            .or_else(|| app.ssh_kex_init.as_ref().map(ApplicationLayer::SshKexInit))
            .or_else(|| app.coap.as_ref().map(ApplicationLayer::Coap))
            .or_else(|| app.kerberos.as_ref().map(ApplicationLayer::Kerberos))
            .or_else(|| app.stun.as_ref().map(ApplicationLayer::Stun))
            .or_else(|| app.rip.as_ref().map(ApplicationLayer::Rip))
            .or_else(|| app.isakmp.as_ref().map(ApplicationLayer::Isakmp))
            .or_else(|| app.rpc.as_ref().map(ApplicationLayer::Rpc))
            .or_else(|| app.syslog.as_ref().map(ApplicationLayer::Syslog))
            .or_else(|| app.hsrp.as_ref().map(ApplicationLayer::Hsrp))
    }

    /// Alias for [`Self::innermost_flow_key`]. For tunneled packets, prefer the
    /// explicit outer or innermost methods.
    pub fn flow_key(&self) -> Option<FlowKey> {
        self.innermost_flow_key()
    }

    /// Returns this packet's flow key without descending into `inner`. For a
    /// tunnel, this identifies the outer endpoints.
    #[must_use]
    pub fn outer_flow_key(&self) -> Option<FlowKey> {
        let (src_ip, dst_ip, protocol) = if let Some(ipv4) = self.ipv4.as_ref() {
            (
                IpAddr::V4(ipv4.source),
                IpAddr::V4(ipv4.destination),
                ipv4.protocol,
            )
        } else {
            let ipv6 = self.ipv6.as_ref()?;
            (
                IpAddr::V6(ipv6.source),
                IpAddr::V6(ipv6.destination),
                ipv6.resolved_next_header,
            )
        };

        let (src_port, dst_port) = match self.transport.as_ref() {
            Some(TransportSegment::Tcp(tcp)) => (tcp.source_port, tcp.destination_port),
            Some(TransportSegment::Udp(udp)) => (udp.source_port, udp.destination_port),
            Some(TransportSegment::Sctp(sctp)) => (sctp.source_port, sctp.destination_port),
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

    /// Returns the deepest decoded packet's flow key, or the packet's own key
    /// when no tunnel is present.
    #[must_use]
    pub fn innermost_flow_key(&self) -> Option<FlowKey> {
        if let Some(inner) = self.inner.as_deref() {
            return inner.innermost_flow_key();
        }
        self.outer_flow_key()
    }

    /// Iterates flow keys outermost first, skipping layers without network or
    /// transport headers. Non-tunneled packets yield at most one key.
    pub fn flow_path(&self) -> impl Iterator<Item = FlowKey> + '_ {
        let mut current = Some(self);
        from_fn(move || {
            while let Some(packet) = current {
                current = packet.inner.as_deref();
                if let Some(key) = packet.outer_flow_key() {
                    return Some(key);
                }
            }
            None
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
            Some(TransportSegment::Sctp(_)) => Some("sctp"),
            None if self.sctp.is_some() => Some("sctp"),
            None => None,
        }
    }

    pub fn warning_code_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.warnings.iter().map(|w| w.code.as_str())
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
        OpenVpnOpcode, ParseMode, ParseWarningCode, ParseWarningProtocol, UdpAppHint,
        WireGuardMessageType,
    };

    #[test]
    fn stable_name_helpers_are_exposed() {
        assert_eq!(ParseMode::Permissive.as_str(), "permissive");
        assert_eq!(ParseWarningProtocol::Tunnel.as_str(), "tunnel");
        assert_eq!(ParseWarningCode::VxlanInner.as_str(), "vxlan-inner");
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
