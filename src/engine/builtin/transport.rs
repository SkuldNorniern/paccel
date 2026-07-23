use std::net::Ipv4Addr;

use crate::engine::constants::ip_proto;
use crate::layer::LayerError;
use crate::layer::application::bgp::{BgpMessage, parse_bgp_message};
use crate::layer::application::coap::{CoapMessage, parse_coap_message};
use crate::layer::application::dhcp::{DhcpMessage, parse_dhcp_message};
use crate::layer::application::dhcp6::{Dhcp6Message, parse_dhcp6_message};
use crate::layer::application::dnp3::{Dnp3Message, parse_dnp3_message};
use crate::layer::application::dns::{DnsMessage, parse_dns_message};
use crate::layer::application::ftp::{FtpMessage, parse_ftp};
use crate::layer::application::http::{HttpMessage, parse_http};
use crate::layer::application::isakmp::{IsakmpHeader, parse_isakmp_header};
use crate::layer::application::kerberos::{
    KerberosMessage, parse_kerberos_tcp, parse_kerberos_udp,
};
use crate::layer::application::ldap::{LdapMessage, parse_ldap_message};
use crate::layer::application::modbus::{ModbusMessage, parse_modbus_message};
use crate::layer::application::mqtt::{MqttMessage, parse_mqtt_message};
use crate::layer::application::nntp::{NntpMessage, parse_nntp};
use crate::layer::application::ntp::{NtpMessage, parse_ntp_message};
use crate::layer::application::ospf::{OspfHeader, parse_ospf_header};
use crate::layer::application::quic::{QuicLongHeader, parse_quic_long_header};
use crate::layer::application::radius::{RadiusMessage, parse_radius_message};
use crate::layer::application::rip::{RipHeader, parse_rip_header};
use crate::layer::application::rtcp::{RtcpHeader, parse_rtcp};
use crate::layer::application::rtp::{RtpHeader, parse_rtp};
use crate::layer::application::sip::{SipMessage, parse_sip};
use crate::layer::application::smtp::{SmtpMessage, parse_smtp};
use crate::layer::application::snmp::{SnmpMessage, parse_snmp_message};
use crate::layer::application::ssh::{SshBanner, parse_ssh_banner};
use crate::layer::application::stun::{StunMessage, parse_stun_message};
use crate::layer::application::telnet::{TelnetCommand, parse_telnet_command};
use crate::layer::application::tftp::{TftpMessage, parse_tftp_message};
use crate::layer::application::tls::{TlsClientHello, parse_tls_client_hello};
use crate::layer::network::icmp::IcmpHeader;
use crate::layer::network::icmpv6::{Icmpv6Header, NdpMessage, parse_ndp};
use crate::layer::transport::tcp::{TcpFlags, TcpHeader};
use crate::layer::transport::udp::UdpHeader;

use super::types::{
    AhInfo, EspInfo, GeneveInfo, GreInfo, IgmpInfo, L2tpInfo, OpenVpnInfo, OpenVpnOpcode,
    ParseConfig, SctpChunk, SctpInfo, StopLayer, TcpOptionsParsed, TransportSegment, UdpAppHint,
    VxlanInfo, WireGuardInfo, WireGuardMessageType,
};

const UDP_HEADER_LEN: usize = 8;
const UDP_PORT_DNS: u16 = 53;
const UDP_PORT_MDNS: u16 = 5353;
const UDP_PORT_DHCP_SERVER: u16 = 67;
const UDP_PORT_DHCP_CLIENT: u16 = 68;
const UDP_PORT_DHCPV6_CLIENT: u16 = 546;
const UDP_PORT_DHCPV6_SERVER: u16 = 547;
const UDP_PORT_TFTP: u16 = 69;
const UDP_PORT_SNMP: u16 = 161;
const UDP_PORT_SNMP_TRAP: u16 = 162;
const UDP_PORT_RADIUS_AUTH: u16 = 1812;
const UDP_PORT_RADIUS_AUTH_LEGACY: u16 = 1645;
const UDP_PORT_RADIUS_ACCT: u16 = 1813;
const UDP_PORT_RADIUS_ACCT_LEGACY: u16 = 1646;
const UDP_PORT_NTP: u16 = 123;
const UDP_PORT_L2TP: u16 = 1701;
const UDP_PORT_VXLAN: u16 = 4789;
const UDP_PORT_GENEVE: u16 = 6081;
const UDP_PORT_OPENVPN: u16 = 1194;
const UDP_PORT_SIP: u16 = 5060;
const UDP_PORT_WIREGUARD: u16 = 51820;
const UDP_PORT_WIREGUARD_ALT: u16 = 51821;
const UDP_PORT_COAP: u16 = 5683;
const UDP_PORT_ISAKMP: u16 = 500;
const UDP_PORT_RIP: u16 = 520;
const STUN_PORT: u16 = 3478;
const UDP_PORT_LLMNR: u16 = 5355;
const UDP_PORT_NBNS: u16 = 137;
const DNP3_PORT: u16 = 20_000;
const TCP_PORT_FTP: u16 = 21;
const TCP_PORT_SMTP: u16 = 25;
const TCP_PORT_TELNET: u16 = 23;
const TCP_PORT_BGP: u16 = 179;
const TCP_PORT_LDAP: u16 = 389;
const TCP_PORT_LDAPS: u16 = 636;
const TCP_PORT_NNTP: u16 = 119;
const TCP_PORT_NNTPS: u16 = 563;
const TCP_PORT_MQTT: u16 = 1883;
const TCP_PORT_MODBUS: u16 = 502;
const TCP_PORT_SUBMISSION: u16 = 587;
const PORT_KERBEROS: u16 = 88;

#[derive(Debug, Default)]
pub(super) struct TransportParse {
    pub transport: Option<TransportSegment>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
    pub ndp: Option<NdpMessage>,
    pub igmp: Option<IgmpInfo>,
    pub ospf: Option<OspfHeader>,
    pub sctp: Option<SctpInfo>,
    pub tcp_options: Option<TcpOptionsParsed>,
    pub gre: Option<GreInfo>,
    pub vxlan: Option<VxlanInfo>,
    pub geneve: Option<GeneveInfo>,
    pub l2tp: Option<L2tpInfo>,
    pub ah: Option<AhInfo>,
    pub esp: Option<EspInfo>,
    pub wireguard: Option<WireGuardInfo>,
    pub openvpn: Option<OpenVpnInfo>,
    pub dnp3: Option<Dnp3Message>,
    pub dns: Option<DnsMessage>,
    pub dhcp: Option<DhcpMessage>,
    pub dhcp6: Option<Dhcp6Message>,
    pub tftp: Option<TftpMessage>,
    pub radius: Option<RadiusMessage>,
    pub snmp: Option<SnmpMessage>,
    pub ntp: Option<NtpMessage>,
    pub tls: Option<TlsClientHello>,
    pub http: Option<HttpMessage>,
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
    pub hints: Vec<UdpAppHint>,
}

impl TransportParse {
    fn with_tcp(tcp: TcpHeader, tcp_options: Option<TcpOptionsParsed>) -> Self {
        Self {
            transport: Some(TransportSegment::Tcp(tcp)),
            tcp_options,
            ..Self::default()
        }
    }

    fn with_icmp(icmp: IcmpHeader) -> Self {
        Self {
            icmp: Some(icmp),
            ..Self::default()
        }
    }

    fn with_icmpv6(icmpv6: Icmpv6Header, ndp: Option<NdpMessage>) -> Self {
        Self {
            icmpv6: Some(icmpv6),
            ndp,
            ..Self::default()
        }
    }

    fn with_igmp(igmp: IgmpInfo) -> Self {
        Self {
            igmp: Some(igmp),
            ..Self::default()
        }
    }

    fn with_ospf(ospf: OspfHeader) -> Self {
        Self {
            ospf: Some(ospf),
            ..Self::default()
        }
    }

    fn with_sctp(sctp: SctpInfo) -> Self {
        Self {
            sctp: Some(sctp),
            ..Self::default()
        }
    }

    fn with_gre(gre: GreInfo) -> Self {
        Self {
            gre: Some(gre),
            ..Self::default()
        }
    }

    fn with_ah(ah: AhInfo) -> Self {
        Self {
            ah: Some(ah),
            ..Self::default()
        }
    }

    fn with_esp(esp: EspInfo) -> Self {
        Self {
            esp: Some(esp),
            ..Self::default()
        }
    }
}

pub(super) fn parse_transport(
    protocol: u8,
    l4_bytes: &[u8],
    config: ParseConfig,
) -> Result<TransportParse, LayerError> {
    match protocol {
        ip_proto::TCP => {
            let parse_application = config.stop_after == StopLayer::Application;
            let tcp = parse_tcp_header(l4_bytes, parse_application)?;
            let header_len = usize::from(tcp.data_offset) * 4;
            let tcp_options = parse_application.then(|| {
                tcp.options
                    .as_deref()
                    .map(parse_tcp_options)
                    .unwrap_or_default()
            });
            let source_port = tcp.source_port;
            let destination_port = tcp.destination_port;
            let mut parsed = TransportParse::with_tcp(tcp, tcp_options);
            if parse_application {
                let payload = &l4_bytes[header_len..];
                parsed.dnp3 = ((source_port == DNP3_PORT || destination_port == DNP3_PORT)
                    && payload.starts_with(&[0x05, 0x64]))
                .then(|| parse_dnp3_message(payload).ok())
                .flatten();
                if parsed.dnp3.is_none() {
                    parsed.openvpn =
                        maybe_classify_openvpn_tcp(source_port, destination_port, payload);
                    if parsed.openvpn.is_none() {
                        parsed.tls = (payload.len() >= 5 && payload[0] == 22)
                            .then(|| parse_tls_client_hello(payload).ok())
                            .flatten();
                        if parsed.tls.is_none() {
                            parsed.http = parse_http(payload).ok();
                            if parsed.http.is_none()
                                && (source_port == UDP_PORT_SIP || destination_port == UDP_PORT_SIP)
                            {
                                parsed.sip = parse_sip(payload).ok();
                            }
                            if parsed.http.is_none() && parsed.sip.is_none() {
                                if !payload.is_empty() {
                                    parsed.ssh = parse_ssh_banner(payload).ok();
                                }
                                if parsed.ssh.is_none() {
                                    classify_tcp_app_by_port(
                                        source_port,
                                        destination_port,
                                        payload,
                                        &mut parsed,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Ok(parsed)
        }
        ip_proto::UDP => parse_udp_transport(l4_bytes, config),
        ip_proto::ICMP => {
            let icmp = parse_icmp_minimal(l4_bytes)?;
            Ok(TransportParse::with_icmp(icmp))
        }
        ip_proto::ICMPV6 => {
            let (icmpv6, ndp) =
                parse_icmpv6_minimal(l4_bytes, config.stop_after == StopLayer::Application)?;
            Ok(TransportParse::with_icmpv6(icmpv6, ndp))
        }
        ip_proto::IGMP => {
            let igmp = parse_igmp_minimal(l4_bytes)?;
            Ok(TransportParse::with_igmp(igmp))
        }
        ip_proto::OSPF => {
            let ospf = parse_ospf_header(l4_bytes)?;
            Ok(TransportParse::with_ospf(ospf))
        }
        ip_proto::SCTP => {
            let sctp = parse_sctp_minimal(l4_bytes)?;
            Ok(TransportParse::with_sctp(sctp))
        }
        ip_proto::GRE => {
            let gre = parse_gre_minimal(l4_bytes)?;
            Ok(TransportParse::with_gre(gre))
        }
        ip_proto::AH => {
            let ah = parse_ah_minimal(l4_bytes)?;
            Ok(TransportParse::with_ah(ah))
        }
        ip_proto::ESP => {
            let esp = parse_esp_minimal(l4_bytes)?;
            Ok(TransportParse::with_esp(esp))
        }
        _ => Ok(TransportParse::default()),
    }
}

fn classify_tcp_app_by_port(
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    parsed: &mut TransportParse,
) {
    if source_port == TCP_PORT_FTP || destination_port == TCP_PORT_FTP {
        parsed.ftp = parse_ftp(payload).ok();
        return;
    }
    if source_port == TCP_PORT_SMTP
        || destination_port == TCP_PORT_SMTP
        || source_port == TCP_PORT_SUBMISSION
        || destination_port == TCP_PORT_SUBMISSION
    {
        parsed.smtp = parse_smtp(payload).ok();
        return;
    }
    if source_port == TCP_PORT_TELNET || destination_port == TCP_PORT_TELNET {
        parsed.telnet = parse_telnet_command(payload).ok();
        return;
    }
    if source_port == TCP_PORT_BGP || destination_port == TCP_PORT_BGP {
        parsed.bgp = parse_bgp_message(payload).ok();
    }
    if parsed.bgp.is_none()
        && (source_port == TCP_PORT_LDAP
            || destination_port == TCP_PORT_LDAP
            || source_port == TCP_PORT_LDAPS
            || destination_port == TCP_PORT_LDAPS)
    {
        parsed.ldap = parse_ldap_message(payload).ok();
    }
    if parsed.bgp.is_none()
        && parsed.ldap.is_none()
        && (source_port == TCP_PORT_NNTP
            || destination_port == TCP_PORT_NNTP
            || source_port == TCP_PORT_NNTPS
            || destination_port == TCP_PORT_NNTPS)
    {
        parsed.nntp = parse_nntp(payload).ok();
    }
    if parsed.bgp.is_none()
        && parsed.ldap.is_none()
        && parsed.nntp.is_none()
        && (source_port == TCP_PORT_MQTT || destination_port == TCP_PORT_MQTT)
    {
        parsed.mqtt = parse_mqtt_message(payload).ok();
    }
    if parsed.bgp.is_none()
        && parsed.ldap.is_none()
        && parsed.nntp.is_none()
        && parsed.mqtt.is_none()
        && (source_port == TCP_PORT_MODBUS || destination_port == TCP_PORT_MODBUS)
    {
        parsed.modbus = parse_modbus_message(payload).ok();
    }
    if parsed.bgp.is_none()
        && parsed.ldap.is_none()
        && parsed.nntp.is_none()
        && parsed.mqtt.is_none()
        && parsed.modbus.is_none()
        && (source_port == PORT_KERBEROS || destination_port == PORT_KERBEROS)
    {
        parsed.kerberos = parse_kerberos_tcp(payload).ok();
    }
}

fn parse_udp_transport(l4_bytes: &[u8], config: ParseConfig) -> Result<TransportParse, LayerError> {
    let udp = parse_udp_header(l4_bytes)?;
    let udp_end = (udp.length as usize).min(l4_bytes.len());
    let app = &l4_bytes[UDP_HEADER_LEN..udp_end];
    let mut hints = Vec::new();
    let mut dns = None;
    let mut dhcp = None;
    let mut dhcp6 = None;
    let mut tftp = None;
    let mut radius = None;
    let mut snmp = None;
    let mut ntp = None;
    let mut sip = None;
    let mut coap = None;
    let mut kerberos = None;
    let mut stun = None;
    let mut rip = None;
    let mut isakmp = None;

    let parse_application = config.stop_after == StopLayer::Application;
    let (wireguard, openvpn) = if parse_application {
        maybe_probe_dns_udp(&udp, app, &mut hints, &mut dns);
        maybe_probe_mdns_udp(&udp, app, &mut hints, &mut dns);
        maybe_probe_dhcp_udp(&udp, app, &mut hints, &mut dhcp);
        maybe_probe_dhcp6_udp(&udp, app, &mut hints, &mut dhcp6);
        maybe_probe_tftp_udp(&udp, app, &mut hints, &mut tftp);
        maybe_probe_radius_udp(&udp, app, &mut hints, &mut radius);
        maybe_probe_snmp_udp(&udp, app, &mut hints, &mut snmp);
        maybe_probe_ntp_udp(&udp, app, &mut hints, &mut ntp);
        maybe_probe_sip_udp(&udp, app, &mut hints, &mut sip);
        maybe_probe_coap_udp(&udp, app, &mut hints, &mut coap);
        maybe_probe_kerberos_udp(&udp, app, &mut hints, &mut kerberos);
        maybe_probe_stun_udp(&udp, app, &mut hints, &mut stun);
        maybe_probe_rip_udp(&udp, app, &mut hints, &mut rip);
        maybe_probe_isakmp_udp(&udp, app, &mut hints, &mut isakmp);
        maybe_probe_llmnr_udp(&udp, app, &mut hints);
        maybe_probe_nbns_udp(&udp, app, &mut hints);
        (
            maybe_classify_wireguard_udp(&udp, app, &mut hints),
            maybe_classify_openvpn_udp(&udp, app, &mut hints),
        )
    } else {
        (None, None)
    };

    let vxlan = maybe_parse_vxlan(&udp, app);
    let geneve = maybe_parse_geneve(&udp, app);
    let l2tp = maybe_parse_l2tp(&udp, app, &mut hints);
    let quic = (parse_application
        && wireguard.is_none()
        && openvpn.is_none()
        && vxlan.is_none()
        && geneve.is_none()
        && l2tp.is_none()
        && app.len() >= 7
        && app[0] & 0x80 != 0)
        .then(|| parse_quic_long_header(app).ok())
        .flatten();
    let quic_short = parse_application
        && wireguard.is_none()
        && openvpn.is_none()
        && vxlan.is_none()
        && geneve.is_none()
        && l2tp.is_none()
        && quic.is_none()
        && !app.is_empty()
        && app[0] & 0xc0 == 0x40;
    if quic_short {
        push_hint_unique(&mut hints, UdpAppHint::QuicShort);
    }
    let already_classified = [
        dns.is_some(),
        dhcp.is_some(),
        dhcp6.is_some(),
        tftp.is_some(),
        radius.is_some(),
        snmp.is_some(),
        ntp.is_some(),
        sip.is_some(),
        coap.is_some(),
        kerberos.is_some(),
        stun.is_some(),
        rip.is_some(),
        isakmp.is_some(),
        wireguard.is_some(),
        openvpn.is_some(),
        vxlan.is_some(),
        geneve.is_some(),
        l2tp.is_some(),
        quic.is_some(),
        quic_short,
    ]
    .into_iter()
    .any(|matched| matched);
    let rtcp = maybe_probe_rtcp_udp(parse_application, app, &mut hints, already_classified);
    let rtp = maybe_probe_rtp_udp(
        parse_application,
        app,
        &mut hints,
        already_classified || rtcp.is_some(),
    );

    Ok(TransportParse {
        transport: Some(TransportSegment::Udp(udp)),
        vxlan,
        geneve,
        l2tp,
        wireguard,
        openvpn,
        dns,
        dhcp,
        dhcp6,
        tftp,
        radius,
        snmp,
        ntp,
        sip,
        rtcp,
        rtp,
        quic,
        coap,
        kerberos,
        stun,
        rip,
        isakmp,
        hints,
        ..TransportParse::default()
    })
}

fn maybe_probe_sip_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    sip: &mut Option<SipMessage>,
) {
    if !is_udp_port_match(udp, UDP_PORT_SIP) {
        return;
    }
    if let Ok(message) = parse_sip(payload) {
        push_hint_unique(hints, UdpAppHint::Sip);
        *sip = Some(message);
    }
}

fn maybe_probe_rtp_udp(
    parse_application: bool,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    already_classified: bool,
) -> Option<RtpHeader> {
    if !parse_application || already_classified {
        return None;
    }
    let header = parse_rtp(payload).ok()?;
    push_hint_unique(hints, UdpAppHint::Rtp);
    Some(header)
}

fn maybe_probe_rtcp_udp(
    parse_application: bool,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    already_classified: bool,
) -> Option<RtcpHeader> {
    if !parse_application || already_classified {
        return None;
    }
    let header = parse_rtcp(payload).ok()?;
    push_hint_unique(hints, UdpAppHint::Rtcp);
    Some(header)
}

fn maybe_probe_dns_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    dns: &mut Option<DnsMessage>,
) {
    if !is_udp_port_match(udp, UDP_PORT_DNS) || !likely_dns_message(payload) {
        return;
    }
    push_hint_unique(hints, UdpAppHint::Dns);
    *dns = try_parse_dns_message(payload);
}

fn maybe_probe_mdns_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    dns: &mut Option<DnsMessage>,
) {
    if !is_udp_port_match(udp, UDP_PORT_MDNS) || !likely_dns_message(payload) {
        return;
    }
    push_hint_unique(hints, UdpAppHint::Mdns);
    if dns.is_none() {
        *dns = try_parse_dns_message(payload);
    }
}

fn maybe_probe_dhcp_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    dhcp: &mut Option<DhcpMessage>,
) {
    let is_dhcp_port = is_udp_port_match(udp, UDP_PORT_DHCP_SERVER)
        || is_udp_port_match(udp, UDP_PORT_DHCP_CLIENT);
    if is_dhcp_port && likely_dhcp_message(payload) {
        push_hint_unique(hints, UdpAppHint::Dhcp);
        *dhcp = parse_dhcp_message(payload).ok();
    }
}

fn maybe_probe_dhcp6_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    dhcp6: &mut Option<Dhcp6Message>,
) {
    let is_dhcp6_port = is_udp_port_match(udp, UDP_PORT_DHCPV6_CLIENT)
        || is_udp_port_match(udp, UDP_PORT_DHCPV6_SERVER);
    if is_dhcp6_port && likely_dhcp6_message(payload) {
        push_hint_unique(hints, UdpAppHint::Dhcpv6);
        *dhcp6 = parse_dhcp6_message(payload).ok();
    }
}

/// Probes only traffic whose source or destination is the well-known TFTP port.
///
/// TFTP switches to ephemeral ports after the initial request. This stateless
/// parser deliberately does not classify those later transfer packets because
/// their short opcode-and-counter shapes are too generic to sniff safely.
fn maybe_probe_tftp_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    tftp: &mut Option<TftpMessage>,
) {
    if is_udp_port_match(udp, UDP_PORT_TFTP) && likely_tftp_message(payload) {
        push_hint_unique(hints, UdpAppHint::Tftp);
        *tftp = parse_tftp_message(payload).ok();
    }
}

fn maybe_probe_coap_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    coap: &mut Option<CoapMessage>,
) {
    if is_udp_port_match(udp, UDP_PORT_COAP)
        && let Ok(message) = parse_coap_message(payload)
    {
        push_hint_unique(hints, UdpAppHint::Coap);
        *coap = Some(message);
    }
}

fn maybe_probe_kerberos_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    kerberos: &mut Option<KerberosMessage>,
) {
    if is_udp_port_match(udp, PORT_KERBEROS)
        && let Ok(message) = parse_kerberos_udp(payload)
    {
        push_hint_unique(hints, UdpAppHint::Kerberos);
        *kerberos = Some(message);
    }
}

fn maybe_probe_stun_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    stun: &mut Option<StunMessage>,
) {
    if is_udp_port_match(udp, STUN_PORT) && likely_stun_message(payload) {
        push_hint_unique(hints, UdpAppHint::Stun);
        *stun = parse_stun_message(payload).ok();
    }
}

fn maybe_probe_rip_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    rip: &mut Option<RipHeader>,
) {
    if is_udp_port_match(udp, UDP_PORT_RIP)
        && let Ok(header) = parse_rip_header(payload)
    {
        push_hint_unique(hints, UdpAppHint::Rip);
        *rip = Some(header);
    }
}

fn maybe_probe_isakmp_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    isakmp: &mut Option<IsakmpHeader>,
) {
    if is_udp_port_match(udp, UDP_PORT_ISAKMP)
        && let Ok(header) = parse_isakmp_header(payload)
    {
        push_hint_unique(hints, UdpAppHint::Isakmp);
        *isakmp = Some(header);
    }
}

fn maybe_probe_llmnr_udp(udp: &UdpHeader, payload: &[u8], hints: &mut Vec<UdpAppHint>) {
    if is_udp_port_match(udp, UDP_PORT_LLMNR)
        && payload.len() >= 12
        && parse_dns_message(payload).is_ok()
    {
        push_hint_unique(hints, UdpAppHint::Llmnr);
    }
}

fn maybe_probe_nbns_udp(udp: &UdpHeader, payload: &[u8], hints: &mut Vec<UdpAppHint>) {
    if is_udp_port_match(udp, UDP_PORT_NBNS)
        && payload.len() >= 12
        && parse_dns_message(payload).is_ok()
    {
        push_hint_unique(hints, UdpAppHint::Nbns);
    }
}

fn maybe_probe_radius_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    radius: &mut Option<RadiusMessage>,
) {
    let is_radius_port = is_udp_port_match(udp, UDP_PORT_RADIUS_AUTH)
        || is_udp_port_match(udp, UDP_PORT_RADIUS_AUTH_LEGACY)
        || is_udp_port_match(udp, UDP_PORT_RADIUS_ACCT)
        || is_udp_port_match(udp, UDP_PORT_RADIUS_ACCT_LEGACY);
    if is_radius_port && likely_radius_message(payload) {
        push_hint_unique(hints, UdpAppHint::Radius);
        *radius = parse_radius_message(payload).ok();
    }
}

fn maybe_probe_snmp_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    snmp: &mut Option<SnmpMessage>,
) {
    let is_snmp_port =
        is_udp_port_match(udp, UDP_PORT_SNMP) || is_udp_port_match(udp, UDP_PORT_SNMP_TRAP);
    if is_snmp_port && likely_snmp_message(payload) {
        push_hint_unique(hints, UdpAppHint::Snmp);
        *snmp = parse_snmp_message(payload).ok();
    }
}

fn maybe_probe_ntp_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    ntp: &mut Option<NtpMessage>,
) {
    if is_udp_port_match(udp, UDP_PORT_NTP) && likely_ntp_message(payload) {
        push_hint_unique(hints, UdpAppHint::Ntp);
        *ntp = parse_ntp_message(payload).ok();
    }
}

fn maybe_parse_vxlan(udp: &UdpHeader, payload: &[u8]) -> Option<VxlanInfo> {
    if !is_udp_port_match(udp, UDP_PORT_VXLAN) || payload.len() < 8 {
        return None;
    }
    parse_vxlan_minimal(payload).ok()
}

fn maybe_parse_geneve(udp: &UdpHeader, payload: &[u8]) -> Option<GeneveInfo> {
    if !is_udp_port_match(udp, UDP_PORT_GENEVE) || payload.len() < 8 {
        return None;
    }
    parse_geneve_minimal(payload).ok()
}

fn maybe_parse_l2tp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
) -> Option<L2tpInfo> {
    if !is_udp_port_match(udp, UDP_PORT_L2TP) || payload.len() < 6 {
        return None;
    }
    let info = parse_l2tp_minimal(payload);
    push_hint_unique(hints, UdpAppHint::L2tp);
    Some(info)
}

fn maybe_classify_wireguard_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
) -> Option<WireGuardInfo> {
    let is_wg_port = is_udp_port_match(udp, UDP_PORT_WIREGUARD)
        || is_udp_port_match(udp, UDP_PORT_WIREGUARD_ALT);
    if !is_wg_port {
        return None;
    }

    let info = classify_wireguard_message(payload)?;
    push_hint_unique(hints, UdpAppHint::WireGuard);
    Some(info)
}

fn classify_wireguard_message(payload: &[u8]) -> Option<WireGuardInfo> {
    let message_type = *payload.first()?;
    let message_type = match message_type {
        1 if payload.len() >= 148 => WireGuardMessageType::HandshakeInitiation,
        2 if payload.len() >= 92 => WireGuardMessageType::HandshakeResponse,
        3 if payload.len() >= 64 => WireGuardMessageType::CookieReply,
        4 if payload.len() >= 32 => WireGuardMessageType::TransportData,
        _ => return None,
    };

    Some(WireGuardInfo { message_type })
}

fn maybe_classify_openvpn_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
) -> Option<OpenVpnInfo> {
    if !is_udp_port_match(udp, UDP_PORT_OPENVPN) {
        return None;
    }

    let info = parse_openvpn_header(payload)?;
    push_hint_unique(hints, UdpAppHint::OpenVpn);
    Some(info)
}

fn maybe_classify_openvpn_tcp(
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Option<OpenVpnInfo> {
    let is_openvpn_port = source_port == UDP_PORT_OPENVPN || destination_port == UDP_PORT_OPENVPN;
    if !is_openvpn_port || payload.len() < 3 {
        return None;
    }

    let packet_len = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_len == 0 {
        return None;
    }
    parse_openvpn_header(&payload[2..])
}

/// Parses only the fixed OpenVPN wire header.
///
/// Control-channel bytes after the eight-byte session ID are opaque because
/// fields such as the tls-auth HMAC have deployment-specific lengths that
/// cannot be discovered reliably from packet bytes alone.
fn parse_openvpn_header(payload: &[u8]) -> Option<OpenVpnInfo> {
    let opcode_and_key_id = *payload.first()?;
    let opcode = OpenVpnOpcode::from_u8(opcode_and_key_id >> 3)?;
    let key_id = opcode_and_key_id & 0x07;

    let (session_id, peer_id) = match opcode {
        OpenVpnOpcode::DataV1 => (None, None),
        OpenVpnOpcode::DataV2 => {
            let peer_id_bytes = payload.get(1..4)?;
            let peer_id =
                u32::from_be_bytes([0, peer_id_bytes[0], peer_id_bytes[1], peer_id_bytes[2]]);
            (None, Some(peer_id))
        }
        _ => {
            let session_id_bytes: [u8; 8] = payload.get(1..9)?.try_into().ok()?;
            (Some(u64::from_be_bytes(session_id_bytes)), None)
        }
    };

    Some(OpenVpnInfo {
        opcode,
        key_id,
        session_id,
        peer_id,
    })
}

fn is_udp_port_match(udp: &UdpHeader, port: u16) -> bool {
    udp.source_port == port || udp.destination_port == port
}

fn parse_icmp_minimal(data: &[u8]) -> Result<IcmpHeader, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    Ok(IcmpHeader {
        icmp_type: data[0],
        icmp_code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
        rest_of_header: [data[4], data[5], data[6], data[7]],
    })
}

fn parse_icmpv6_minimal(
    data: &[u8],
    parse_application: bool,
) -> Result<(Icmpv6Header, Option<NdpMessage>), LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    let header = Icmpv6Header {
        icmp_type: data[0],
        icmp_code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
        rest_of_header: [data[4], data[5], data[6], data[7]],
    };
    let ndp = parse_application
        .then(|| parse_ndp(data[0], &data[4..]))
        .flatten();
    Ok((header, ndp))
}

fn parse_igmp_minimal(data: &[u8]) -> Result<IgmpInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    let msg_type = data[0];
    let group_address = Some(Ipv4Addr::new(data[4], data[5], data[6], data[7]));
    Ok(IgmpInfo {
        msg_type,
        group_address,
    })
}

fn parse_sctp_minimal(data: &[u8]) -> Result<SctpInfo, LayerError> {
    if data.len() < 12 {
        return Err(LayerError::InvalidLength);
    }

    let mut chunks = Vec::new();
    let mut offset = 12;
    while offset + 4 <= data.len() {
        let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let chunk_len = usize::from(length);
        if chunk_len < 4 || offset + chunk_len > data.len() {
            break;
        }
        chunks.push(SctpChunk {
            chunk_type: data[offset],
            flags: data[offset + 1],
            length,
        });
        let padded_len = match chunk_len.checked_add(3) {
            Some(length) => length & !3,
            None => break,
        };
        offset = match offset.checked_add(padded_len) {
            Some(next) => next,
            None => break,
        };
    }

    Ok(SctpInfo {
        source_port: u16::from_be_bytes([data[0], data[1]]),
        destination_port: u16::from_be_bytes([data[2], data[3]]),
        verification_tag: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        checksum: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        chunks,
    })
}

fn parse_tcp_options(blob: &[u8]) -> TcpOptionsParsed {
    let mut out = TcpOptionsParsed::default();
    let mut i = 0;
    while i < blob.len() {
        let kind = blob[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 2 > blob.len() {
            break;
        }
        let len = blob[i + 1] as usize;
        if len < 2 || i + len > blob.len() {
            break;
        }
        parse_tcp_option(kind, &blob[i..i + len], &mut out);
        i += len;
    }
    out
}

fn parse_tcp_option(kind: u8, option: &[u8], out: &mut TcpOptionsParsed) {
    match kind {
        2 if option.len() >= 4 => {
            out.mss = Some(u16::from_be_bytes([option[2], option[3]]));
        }
        3 if option.len() >= 3 => {
            out.window_scale = Some(option[2]);
        }
        4 => {
            out.sack_permitted = true;
        }
        8 if option.len() >= 10 => {
            out.ts_val = Some(u32::from_be_bytes([
                option[2], option[3], option[4], option[5],
            ]));
            out.ts_ecr = Some(u32::from_be_bytes([
                option[6], option[7], option[8], option[9],
            ]));
        }
        _ => {}
    }
}

fn parse_gre_minimal(data: &[u8]) -> Result<GreInfo, LayerError> {
    if data.len() < 4 {
        return Err(LayerError::InvalidLength);
    }
    let checksum_present = data[0] & 0x80 != 0;
    let key_present = data[0] & 0x20 != 0;
    let sequence_present = data[0] & 0x10 != 0;
    let header_len = 4
        + usize::from(checksum_present) * 4
        + usize::from(key_present) * 4
        + usize::from(sequence_present) * 4;
    if data.len() < header_len {
        return Err(LayerError::InvalidLength);
    }
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);
    let mut offset = 4;
    if checksum_present {
        offset += 4;
    }
    let key = key_present.then(|| {
        let value = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        value
    });
    let sequence = sequence_present.then(|| {
        u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    });
    Ok(GreInfo {
        protocol_type,
        checksum_present,
        key_present,
        sequence_present,
        key,
        sequence,
        header_len,
    })
}

fn parse_ah_minimal(data: &[u8]) -> Result<AhInfo, LayerError> {
    if data.len() < 12 {
        return Err(LayerError::InvalidLength);
    }
    Ok(AhInfo {
        next_header: data[0],
        payload_len: data[1],
        spi: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        sequence: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
    })
}

fn parse_esp_minimal(data: &[u8]) -> Result<EspInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    Ok(EspInfo {
        spi: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        sequence: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
    })
}

fn parse_vxlan_minimal(data: &[u8]) -> Result<VxlanInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    let vni = u32::from(data[4]) << 16 | u32::from(data[5]) << 8 | u32::from(data[6]);
    Ok(VxlanInfo { vni })
}

fn parse_geneve_minimal(data: &[u8]) -> Result<GeneveInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    let version = (data[0] >> 6) & 0x03;
    let opt_len = data[0] & 0x3f;
    let header_len = 8 + usize::from(opt_len) * 4;
    if data.len() < header_len {
        return Err(LayerError::InvalidLength);
    }
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);
    let vni = u32::from(data[4]) << 16 | u32::from(data[5]) << 8 | u32::from(data[6]);
    Ok(GeneveInfo {
        version,
        opt_len,
        protocol_type,
        vni,
        header_len,
    })
}

fn parse_l2tp_minimal(data: &[u8]) -> L2tpInfo {
    let flags = data
        .get(..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .unwrap_or_default();
    let mut offset = 2usize;
    if flags & 0x4000 != 0 {
        offset += 2;
    }
    let tunnel_id = data
        .get(offset..offset.saturating_add(2))
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes);
    offset += 2;
    let session_id = data
        .get(offset..offset.saturating_add(2))
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes);

    L2tpInfo {
        flags,
        version: flags.to_be_bytes()[1] & 0x0f,
        tunnel_id,
        session_id,
    }
}

fn parse_tcp_header(l4_bytes: &[u8], parse_options: bool) -> Result<TcpHeader, LayerError> {
    if l4_bytes.len() < 20 {
        return Err(LayerError::InvalidLength);
    }

    let source_port = u16::from_be_bytes([l4_bytes[0], l4_bytes[1]]);
    let destination_port = u16::from_be_bytes([l4_bytes[2], l4_bytes[3]]);
    let sequence_number = u32::from_be_bytes([l4_bytes[4], l4_bytes[5], l4_bytes[6], l4_bytes[7]]);
    let acknowledgment_number =
        u32::from_be_bytes([l4_bytes[8], l4_bytes[9], l4_bytes[10], l4_bytes[11]]);

    let data_offset = (l4_bytes[12] >> 4) & 0x0f;
    if data_offset < 5 {
        return Err(LayerError::InvalidHeader);
    }

    let header_length = (data_offset as usize) * 4;
    if l4_bytes.len() < header_length {
        return Err(LayerError::InvalidLength);
    }

    let flags = TcpFlags {
        fin: (l4_bytes[13] & 0x01) != 0,
        syn: (l4_bytes[13] & 0x02) != 0,
        rst: (l4_bytes[13] & 0x04) != 0,
        psh: (l4_bytes[13] & 0x08) != 0,
        ack: (l4_bytes[13] & 0x10) != 0,
        urg: (l4_bytes[13] & 0x20) != 0,
        ece: (l4_bytes[13] & 0x40) != 0,
        cwr: (l4_bytes[13] & 0x80) != 0,
        ns: (l4_bytes[12] & 0x01) != 0,
    };

    let window_size = u16::from_be_bytes([l4_bytes[14], l4_bytes[15]]);
    let checksum = u16::from_be_bytes([l4_bytes[16], l4_bytes[17]]);
    let urgent_pointer = u16::from_be_bytes([l4_bytes[18], l4_bytes[19]]);
    let options = if parse_options && header_length > 20 {
        Some(l4_bytes[20..header_length].to_vec())
    } else {
        None
    };

    Ok(TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
        options,
    })
}

fn parse_udp_header(l4_bytes: &[u8]) -> Result<UdpHeader, LayerError> {
    if l4_bytes.len() < 8 {
        return Err(LayerError::InvalidLength);
    }

    let source_port = u16::from_be_bytes([l4_bytes[0], l4_bytes[1]]);
    let destination_port = u16::from_be_bytes([l4_bytes[2], l4_bytes[3]]);
    let length = u16::from_be_bytes([l4_bytes[4], l4_bytes[5]]);
    let checksum = u16::from_be_bytes([l4_bytes[6], l4_bytes[7]]);

    if length < 8 {
        return Err(LayerError::InvalidHeader);
    }
    Ok(UdpHeader {
        source_port,
        destination_port,
        length,
        checksum,
    })
}

fn likely_dns_message(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }

    let opcode = (payload[2] >> 3) & 0x0f;
    if opcode > 5 {
        return false;
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);

    qdcount != 0 || ancount != 0 || nscount != 0 || arcount != 0
}

fn try_parse_dns_message(payload: &[u8]) -> Option<DnsMessage> {
    parse_dns_message(payload).ok()
}

fn likely_dhcp_message(payload: &[u8]) -> bool {
    if payload.len() < 240 {
        return false;
    }

    let op = payload[0];
    if op != 1 && op != 2 {
        return false;
    }

    payload[236..240] == [99, 130, 83, 99]
}

fn likely_dhcp6_message(payload: &[u8]) -> bool {
    payload.len() >= 4 && (1..=13).contains(&payload[0])
}

fn likely_tftp_message(payload: &[u8]) -> bool {
    let Some(opcode) = payload.get(..2) else {
        return false;
    };
    (1..=6).contains(&u16::from_be_bytes([opcode[0], opcode[1]]))
}

fn likely_radius_message(payload: &[u8]) -> bool {
    if payload.len() < 20 {
        return false;
    }

    let known_code = matches!(
        payload[0],
        1 | 2 | 3 | 4 | 5 | 11 | 12 | 13 | 40 | 41 | 42 | 43 | 44 | 45
    );
    let length = u16::from_be_bytes([payload[2], payload[3]]);

    known_code && (20..=4096).contains(&length)
}

fn likely_stun_message(payload: &[u8]) -> bool {
    payload.len() >= 20 && payload[4..8] == [0x21, 0x12, 0xa4, 0x42]
}

fn likely_snmp_message(payload: &[u8]) -> bool {
    payload.len() >= 2 && payload[0] == 0x30
}

fn likely_ntp_message(payload: &[u8]) -> bool {
    if payload.len() < 48 {
        return false;
    }

    let first = payload[0];
    let version = (first >> 3) & 0x07;
    let mode = first & 0x07;

    (1..=4).contains(&version) && (1..=7).contains(&mode)
}

fn push_hint_unique(hints: &mut Vec<UdpAppHint>, hint: UdpAppHint) {
    if !hints.contains(&hint) {
        hints.push(hint);
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::engine::builtin::{
        BuiltinPacketParser, Dnp3AppFunctionCode, Dnp3FunctionCode, FlowKey, FtpMessage,
        OpenVpnOpcode, ParseConfig, ParseWarningCode, SipMessage, SmtpMessage, SnmpMessage,
        SnmpPduType, StopLayer, TelnetCommand, TftpMessage, TransportSegment, UdpAppHint,
        WireGuardMessageType,
    };
    use crate::layer::application::http::HttpMessage;
    use crate::layer::network::icmpv6::NdpMessage;

    fn build_ethernet_ipv4_udp_frame(src_port: u16, dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + udp_payload.len()) as u16;
        let ip_total_len = (20 + udp_len as usize) as u16;

        let mut frame = Vec::with_capacity(14 + ip_total_len as usize);
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&ip_total_len.to_be_bytes());
        frame.extend_from_slice(&0x1234u16.to_be_bytes());
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.push(64);
        frame.push(17);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[192, 168, 1, 1]);
        frame.extend_from_slice(&[224, 0, 0, 251]);

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(udp_payload);

        frame
    }

    fn build_ethernet_ipv6_udp_frame(src_port: u16, dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + udp_payload.len()) as u16;
        let mut udp = Vec::with_capacity(usize::from(udp_len));
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(udp_payload);
        build_ethernet_ipv6_l4_frame(17, &udp)
    }

    fn build_ethernet_ipv4_tcp_frame(src_port: u16, dst_port: u16, tcp_payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::with_capacity(20 + tcp_payload.len());
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.extend_from_slice(&[0x50, 0x18]);
        tcp.extend_from_slice(&0x4000u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(tcp_payload);
        build_ethernet_ipv4_l4_frame(6, &tcp)
    }

    fn tls_client_hello() -> Vec<u8> {
        let mut extensions = Vec::new();

        let server_name = b"example.com";
        let server_name_list_len = 3 + server_name.len();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(2 + server_name_list_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(server_name);

        let alpn_protocols: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let alpn_list_len = alpn_protocols
            .iter()
            .map(|protocol| 1 + protocol.len())
            .sum::<usize>();
        extensions.extend_from_slice(&16u16.to_be_bytes());
        extensions.extend_from_slice(&(2 + alpn_list_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(alpn_list_len as u16).to_be_bytes());
        for protocol in alpn_protocols {
            extensions.push(protocol.len() as u8);
            extensions.extend_from_slice(protocol);
        }

        extensions.extend_from_slice(&43u16.to_be_bytes());
        extensions.extend_from_slice(&5u16.to_be_bytes());
        extensions.push(4);
        extensions.extend_from_slice(&0x0304u16.to_be_bytes());
        extensions.extend_from_slice(&0x0303u16.to_be_bytes());

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0x42; 32]);
        hello.push(0);
        hello.extend_from_slice(&4u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.extend_from_slice(&0x1302u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let handshake_len = hello.len();
        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(4 + handshake_len as u16).to_be_bytes());
        record.push(1);
        record.extend_from_slice(&[
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ]);
        record.extend_from_slice(&hello);
        record
    }

    fn build_ethernet_ipv4_l4_frame(protocol: u8, l4_payload: &[u8]) -> Vec<u8> {
        let ip_total_len = (20 + l4_payload.len()) as u16;
        let mut frame = Vec::with_capacity(14 + ip_total_len as usize);
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&ip_total_len.to_be_bytes());
        frame.extend_from_slice(&0x1234u16.to_be_bytes());
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.push(64);
        frame.push(protocol);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&[10, 0, 0, 2]);
        frame.extend_from_slice(l4_payload);
        frame
    }

    fn build_ethernet_ipv6_l4_frame(next_header: u8, l4_payload: &[u8]) -> Vec<u8> {
        let payload_len = l4_payload.len() as u16;
        let mut frame = Vec::with_capacity(14 + 40 + l4_payload.len());
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());

        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.push(next_header);
        frame.push(64);
        frame.extend_from_slice(&[0; 15]);
        frame.push(1);
        frame.extend_from_slice(&[0; 15]);
        frame.push(1);
        frame.extend_from_slice(l4_payload);
        frame
    }

    fn wireguard_payload(message_type: u8, total_len: usize) -> Vec<u8> {
        let mut payload = vec![0u8; total_len];
        payload[0] = message_type;
        payload
    }

    #[test]
    fn parses_ethernet_ipv4_tcp_minimal() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x12, 0x34,
            0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));
    }

    #[test]
    fn flow_key_uses_outer_ipv4_tcp_tuple_and_reverses_it() {
        let frame = build_ethernet_ipv4_tcp_frame(49152, 443, &[]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let expected = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 49152,
            dst_port: 443,
            protocol: 6,
        };

        assert_eq!(parsed.flow_key(), Some(expected));
        assert_eq!(
            parsed.reverse_flow_key(),
            Some(FlowKey {
                src_ip: expected.dst_ip,
                dst_ip: expected.src_ip,
                src_port: expected.dst_port,
                dst_port: expected.src_port,
                protocol: expected.protocol,
            })
        );
    }

    #[test]
    fn parses_tls_client_hello_from_tcp_payload() {
        let frame = build_ethernet_ipv4_tcp_frame(49152, 8443, &tls_client_hello());
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let tls = parsed.tls.as_ref().expect("TLS ClientHello");

        assert_eq!(tls.server_name.as_deref(), Some("example.com"));
        assert!(tls.alpn.iter().any(|protocol| protocol == "h2"));
        assert!(tls.supported_versions.contains(&0x0304));
        assert!(!tls.cipher_suites.is_empty());
    }

    #[test]
    fn parses_dnp3_on_tcp_port_20000() {
        let payload = [
            0x05, 0x64, 0x0b, 0xc4, 0x03, 0x00, 0x04, 0x00, 0xef, 0x7a, 0xc1, 0xc1, 0x01, 0x3c,
            0x02, 0x06, 0xb5, 0x76,
        ];
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 20_000, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let dnp3 = parsed.dnp3.as_ref().expect("DNP3 should be present");

        assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));
        assert_eq!(dnp3.link_function, Dnp3FunctionCode::UnconfirmedUserData);
        assert_eq!(dnp3.destination, 3);
        assert_eq!(dnp3.source, 4);
        assert_eq!(
            dnp3.application.map(|application| application.function),
            Some(Dnp3AppFunctionCode::Read)
        );
    }

    #[test]
    fn does_not_parse_dnp3_off_well_known_port() {
        let payload = [
            0x05, 0x64, 0x0b, 0xc4, 0x03, 0x00, 0x04, 0x00, 0xef, 0x7a, 0xc1, 0xc1, 0x01, 0x3c,
            0x02, 0x06, 0xb5, 0x76,
        ];
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 20_001, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.dnp3.is_none());
    }

    #[test]
    fn parses_http_request_from_tcp_payload() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(49152, 80, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        let (method, target, host) = parsed
            .http
            .as_ref()
            .and_then(|message| match message {
                HttpMessage::Request {
                    method,
                    target,
                    host,
                    ..
                } => Some((method, target, host)),
                HttpMessage::Response { .. } => None,
            })
            .expect("HTTP request");
        assert_eq!(method, "GET");
        assert_eq!(target, "/index.html");
        assert_eq!(host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_http_response_from_tcp_payload() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(80, 49152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        let status = parsed
            .http
            .as_ref()
            .and_then(|message| match message {
                HttpMessage::Response { status, .. } => Some(*status),
                HttpMessage::Request { .. } => None,
            })
            .expect("HTTP response");
        assert_eq!(status, 200);
    }

    #[test]
    fn rejects_non_http_tcp_payload() {
        let frame = build_ethernet_ipv4_tcp_frame(49152, 80, &[0xde, 0xad, 0xbe, 0xef]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.http.is_none());
    }

    #[test]
    fn parses_ospf_from_ip_payload() {
        let payload = [
            0x02, 0x01, 0x00, 0x2c, 0xc0, 0xa8, 0xaa, 0x08, 0x00, 0x00, 0x00, 0x01, 0x27, 0x3b,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let frame = build_ethernet_ipv4_l4_frame(89, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ospf = parsed.ospf.as_ref().expect("OSPF header");

        assert_eq!(ospf.version, 2);
        assert_eq!(ospf.message_type, 1);
        assert_eq!(ospf.router_id, Ipv4Addr::new(192, 168, 170, 8));
    }

    #[test]
    fn parses_rip_from_udp_payload() {
        let frame = build_ethernet_ipv4_udp_frame(520, 520, &[1, 1, 0, 0]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let rip = parsed.rip.as_ref().expect("RIP header");

        assert_eq!(rip.command, 1);
        assert_eq!(rip.version, 1);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Rip));
    }

    #[test]
    fn parses_isakmp_from_udp_payload() {
        let payload = [
            0x5d, 0x48, 0xbf, 0xee, 0xb7, 0xd5, 0x74, 0xda, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8,
        ];
        let frame = build_ethernet_ipv4_udp_frame(500, 500, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let isakmp = parsed.isakmp.as_ref().expect("ISAKMP header");

        assert_eq!(isakmp.initiator_spi, 0x5d48_bfee_b7d5_74da);
        assert_eq!(isakmp.major_version, 2);
        assert_eq!(isakmp.exchange_type, 0x22);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Isakmp));
    }

    #[test]
    fn parses_sip_request_from_udp_payload() {
        let payload = b"INVITE sip:test@10.0.2.15:5060 SIP/2.0\r\nCall-ID: udp-call\r\nContent-Length: 0\r\n\r\n";
        let frame = build_ethernet_ipv4_udp_frame(5060, 5060, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(matches!(
            parsed.sip,
            Some(SipMessage::Request { ref method, .. }) if method == "INVITE"
        ));
        assert!(parsed.udp_hints.contains(&UdpAppHint::Sip));
    }

    #[test]
    fn parses_sip_response_from_tcp_payload() {
        let payload = b"SIP/2.0 100 Trying\r\nCall-ID: tcp-call\r\nContent-Length: 0\r\n\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(5060, 49152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(matches!(
            parsed.sip,
            Some(SipMessage::Response { status: 100, .. })
        ));
        assert!(parsed.http.is_none());
    }

    #[test]
    fn parses_rtp_as_last_resort_udp_payload() {
        let payload = [
            0x80, 0x80, 0x92, 0xdb, 0x00, 0x00, 0x00, 0xa0, 0x34, 0x3d, 0xa9, 0x9b, 0xaa,
        ];
        let frame = build_ethernet_ipv4_udp_frame(27_942, 6000, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let rtp = parsed.rtp.as_ref().expect("RTP header");

        assert_eq!(rtp.sequence_number, 37_595);
        assert_eq!(rtp.timestamp, 160);
        assert_eq!(rtp.ssrc, 0x343d_a99b);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Rtp));
    }

    #[test]
    fn parses_rtcp_sender_report_as_last_resort_udp_payload() {
        let payload = [0x81, 0xc8, 0x00, 0x0c, 0x5d, 0x93, 0x15, 0x34];
        let frame = build_ethernet_ipv4_udp_frame(27_943, 6001, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let rtcp = parsed.rtcp.as_ref().expect("RTCP header");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Rtcp));
        assert_eq!(rtcp.packet_type, 200);
        assert_eq!(rtcp.version, 2);
        assert_eq!(rtcp.ssrc, 0x5d93_1534);
    }

    #[test]
    fn parses_ssh_banner_on_nonstandard_tcp_port() {
        let payload = b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 29_418, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ssh = parsed.ssh.as_ref().expect("SSH banner");

        assert_eq!(ssh.protocol_version, "2.0");
        assert_eq!(ssh.software_version, "OpenSSH_7.6p1");
    }

    #[test]
    fn parses_ftp_response_on_tcp_port_21() {
        let payload = b"220 FTP server ready.\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(21, 49_152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.ftp,
            Some(FtpMessage::Response {
                code: 220,
                text: "FTP server ready.".to_string(),
            })
        );
    }

    #[test]
    fn parses_ftp_command_on_tcp_port_21() {
        let payload = b"USER anonymous\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 21, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.ftp,
            Some(FtpMessage::Command {
                verb: "USER".to_string(),
                args: "anonymous".to_string(),
            })
        );
    }

    #[test]
    fn parses_smtp_response_on_tcp_port_25() {
        let payload = b"220-mail.example ESMTP ready\r\n220 mail.example ready\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(25, 49_152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.smtp,
            Some(SmtpMessage::Response {
                code: 220,
                text: "mail.example ESMTP ready".to_string(),
            })
        );
    }

    #[test]
    fn parses_smtp_command_on_tcp_port_25() {
        let payload = b"EHLO client.example\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 25, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.smtp,
            Some(SmtpMessage::Command {
                verb: "EHLO".to_string(),
                args: "client.example".to_string(),
            })
        );
    }

    #[test]
    fn parses_telnet_iac_do_on_tcp_port_23() {
        let payload = [0xff, 0xfd, 0x03, 0xff, 0xfb, 0x01];
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 23, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.telnet,
            Some(TelnetCommand {
                command: 0xfd,
                option: 0x03,
            })
        );
    }

    #[test]
    fn parses_quic_initial_from_udp_payload() {
        let payload = [
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x11, 0x22, 0x33, 0x44, 0x00,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 443, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let quic = parsed.quic.as_ref().expect("QUIC long header");

        assert!(quic.is_initial);
        assert_eq!(quic.version, 1);
        assert_eq!(quic.dcid, [0x11, 0x22, 0x33, 0x44]);
        assert!(quic.scid.is_empty());
    }

    #[test]
    fn classifies_quic_short_header_as_hint_only() {
        let frame = build_ethernet_ipv4_udp_frame(49152, 443, &[0x40]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::QuicShort));
        assert!(parsed.quic.is_none());
    }

    #[test]
    fn parses_icmp_echo_identifier_and_sequence() {
        let frame = build_ethernet_ipv4_l4_frame(1, &[8, 0, 0, 0, 0x12, 0x34, 0xab, 0xcd]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let icmp = parsed.icmp.as_ref().expect("icmp");

        assert_eq!(icmp.echo_identifier(), Some(0x1234));
        assert_eq!(icmp.echo_sequence(), Some(0xabcd));
    }

    #[test]
    fn parses_icmpv6_echo_identifier_and_sequence() {
        let frame = build_ethernet_ipv6_l4_frame(58, &[128, 0, 0, 0, 0x56, 0x78, 0x9a, 0xbc]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let icmpv6 = parsed.icmpv6.as_ref().expect("icmpv6");

        assert_eq!(icmpv6.echo_identifier(), Some(0x5678));
        assert_eq!(icmpv6.echo_sequence(), Some(0x9abc));
    }

    #[test]
    fn parses_ndp_neighbor_solicitation_with_source_link_addr() {
        let target = "2001:db8::1234"
            .parse::<Ipv6Addr>()
            .expect("valid target address");
        let link_addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut message = vec![135, 0, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&target.octets());
        message.extend_from_slice(&[1, 1]);
        message.extend_from_slice(&link_addr);

        let frame = build_ethernet_ipv6_l4_frame(58, &message);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ndp = parsed.ndp.as_ref().expect("neighbor solicitation");
        assert!(matches!(ndp, NdpMessage::NeighborSolicitation { .. }));
        if let NdpMessage::NeighborSolicitation {
            target: parsed_target,
            options,
        } = ndp
        {
            assert_eq!(*parsed_target, target);
            assert_eq!(options.len(), 1);
            assert_eq!(options[0].source_link_addr(), Some(link_addr.as_slice()));
        }
    }

    #[test]
    fn parses_ndp_router_advertisement_with_mtu() {
        let mut message = vec![134, 0, 0, 0, 64, 0x80];
        message.extend_from_slice(&1800u16.to_be_bytes());
        message.extend_from_slice(&30_000u32.to_be_bytes());
        message.extend_from_slice(&1_000u32.to_be_bytes());
        message.extend_from_slice(&[5, 1, 0, 0]);
        message.extend_from_slice(&1500u32.to_be_bytes());

        let frame = build_ethernet_ipv6_l4_frame(58, &message);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ndp = parsed.ndp.as_ref().expect("router advertisement");
        assert!(matches!(ndp, NdpMessage::RouterAdvertisement { .. }));
        if let NdpMessage::RouterAdvertisement { options, .. } = ndp {
            assert_eq!(options.len(), 1);
            assert_eq!(options[0].mtu(), Some(1500));
        }
    }

    #[test]
    fn parses_sctp_common_header_and_init_chunk() {
        let sctp = [
            0x13, 0x88, 0x13, 0x89, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x00,
            0x00, 0x04,
        ];
        let frame = build_ethernet_ipv4_l4_frame(132, &sctp);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let sctp = parsed.sctp.as_ref().expect("sctp");

        assert_eq!(sctp.source_port, 5000);
        assert_eq!(sctp.destination_port, 5001);
        assert_eq!(sctp.verification_tag, 0x1122_3344);
        assert_eq!(sctp.chunks.len(), 1);
        assert_eq!(sctp.chunks[0].chunk_type, 1);
    }

    #[test]
    fn parses_ethernet_vlan_ipv4_udp_dns() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, 0x00, 0x64, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x3d, 0x12, 0x34, 0x40, 0x00, 64, 17, 0x00, 0x00, 192, 168, 1, 1, 8, 8, 8, 8,
            0x30, 0x39, 0x00, 0x35, 0x00, 0x29, 0x00, 0x00, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
        assert!(parsed.dns.is_some());
        assert!(parsed.udp_hints.contains(&UdpAppHint::Dns));
    }

    #[test]
    fn transport_mode_skips_dns_but_keeps_udp_flow_key() {
        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let frame = build_ethernet_ipv4_udp_frame(12345, 53, &dns_query);
        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                stop_after: StopLayer::Transport,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        assert!(parsed.dns.is_none());
        assert!(parsed.udp_hints.is_empty());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
        assert_eq!(
            parsed.flow_key(),
            Some(FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                src_port: 12345,
                dst_port: 53,
                protocol: 17,
            })
        );
    }

    #[test]
    fn default_application_mode_still_parses_dns() {
        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let frame = build_ethernet_ipv4_udp_frame(12345, 53, &dns_query);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.dns.is_some());
    }

    #[test]
    fn network_mode_stops_after_ipv4_header() {
        let frame = build_ethernet_ipv4_tcp_frame(49152, 443, &[]);
        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                stop_after: StopLayer::Network,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        assert!(parsed.ipv4.is_some());
        assert!(parsed.transport.is_none());
        assert_eq!(
            parsed.flow_key(),
            Some(FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: 0,
                dst_port: 0,
                protocol: 6,
            })
        );
    }

    #[test]
    fn parses_dhcp_discover() {
        let mut payload = vec![0u8; 244];
        payload[0] = 1;
        payload[236..240].copy_from_slice(&[99, 130, 83, 99]);
        payload[240..244].copy_from_slice(&[53, 1, 1, 255]);

        let frame = build_ethernet_ipv4_udp_frame(68, 67, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Dhcp));
        assert_eq!(parsed.dhcp.as_ref().expect("dhcp").message_type, Some(1));
    }

    #[test]
    fn parses_dhcp6_solicit() {
        let payload = [
            1, 0x10, 0x08, 0x74, 0, 1, 0, 14, 0, 1, 0, 1, 0x2a, 0x2b, 0x2c, 0x2d, 0, 1, 2, 3, 4, 5,
        ];

        let frame = build_ethernet_ipv6_udp_frame(546, 547, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Dhcpv6));
        let dhcp6 = parsed.dhcp6.as_ref().expect("dhcpv6");
        assert_eq!(dhcp6.msg_type, 1);
        assert_eq!(dhcp6.transaction_id, 0x10_0874);
    }

    #[test]
    fn parses_radius_access_request() {
        let payload = [
            0x01, 0x67, 0x00, 0x57, 0x40, 0xb6, 0x64, 0xdb, 0xf5, 0xd6, 0x81, 0xb2, 0xad, 0xbd,
            0x17, 0x69, 0x51, 0x51, 0x18, 0xc8, 0x01, 0x07, 0x73, 0x74, 0x65, 0x76, 0x65, 0x02,
            0x12, 0xdb, 0xc6, 0xc4, 0xb7, 0x58, 0xbe, 0x14, 0xf0, 0x05, 0xb3, 0x87, 0x7c, 0x9e,
            0x2f, 0xb6, 0x01, 0x04, 0x06, 0xc0, 0xa8, 0x00, 0x1c, 0x05, 0x06, 0x00, 0x00, 0x00,
            0x7b, 0x50, 0x12, 0x5f, 0x0f, 0x86, 0x47, 0xe8, 0xc8, 0x9b, 0xd8, 0x81, 0x36, 0x42,
            0x68, 0xfc, 0xd0, 0x45, 0x32, 0x4f, 0x0c, 0x02, 0x66, 0x00, 0x0a, 0x01, 0x73, 0x74,
            0x65, 0x76, 0x65,
        ];

        let frame = build_ethernet_ipv4_udp_frame(49_152, 1812, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let radius = parsed.radius.as_ref().expect("RADIUS should be present");
        assert_eq!(radius.code, 1);
        assert_eq!(radius.identifier, 103);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Radius));
    }

    #[test]
    fn parses_snmp_v3_get_request() {
        let payload = [
            0x30, 0x4b, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x30, 0xf6, 0xf3, 0xd4, 0x02,
            0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e,
            0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
            0x30, 0x21, 0x04, 0x0d, 0x80, 0x00, 0x1f, 0x88, 0x80, 0x59, 0xdc, 0x48, 0x61, 0x45,
            0xa2, 0x63, 0x22, 0x04, 0x00, 0xa0, 0x0e, 0x02, 0x04, 0x7d, 0x0e, 0x08, 0x2e, 0x02,
            0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];

        let frame = build_ethernet_ipv4_udp_frame(49_152, 161, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(matches!(
            parsed.snmp,
            Some(SnmpMessage::V3 {
                msg_id: 821_490_644,
                msg_max_size: 65_507,
                msg_flags: 0x04,
                pdu_type: Some(SnmpPduType::GetRequest),
                request_id: Some(2_098_071_598),
                ..
            })
        ));
        assert!(parsed.udp_hints.contains(&UdpAppHint::Snmp));
    }

    #[test]
    fn parses_tftp_read_request_only_on_well_known_port() {
        let payload = b"\0\x01rfc1350.txt\0octet\0";
        let frame = build_ethernet_ipv4_udp_frame(49152, 69, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.tftp,
            Some(TftpMessage::ReadRequest {
                filename: "rfc1350.txt".to_owned(),
                mode: "octet".to_owned(),
            })
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::Tftp));

        let non_tftp_frame = build_ethernet_ipv4_udp_frame(49152, 1069, payload);
        let non_tftp = BuiltinPacketParser::parse(&non_tftp_frame).expect("parse should succeed");
        assert!(non_tftp.tftp.is_none());
        assert!(!non_tftp.udp_hints.contains(&UdpAppHint::Tftp));
    }

    #[test]
    fn parses_ntp_client() {
        let mut payload = vec![0u8; 48];
        payload[0] = 0x23;
        payload[1] = 2;
        payload[16..24].copy_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        payload[40..48].copy_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());

        let frame = build_ethernet_ipv4_udp_frame(123, 123, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Ntp));
        let ntp = parsed.ntp.as_ref().expect("ntp");
        assert_eq!(ntp.version, 4);
        assert_eq!(ntp.mode, 3);
        assert_eq!(ntp.reference_ts, 0x0102_0304_0506_0708);
        assert_eq!(ntp.transmit_ts, 0x1112_1314_1516_1718);
    }

    #[test]
    fn parses_l2tp_over_udp() {
        let l2tp = [
            0x42, 0x02, 0x00, 0x0c, 0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0x00, 0x02,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 1701, &l2tp);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let l2tp = parsed.l2tp.as_ref().expect("L2TP metadata");
        assert_eq!(l2tp.flags, 0x4202);
        assert_eq!(l2tp.version, 2);
        assert_eq!(l2tp.tunnel_id, Some(0x1234));
        assert_eq!(l2tp.session_id, Some(0x5678));
        assert!(parsed.udp_hints.contains(&UdpAppHint::L2tp));
    }

    #[test]
    fn detects_mdns_udp_probe() {
        let payload = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let frame = build_ethernet_ipv4_udp_frame(5353, 5353, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Mdns));
        assert!(parsed.dns.is_some());
    }

    #[test]
    fn test_stun_udp_hint() {
        let payload = [
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 3478, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Stun));
        assert!(parsed.stun.is_some());
    }

    #[test]
    fn test_llmnr_udp_hint() {
        let payload = [
            0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 5355, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Llmnr));
        assert!(parsed.dns.is_none());
    }

    #[test]
    fn test_nbns_udp_hint() {
        let payload = [
            0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 137, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Nbns));
        assert!(parsed.dns.is_none());
    }

    #[test]
    fn parses_tcp_options_mss_and_window_scale() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x70, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let opts = parsed.tcp_options.as_ref().expect("tcp_options");
        assert_eq!(opts.mss, Some(1460));
        assert_eq!(opts.window_scale, Some(7));
    }

    #[test]
    fn parses_ipv4_gre() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x2c, 0x00, 0x01,
            0x40, 0x00, 64, 47, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 64, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(parsed.gre.is_some());
        assert_eq!(parsed.gre.as_ref().unwrap().protocol_type, 0x0800);
        assert!(
            parsed
                .inner
                .as_ref()
                .is_some_and(|inner| inner.ipv4.is_some())
        );
        assert!(
            !parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::GreInner))
        );
    }

    #[test]
    fn gre_minimal_parsed_with_warning() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x24, 0x00, 0x01,
            0x40, 0x00, 64, 47, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.gre.is_some());
        assert_eq!(parsed.gre.as_ref().unwrap().protocol_type, 0x0800);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::GreInner))
        );
    }

    #[test]
    fn gre_key_and_sequence_extend_header() {
        let gre_header = [
            0x30, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let frame = build_ethernet_ipv4_l4_frame(47, &gre_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let gre = parsed.gre.as_ref().expect("gre");
        assert!(!gre.checksum_present);
        assert!(gre.key_present);
        assert!(gre.sequence_present);
        assert_eq!(gre.key, Some(0x0102_0304));
        assert_eq!(gre.sequence, Some(0x0506_0708));
        assert_eq!(gre.header_len, 12);
    }

    #[test]
    fn gre_truncated_checksum_header_errors() {
        let frame = build_ethernet_ipv4_l4_frame(47, &[0x80, 0x00, 0x08, 0x00]);
        assert!(BuiltinPacketParser::parse(&frame).is_err());
    }

    #[test]
    fn tcp_options_mss_and_window_scale_parsed() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.tcp_options.is_some());
        let opts = parsed.tcp_options.as_ref().unwrap();
        assert_eq!(opts.mss, Some(0x05b4));
        assert_eq!(opts.window_scale, Some(6));
    }

    #[test]
    fn vxlan_minimal_parsed_with_warning() {
        let vxlan_header: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 100, 0];
        let frame = build_ethernet_ipv4_udp_frame(4789, 4789, &vxlan_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.vxlan.is_some());
        assert_eq!(parsed.vxlan.as_ref().unwrap().vni, 100);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::VxlanInner))
        );
    }

    #[test]
    fn vxlan_decodes_inner_ethernet_ipv4_udp() {
        let inner = build_ethernet_ipv4_udp_frame(1234, 4321, &[]);
        let mut payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 100, 0];
        payload.extend_from_slice(&inner);
        let frame = build_ethernet_ipv4_udp_frame(4789, 4789, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.vxlan.is_some());
        let inner = parsed.inner.as_ref().expect("inner packet");
        assert!(inner.ethernet.is_some());
        assert!(inner.ipv4.is_some());
        assert!(matches!(inner.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn vxlan_flow_key_uses_inner_ipv4_tcp_tuple_in_transport_mode() {
        let inner = build_ethernet_ipv4_tcp_frame(23456, 8443, &[]);
        let mut payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 100, 0];
        payload.extend_from_slice(&inner);
        let frame = build_ethernet_ipv4_udp_frame(4789, 4789, &payload);
        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                stop_after: StopLayer::Transport,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        assert!(parsed.vxlan.is_some());
        assert!(parsed.inner.is_some());
        assert_eq!(
            parsed.flow_key(),
            Some(FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: 23456,
                dst_port: 8443,
                protocol: 6,
            })
        );
    }

    #[test]
    fn ipv4_in_ipv4_decodes_inner_packet() {
        let inner_frame = build_ethernet_ipv4_l4_frame(1, &[8, 0, 0, 0, 0, 1, 0, 1]);
        let frame = build_ethernet_ipv4_l4_frame(4, &inner_frame[14..]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(
            parsed
                .inner
                .as_ref()
                .is_some_and(|inner| inner.ipv4.is_some())
        );
    }

    #[test]
    fn zero_tunnel_depth_disables_recursion() {
        let inner_frame = build_ethernet_ipv4_l4_frame(1, &[8, 0, 0, 0, 0, 1, 0, 1]);
        let mut gre = vec![0x00, 0x00, 0x08, 0x00];
        gre.extend_from_slice(&inner_frame[14..]);
        let frame = build_ethernet_ipv4_l4_frame(47, &gre);

        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                max_tunnel_depth: 0,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");
        assert!(parsed.inner.is_none());
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::TunnelDepthLimit))
        );
    }

    #[test]
    fn geneve_minimal_parsed_with_warning() {
        let geneve_header: [u8; 8] = [0x00, 0x00, 0x65, 0x58, 0x00, 0x00, 101, 0];
        let frame = build_ethernet_ipv4_udp_frame(6081, 6081, &geneve_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.geneve.is_some());
        assert_eq!(parsed.geneve.as_ref().unwrap().version, 0);
        assert_eq!(parsed.geneve.as_ref().unwrap().protocol_type, 0x6558);
        assert_eq!(parsed.geneve.as_ref().unwrap().vni, 101);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::GeneveInner))
        );
    }

    #[test]
    fn geneve_options_extend_header() {
        let geneve_header: [u8; 12] = [
            0x01, 0x00, 0x65, 0x58, 0x00, 0x00, 101, 0, 0x01, 0x02, 0x03, 0x04,
        ];
        let frame = build_ethernet_ipv4_udp_frame(6081, 6081, &geneve_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let geneve = parsed.geneve.as_ref().expect("geneve");
        assert_eq!(geneve.opt_len, 1);
        assert_eq!(geneve.header_len, 12);
    }

    #[test]
    fn geneve_truncated_options_are_not_parsed() {
        let geneve_header: [u8; 8] = [0x01, 0x00, 0x65, 0x58, 0x00, 0x00, 101, 0];
        let frame = build_ethernet_ipv4_udp_frame(6081, 6081, &geneve_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.geneve.is_none());
    }

    #[test]
    fn classifies_wireguard_handshake_initiation() {
        let wg = wireguard_payload(1, 148);
        let frame = build_ethernet_ipv4_udp_frame(51820, 51820, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.wireguard.is_some());
        assert_eq!(
            parsed.wireguard.as_ref().unwrap().message_type,
            WireGuardMessageType::HandshakeInitiation
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn classifies_wireguard_handshake_response() {
        let wg = wireguard_payload(2, 92);
        let frame = build_ethernet_ipv4_udp_frame(51821, 51821, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert_eq!(
            parsed.wireguard.as_ref().unwrap().message_type,
            WireGuardMessageType::HandshakeResponse
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn classifies_wireguard_cookie_reply() {
        let wg = wireguard_payload(3, 64);
        let frame = build_ethernet_ipv4_udp_frame(51820, 9999, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert_eq!(
            parsed.wireguard.as_ref().unwrap().message_type,
            WireGuardMessageType::CookieReply
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn classifies_wireguard_transport_data() {
        let wg = wireguard_payload(4, 32);
        let frame = build_ethernet_ipv4_udp_frame(9999, 51820, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert_eq!(
            parsed.wireguard.as_ref().unwrap().message_type,
            WireGuardMessageType::TransportData
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn does_not_classify_wireguard_when_payload_too_short() {
        let mut wg = vec![0u8; 40];
        wg[0] = 1;
        let frame = build_ethernet_ipv4_udp_frame(51820, 51820, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.wireguard.is_none());
        assert!(!parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn classifies_openvpn_udp_control_packet() {
        let session_id = 0x8138_1462_1d67_462d_u64;
        let mut payload = vec![0x38];
        payload.extend_from_slice(&session_id.to_be_bytes());
        payload.extend_from_slice(&[0xaa, 0xbb]);
        let frame = build_ethernet_ipv4_udp_frame(49152, 1194, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, OpenVpnOpcode::ControlHardResetClientV2);
        assert_eq!(openvpn.key_id, 0);
        assert_eq!(openvpn.session_id, Some(session_id));
        assert_eq!(openvpn.peer_id, None);
        assert!(parsed.udp_hints.contains(&UdpAppHint::OpenVpn));
    }

    #[test]
    fn classifies_openvpn_udp_data_v1_without_session_id() {
        let payload = [0x30, 0xd7, 0xb2, 0x33];
        let frame = build_ethernet_ipv4_udp_frame(1194, 49152, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, OpenVpnOpcode::DataV1);
        assert_eq!(openvpn.session_id, None);
        assert_eq!(openvpn.peer_id, None);
    }

    #[test]
    fn classifies_openvpn_udp_data_v2_with_peer_id() {
        let payload = [0x48, 0x12, 0x34, 0x56, 0xde, 0xad];
        let frame = build_ethernet_ipv4_udp_frame(49152, 1194, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, OpenVpnOpcode::DataV2);
        assert_eq!(openvpn.session_id, None);
        assert_eq!(openvpn.peer_id, Some(0x12_3456));
    }

    #[test]
    fn classifies_length_prefixed_openvpn_tcp_packet() {
        let session_id = 0x8138_1462_1d67_462d_u64;
        let mut payload = vec![0x00, 0x09, 0x38];
        payload.extend_from_slice(&session_id.to_be_bytes());
        let frame = build_ethernet_ipv4_tcp_frame(49152, 1194, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, OpenVpnOpcode::ControlHardResetClientV2);
        assert_eq!(openvpn.session_id, Some(session_id));
    }

    #[test]
    fn does_not_classify_openvpn_on_non_default_port() {
        let payload = [0x38, 0x81, 0x38, 0x14, 0x62, 0x1d, 0x67, 0x46, 0x2d];
        let frame = build_ethernet_ipv4_udp_frame(49152, 443, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.openvpn.is_none());
        assert!(!parsed.udp_hints.contains(&UdpAppHint::OpenVpn));
    }

    #[test]
    fn does_not_classify_invalid_openvpn_opcode() {
        let payload = [0x78, 0x81, 0x38, 0x14, 0x62, 0x1d, 0x67, 0x46, 0x2d];
        let frame = build_ethernet_ipv4_udp_frame(49152, 1194, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.openvpn.is_none());
        assert!(!parsed.udp_hints.contains(&UdpAppHint::OpenVpn));
    }

    #[test]
    fn ah_minimal_parsed_with_warning() {
        let ah = [58, 1, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x09];
        let frame = build_ethernet_ipv4_l4_frame(51, &ah);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ah.is_some());
        assert_eq!(parsed.ah.as_ref().unwrap().next_header, 58);
        assert_eq!(parsed.ah.as_ref().unwrap().spi, 0x1122_3344);
        assert_eq!(parsed.ah.as_ref().unwrap().sequence, 9);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::AhInner))
        );
    }

    #[test]
    fn esp_minimal_parsed_with_warning() {
        let esp = [0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x02];
        let frame = build_ethernet_ipv4_l4_frame(50, &esp);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.esp.is_some());
        assert_eq!(parsed.esp.as_ref().unwrap().spi, 0xaabb_ccdd);
        assert_eq!(parsed.esp.as_ref().unwrap().sequence, 2);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::EspInner))
        );
    }

    #[test]
    fn tcp_options_timestamp_and_sack_permitted() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3a, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x90, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x02, 0x08, 0x0a, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x01,
            0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let opts = parsed.tcp_options.as_ref().expect("tcp_options");
        assert!(opts.sack_permitted);
        assert_eq!(opts.ts_val, Some(0x1111_1111));
        assert_eq!(opts.ts_ecr, Some(0x2222_2222));
    }
}
