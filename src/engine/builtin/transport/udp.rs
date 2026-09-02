use super::minimal::{parse_geneve_minimal, parse_l2tp_minimal, parse_vxlan_minimal};
use super::*;

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
pub(super) const UDP_PORT_SIP: u16 = 5060;
const UDP_PORT_WIREGUARD: u16 = 51820;
const UDP_PORT_WIREGUARD_ALT: u16 = 51821;
const UDP_PORT_COAP: u16 = 5683;
const UDP_PORT_SSDP: u16 = 1900;
const UDP_PORT_NAT_PMP: u16 = 5351;
const UDP_PORT_ISAKMP: u16 = 500;
const UDP_PORT_RIP: u16 = 520;
const UDP_PORT_RPC: u16 = 2049;
const UDP_PORT_SYSLOG: u16 = 514;
const UDP_PORT_HSRP: u16 = 1985;
const STUN_PORT: u16 = 3478;
const UDP_PORT_LLMNR: u16 = 5355;
const UDP_PORT_NBNS: u16 = 137;
pub(super) fn parse_udp_transport(
    parsed: &mut ParsedPacket,
    l4_bytes: &[u8],
    config: ParseConfig,
) -> Result<(), LayerError> {
    let udp = parse_udp_header(l4_bytes)?;
    let declared_end = usize::from(udp.length);
    if declared_end > l4_bytes.len() && config.mode == ParseMode::Strict {
        return Err(LayerError::InvalidLength);
    }
    let udp_end = declared_end.min(l4_bytes.len());
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
    let mut ssdp = None;
    let mut nat_pmp = None;
    let mut pcp = None;
    let mut kerberos = None;
    let mut stun = None;
    let mut rip = None;
    let mut isakmp = None;
    let mut rpc = None;
    let mut syslog = None;
    let mut hsrp = None;

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
        maybe_probe_ssdp_udp(&udp, app, &mut hints, &mut ssdp);
        maybe_probe_pcp_nat_pmp_udp(&udp, app, &mut hints, &mut pcp, &mut nat_pmp);
        maybe_probe_kerberos_udp(&udp, app, &mut hints, &mut kerberos);
        maybe_probe_stun_udp(&udp, app, &mut hints, &mut stun);
        maybe_probe_rip_udp(&udp, app, &mut hints, &mut rip);
        maybe_probe_isakmp_udp(&udp, app, &mut hints, &mut isakmp);
        maybe_probe_rpc_udp(&udp, app, &mut hints, &mut rpc);
        maybe_probe_syslog_udp(&udp, app, &mut hints, &mut syslog);
        maybe_probe_hsrp_udp(&udp, app, &mut hints, &mut hsrp);
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
    // Require the fixed bit here to avoid matching RTP v2 version bits. This runs
    // at the transport layer so the SCID can seed a QuicConnectionTracker before
    // application parsing.
    let quic = (wireguard.is_none()
        && openvpn.is_none()
        && vxlan.is_none()
        && geneve.is_none()
        && l2tp.is_none()
        && app.len() >= 7
        && app[0] & 0xc0 == 0xc0)
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
        ssdp.is_some(),
        nat_pmp.is_some(),
        pcp.is_some(),
        kerberos.is_some(),
        stun.is_some(),
        rip.is_some(),
        isakmp.is_some(),
        rpc.is_some(),
        syslog.is_some(),
        hsrp.is_some(),
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

    parsed.transport = Some(TransportSegment::Udp(udp));
    parsed.vxlan = vxlan;
    parsed.geneve = geneve;
    parsed.l2tp = l2tp;
    parsed.wireguard = wireguard;
    parsed.openvpn = openvpn;
    parsed.dns = dns;
    parsed.dhcp = dhcp;
    parsed.dhcp6 = dhcp6;
    parsed.tftp = tftp;
    parsed.radius = radius;
    parsed.snmp = snmp;
    parsed.ntp = ntp;
    parsed.sip = sip;
    parsed.rtcp = rtcp;
    parsed.rtp = rtp;
    parsed.quic = quic;
    parsed.coap = coap;
    parsed.ssdp = ssdp;
    parsed.nat_pmp = nat_pmp;
    parsed.pcp = pcp;
    parsed.kerberos = kerberos;
    parsed.stun = stun;
    parsed.rip = rip;
    parsed.isakmp = isakmp;
    parsed.rpc = rpc;
    parsed.syslog = syslog;
    parsed.hsrp = hsrp;
    parsed.udp_hints = hints;
    Ok(())
}

fn maybe_probe_hsrp_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    hsrp: &mut Option<HsrpHeader>,
) {
    if is_udp_port_match(udp, UDP_PORT_HSRP)
        && let Ok(header) = parse_hsrp_header(payload)
    {
        push_hint_unique(hints, UdpAppHint::Hsrp);
        *hsrp = Some(header);
    }
}

fn maybe_probe_syslog_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    syslog: &mut Option<SyslogMessage>,
) {
    if !is_udp_port_match(udp, UDP_PORT_SYSLOG) {
        return;
    }
    if let Ok(message) = parse_syslog_message(payload) {
        push_hint_unique(hints, UdpAppHint::Syslog);
        *syslog = Some(message);
    }
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

/// Probes only the well-known TFTP port.
///
/// Transfer packets use ephemeral ports and are too generic for safe stateless
/// detection.
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

fn maybe_probe_ssdp_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    ssdp: &mut Option<SsdpMessage>,
) {
    if is_udp_port_match(udp, UDP_PORT_SSDP)
        && let Ok(message) = parse_ssdp(payload)
    {
        push_hint_unique(hints, UdpAppHint::Ssdp);
        *ssdp = Some(message);
    }
}

fn maybe_probe_pcp_nat_pmp_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    pcp: &mut Option<PcpHeader>,
    nat_pmp: &mut Option<NatPmpMessage>,
) {
    if !is_udp_port_match(udp, UDP_PORT_NAT_PMP) {
        return;
    }
    if let Ok(header) = parse_pcp_header(payload) {
        push_hint_unique(hints, UdpAppHint::Pcp);
        *pcp = Some(header);
    } else if let Ok(message) = parse_nat_pmp(payload) {
        push_hint_unique(hints, UdpAppHint::NatPmp);
        *nat_pmp = Some(message);
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

fn maybe_probe_rpc_udp(
    udp: &UdpHeader,
    payload: &[u8],
    hints: &mut Vec<UdpAppHint>,
    rpc: &mut Option<RpcMessage>,
) {
    if is_udp_port_match(udp, UDP_PORT_RPC)
        && let Ok(message) = parse_rpc_message(payload)
    {
        push_hint_unique(hints, UdpAppHint::Rpc);
        *rpc = Some(message);
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
        && probe_dns(payload).ok().is_some()
    {
        push_hint_unique(hints, UdpAppHint::Llmnr);
    }
}

fn maybe_probe_nbns_udp(udp: &UdpHeader, payload: &[u8], hints: &mut Vec<UdpAppHint>) {
    if is_udp_port_match(udp, UDP_PORT_NBNS)
        && payload.len() >= 12
        && probe_dns(payload).ok().is_some()
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

pub(super) fn maybe_classify_openvpn_tcp(
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

/// Parses the fixed OpenVPN wire header.
///
/// Control data after the eight-byte session ID stays opaque because fields such
/// as the tls-auth HMAC have deployment-specific lengths.
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
    probe_dns(payload).ok()
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
