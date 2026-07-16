use std::net::Ipv4Addr;

use crate::engine::constants::ip_proto;
use crate::layer::application::dhcp::{parse_dhcp_message, DhcpMessage};
use crate::layer::application::dns::{parse_dns_message, DnsMessage};
use crate::layer::application::http::{parse_http, HttpMessage};
use crate::layer::application::ntp::{parse_ntp_message, NtpMessage};
use crate::layer::application::quic::{parse_quic_long_header, QuicLongHeader};
use crate::layer::application::tls::{parse_tls_client_hello, TlsClientHello};
use crate::layer::network::icmp::IcmpHeader;
use crate::layer::network::icmpv6::Icmpv6Header;
use crate::layer::transport::tcp::{TcpFlags, TcpHeader};
use crate::layer::transport::udp::UdpHeader;
use crate::layer::LayerError;

use super::types::{
    AhInfo, EspInfo, GeneveInfo, GreInfo, IgmpInfo, SctpChunk, SctpInfo, TcpOptionsParsed,
    TransportSegment, UdpAppHint, VxlanInfo, WireGuardInfo, WireGuardMessageType,
};

const UDP_HEADER_LEN: usize = 8;
const UDP_PORT_DNS: u16 = 53;
const UDP_PORT_MDNS: u16 = 5353;
const UDP_PORT_DHCP_SERVER: u16 = 67;
const UDP_PORT_DHCP_CLIENT: u16 = 68;
const UDP_PORT_NTP: u16 = 123;
const UDP_PORT_VXLAN: u16 = 4789;
const UDP_PORT_GENEVE: u16 = 6081;
const UDP_PORT_WIREGUARD: u16 = 51820;
const UDP_PORT_WIREGUARD_ALT: u16 = 51821;

#[derive(Debug, Default)]
pub(super) struct TransportParse {
    pub transport: Option<TransportSegment>,
    pub icmp: Option<IcmpHeader>,
    pub icmpv6: Option<Icmpv6Header>,
    pub igmp: Option<IgmpInfo>,
    pub sctp: Option<SctpInfo>,
    pub tcp_options: Option<TcpOptionsParsed>,
    pub gre: Option<GreInfo>,
    pub vxlan: Option<VxlanInfo>,
    pub geneve: Option<GeneveInfo>,
    pub ah: Option<AhInfo>,
    pub esp: Option<EspInfo>,
    pub wireguard: Option<WireGuardInfo>,
    pub dns: Option<DnsMessage>,
    pub dhcp: Option<DhcpMessage>,
    pub ntp: Option<NtpMessage>,
    pub tls: Option<TlsClientHello>,
    pub http: Option<HttpMessage>,
    pub quic: Option<QuicLongHeader>,
    pub hints: Vec<UdpAppHint>,
}

impl TransportParse {
    fn with_tcp(tcp: TcpHeader, tcp_options: TcpOptionsParsed) -> Self {
        Self {
            transport: Some(TransportSegment::Tcp(tcp)),
            tcp_options: Some(tcp_options),
            ..Self::default()
        }
    }

    fn with_icmp(icmp: IcmpHeader) -> Self {
        Self {
            icmp: Some(icmp),
            ..Self::default()
        }
    }

    fn with_icmpv6(icmpv6: Icmpv6Header) -> Self {
        Self {
            icmpv6: Some(icmpv6),
            ..Self::default()
        }
    }

    fn with_igmp(igmp: IgmpInfo) -> Self {
        Self {
            igmp: Some(igmp),
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

pub(super) fn parse_transport(protocol: u8, l4_bytes: &[u8]) -> Result<TransportParse, LayerError> {
    match protocol {
        ip_proto::TCP => {
            let tcp = parse_tcp_header(l4_bytes)?;
            let header_len = usize::from(tcp.data_offset) * 4;
            let tcp_options = tcp
                .options
                .as_deref()
                .map(parse_tcp_options)
                .unwrap_or_default();
            let payload = &l4_bytes[header_len..];
            let tls = (payload.len() >= 5 && payload[0] == 22)
                .then(|| parse_tls_client_hello(payload).ok())
                .flatten();
            let mut parsed = TransportParse::with_tcp(tcp, tcp_options);
            parsed.tls = tls;
            if parsed.tls.is_none() {
                parsed.http = parse_http(payload).ok();
            }
            Ok(parsed)
        }
        ip_proto::UDP => parse_udp_transport(l4_bytes),
        ip_proto::ICMP => {
            let icmp = parse_icmp_minimal(l4_bytes)?;
            Ok(TransportParse::with_icmp(icmp))
        }
        ip_proto::ICMPV6 => {
            let icmpv6 = parse_icmpv6_minimal(l4_bytes)?;
            Ok(TransportParse::with_icmpv6(icmpv6))
        }
        ip_proto::IGMP => {
            let igmp = parse_igmp_minimal(l4_bytes)?;
            Ok(TransportParse::with_igmp(igmp))
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

fn parse_udp_transport(l4_bytes: &[u8]) -> Result<TransportParse, LayerError> {
    let udp = parse_udp_header(l4_bytes)?;
    let udp_end = (udp.length as usize).min(l4_bytes.len());
    let app = &l4_bytes[UDP_HEADER_LEN..udp_end];
    let mut hints = Vec::new();
    let mut dns = None;
    let mut dhcp = None;
    let mut ntp = None;

    maybe_probe_dns_udp(&udp, app, &mut hints, &mut dns);
    maybe_probe_mdns_udp(&udp, app, &mut hints, &mut dns);
    maybe_probe_dhcp_udp(&udp, app, &mut hints, &mut dhcp);
    maybe_probe_ntp_udp(&udp, app, &mut hints, &mut ntp);
    let wireguard = maybe_classify_wireguard_udp(&udp, app, &mut hints);

    let vxlan = maybe_parse_vxlan(&udp, app);
    let geneve = maybe_parse_geneve(&udp, app);
    let quic = (wireguard.is_none()
        && vxlan.is_none()
        && geneve.is_none()
        && app.len() >= 7
        && app[0] & 0x80 != 0)
        .then(|| parse_quic_long_header(app).ok())
        .flatten();

    Ok(TransportParse {
        transport: Some(TransportSegment::Udp(udp)),
        vxlan,
        geneve,
        wireguard,
        dns,
        dhcp,
        ntp,
        quic,
        hints,
        ..TransportParse::default()
    })
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

fn parse_icmpv6_minimal(data: &[u8]) -> Result<Icmpv6Header, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    Ok(Icmpv6Header {
        icmp_type: data[0],
        icmp_code: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
        rest_of_header: [data[4], data[5], data[6], data[7]],
    })
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

fn parse_tcp_header(l4_bytes: &[u8]) -> Result<TcpHeader, LayerError> {
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
    let options = if header_length > 20 {
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
    use crate::engine::builtin::{
        BuiltinPacketParser, ParseConfig, ParseWarningCode, TransportSegment, UdpAppHint,
        WireGuardMessageType,
    };
    use crate::layer::application::http::HttpMessage;

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
    fn parses_sctp_common_header_and_init_chunk() {
        let sctp = [
            0x13, 0x88, 0x13, 0x89, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0x01,
            0x00, 0x00, 0x04,
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
        assert!(parsed.inner.as_ref().is_some_and(|inner| inner.ipv4.is_some()));
        assert!(!parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::GreInner)));
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
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::GreInner)));
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
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::VxlanInner)));
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
    fn ipv4_in_ipv4_decodes_inner_packet() {
        let inner_frame = build_ethernet_ipv4_l4_frame(1, &[8, 0, 0, 0, 0, 1, 0, 1]);
        let frame = build_ethernet_ipv4_l4_frame(4, &inner_frame[14..]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(parsed.inner.as_ref().is_some_and(|inner| inner.ipv4.is_some()));
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
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::TunnelDepthLimit)));
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
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::GeneveInner)));
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
    fn ah_minimal_parsed_with_warning() {
        let ah = [58, 1, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x09];
        let frame = build_ethernet_ipv4_l4_frame(51, &ah);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ah.is_some());
        assert_eq!(parsed.ah.as_ref().unwrap().next_header, 58);
        assert_eq!(parsed.ah.as_ref().unwrap().spi, 0x1122_3344);
        assert_eq!(parsed.ah.as_ref().unwrap().sequence, 9);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::AhInner)));
    }

    #[test]
    fn esp_minimal_parsed_with_warning() {
        let esp = [0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x02];
        let frame = build_ethernet_ipv4_l4_frame(50, &esp);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.esp.is_some());
        assert_eq!(parsed.esp.as_ref().unwrap().spi, 0xaabb_ccdd);
        assert_eq!(parsed.esp.as_ref().unwrap().sequence, 2);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::EspInner)));
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
