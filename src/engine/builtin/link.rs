use std::net::Ipv4Addr;

use crate::engine::constants::ethertype;
use crate::engine::cursor::Cursor;
use crate::layer::LayerError;
use crate::layer::datalink::arp::{ArpOperation, ArpPacket};

use super::types::{EthernetFrame, MplsInfo, MplsLabel, PppoeInfo};

const MAC_ADDR_LEN: usize = 6;
const ETH_HEADER_LEN: usize = 14;
const ETHERTYPE_OFFSET: usize = 12;
const IEEE_8023_MAX_LENGTH: u16 = 1500;
const STP_DESTINATION: [u8; MAC_ADDR_LEN] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
const STP_LLC_HEADER: [u8; 3] = [0x42, 0x42, 0x03];
const CDP_DESTINATION: [u8; MAC_ADDR_LEN] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
const CDP_LLC_SNAP_HEADER: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];

const SLL_HEADER_LEN: usize = 16;
const SLL2_HEADER_LEN: usize = 20;
const SLL_PACKET_TYPE_OFFSET: usize = 0;
const SLL_ADDR_LEN_OFFSET: usize = 4;
const SLL_PROTOCOL_OFFSET: usize = 14;
const SLL2_PROTOCOL_OFFSET: usize = 0;

const VLAN_TAG_LEN: usize = 4;

const ARP_MIN_LEN: usize = 28;
const ARP_HEADER_LEN: usize = 8;
const ARP_ETH_HW_LEN: u8 = 6;
const ARP_IPV4_PROTO_LEN: u8 = 4;
const ARP_SENDER_HW_OFFSET: usize = 8;
const ARP_SENDER_PROTO_OFFSET: usize = 14;
const ARP_TARGET_HW_OFFSET: usize = 18;
const ARP_TARGET_PROTO_OFFSET: usize = 24;

const PPPOE_HEADER_LEN: usize = 6;
const PPPOE_CODE_OFFSET: usize = 1;
const PPPOE_SESSION_ID_OFFSET: usize = 2;
const PPPOE_LENGTH_OFFSET: usize = 4;

const MPLS_LABEL_LEN: usize = 4;

fn read_u16_be_at(raw: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *raw.get(offset)?,
        *raw.get(offset + 1)?,
    ]))
}

fn read_u32_be_at(raw: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *raw.get(offset)?,
        *raw.get(offset + 1)?,
        *raw.get(offset + 2)?,
        *raw.get(offset + 3)?,
    ]))
}

fn read_mac_at(raw: &[u8], offset: usize) -> Option<[u8; MAC_ADDR_LEN]> {
    let mut out = [0u8; MAC_ADDR_LEN];
    out.copy_from_slice(raw.get(offset..offset + MAC_ADDR_LEN)?);
    Some(out)
}

fn read_ipv4_at(raw: &[u8], offset: usize) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::new(
        *raw.get(offset)?,
        *raw.get(offset + 1)?,
        *raw.get(offset + 2)?,
        *raw.get(offset + 3)?,
    ))
}

fn ethertype_at_offset_12(raw: &[u8]) -> Option<u16> {
    read_u16_be_at(raw, ETHERTYPE_OFFSET)
}

fn is_common_ethertype(value: u16) -> bool {
    matches!(
        value,
        ethertype::IPV4
            | ethertype::ARP
            | ethertype::IPV6
            | ethertype::VLAN_8021Q
            | ethertype::QINQ_8021AD
            | ethertype::MPLS_UNICAST
            | ethertype::MPLS_MULTICAST
    )
}

/// The SLL address field pads a six-byte MAC to eight, so its last two bytes
/// sit where ethernet keeps its ethertype. Captures exist whose padding reads
/// 0x0800, so the protocol at offset 14 has to be checked too.
fn looks_like_sll(raw: &[u8]) -> bool {
    raw.len() >= SLL_HEADER_LEN
        && matches!(read_u16_be_at(raw, SLL_PACKET_TYPE_OFFSET), Some(packet_type) if packet_type <= 4)
        && read_u16_be_at(raw, SLL_ADDR_LEN_OFFSET) == Some(u16::from(ARP_ETH_HW_LEN))
        && matches!(read_u16_be_at(raw, SLL_PROTOCOL_OFFSET), Some(protocol) if is_common_ethertype(protocol))
}

fn looks_like_sll2(raw: &[u8]) -> bool {
    raw.len() >= SLL2_HEADER_LEN
        && matches!(
            read_u16_be_at(raw, SLL2_PROTOCOL_OFFSET),
            Some(ethertype::IPV4) | Some(ethertype::ARP) | Some(ethertype::IPV6)
        )
}

fn synthetic_link_frame(protocol: u16, payload_offset: usize) -> (EthernetFrame, usize) {
    (
        EthernetFrame {
            destination: [0u8; MAC_ADDR_LEN],
            source: [0u8; MAC_ADDR_LEN],
            ethertype: protocol,
            vlan_tags: Vec::new(),
            payload_offset,
        },
        payload_offset,
    )
}

fn parse_sll(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    let protocol = read_u16_be_at(raw, SLL_PROTOCOL_OFFSET).ok_or(LayerError::InvalidLength)?;
    Ok(synthetic_link_frame(protocol, SLL_HEADER_LEN))
}

fn parse_sll2(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    let protocol = read_u16_be_at(raw, SLL2_PROTOCOL_OFFSET).ok_or(LayerError::InvalidLength)?;
    Ok(synthetic_link_frame(protocol, SLL2_HEADER_LEN))
}

fn is_vlan_ethertype(value: u16) -> bool {
    matches!(value, ethertype::VLAN_8021Q | ethertype::QINQ_8021AD)
}

pub(super) fn parse_link(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    // Cooked first: it checks four fields, the ethertype guess below checks
    // one, and they read the same two bytes.
    if looks_like_sll(raw) {
        return parse_sll(raw);
    }

    if looks_like_sll2(raw) {
        return parse_sll2(raw);
    }

    if let Some(et) = ethertype_at_offset_12(raw)
        && is_common_ethertype(et)
    {
        return parse_ethernet(raw);
    }

    // Nothing recognised a link header, so there may be none. A LINKTYPE_RAW
    // capture reaching here without its linktype fails every packet otherwise.
    if let Some(protocol) = looks_like_bare_ip(raw) {
        return Ok(synthetic_link_frame(protocol, 0));
    }

    parse_ethernet(raw)
}

/// Whether `raw` begins with an IP header and nothing before it.
///
/// The declared length must account for the frame exactly, because a wrong
/// guess mis-parses silently. Pass the linktype and never reach here.
pub(super) fn looks_like_bare_ip(raw: &[u8]) -> Option<u16> {
    const IPV4_MIN_HEADER_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;

    match raw.first()? >> 4 {
        4 => {
            let header = raw.get(..IPV4_MIN_HEADER_LEN)?;
            let header_len = usize::from(header[0] & 0x0f) * 4;
            if header_len < IPV4_MIN_HEADER_LEN || header_len > raw.len() {
                return None;
            }
            let total_length = usize::from(u16::from_be_bytes([header[2], header[3]]));
            (total_length == raw.len() && total_length >= header_len).then_some(ethertype::IPV4)
        }
        6 => {
            let header = raw.get(..IPV6_HEADER_LEN)?;
            let payload_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
            (payload_length.checked_add(IPV6_HEADER_LEN)? == raw.len()).then_some(ethertype::IPV6)
        }
        _ => None,
    }
}

pub(super) fn parse_link_with_linktype(
    raw: &[u8],
    linktype: Option<u16>,
) -> Result<(EthernetFrame, usize), LayerError> {
    match linktype {
        Some(1) => parse_ethernet(raw),
        Some(113) => parse_sll(raw),
        Some(276) => parse_sll2(raw),
        Some(0 | 108) => {
            let family = raw.get(..4).ok_or(LayerError::InvalidLength)?;
            let protocol = match (family[0], family[3]) {
                (2, _) | (_, 2) => ethertype::IPV4,
                (24 | 28 | 30, _) | (_, 24 | 28 | 30) => ethertype::IPV6,
                _ => return Err(LayerError::InvalidHeader),
            };
            Ok(synthetic_link_frame(protocol, 4))
        }
        // 101 = LINKTYPE_RAW, the current cross-platform number. BSD-derived
        // tools may emit the older DLT_RAW value 12 for the same wire format.
        // 228/229 = LINKTYPE_IPV4/LINKTYPE_IPV6, fixed-family variants.
        Some(101 | 12 | 228 | 229) => {
            let protocol = match raw.first().map(|byte| byte >> 4) {
                Some(4) => ethertype::IPV4,
                Some(6) => ethertype::IPV6,
                Some(_) => return Err(LayerError::InvalidHeader),
                None => return Err(LayerError::InvalidLength),
            };
            Ok(synthetic_link_frame(protocol, 0))
        }
        Some(_) | None => parse_link(raw),
    }
}

pub(super) fn parse_ethernet(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    if raw.len() < ETH_HEADER_LEN {
        return Err(LayerError::InvalidLength);
    }

    let mut cursor = Cursor::new(raw);
    let destination = read_mac_at(raw, 0).ok_or(LayerError::InvalidLength)?;
    let source = read_mac_at(raw, MAC_ADDR_LEN).ok_or(LayerError::InvalidLength)?;
    cursor
        .read_exact(MAC_ADDR_LEN * 2)
        .ok_or(LayerError::InvalidLength)?;

    let mut ethertype = cursor.read_u16_be().ok_or(LayerError::InvalidLength)?;
    let mut vlan_tags = Vec::new();

    if ethertype <= IEEE_8023_MAX_LENGTH {
        let offset = if destination == STP_DESTINATION
            && raw.get(ETH_HEADER_LEN..ETH_HEADER_LEN + STP_LLC_HEADER.len())
                == Some(STP_LLC_HEADER.as_slice())
        {
            ETH_HEADER_LEN + STP_LLC_HEADER.len()
        } else if destination == CDP_DESTINATION
            && raw.get(ETH_HEADER_LEN..ETH_HEADER_LEN + CDP_LLC_SNAP_HEADER.len())
                == Some(CDP_LLC_SNAP_HEADER.as_slice())
        {
            ETH_HEADER_LEN + CDP_LLC_SNAP_HEADER.len()
        } else {
            ETH_HEADER_LEN
        };
        return Ok((
            EthernetFrame {
                destination,
                source,
                ethertype: 0,
                vlan_tags,
                payload_offset: offset,
            },
            offset,
        ));
    }

    while is_vlan_ethertype(ethertype) {
        if raw.len() < cursor.pos() + VLAN_TAG_LEN {
            return Err(LayerError::InvalidLength);
        }
        let tci = cursor.read_u16_be().ok_or(LayerError::InvalidLength)?;
        vlan_tags.push(tci);
        ethertype = cursor.read_u16_be().ok_or(LayerError::InvalidLength)?;
    }

    let offset = cursor.pos();

    Ok((
        EthernetFrame {
            destination,
            source,
            ethertype,
            vlan_tags,
            payload_offset: offset,
        },
        offset,
    ))
}

pub(super) fn parse_arp_packet(data: &[u8]) -> Result<ArpPacket, LayerError> {
    if data.len() < ARP_MIN_LEN {
        return Err(LayerError::InvalidLength);
    }

    let hardware_type = read_u16_be_at(data, 0).ok_or(LayerError::InvalidLength)?;
    let protocol_type = read_u16_be_at(data, 2).ok_or(LayerError::InvalidLength)?;
    let hardware_len = data[4];
    let protocol_len = data[5];

    if hardware_len != ARP_ETH_HW_LEN || protocol_len != ARP_IPV4_PROTO_LEN {
        return Err(LayerError::InvalidHeader);
    }

    let expected_len = ARP_HEADER_LEN
        + (hardware_len as usize)
        + (protocol_len as usize)
        + (hardware_len as usize)
        + (protocol_len as usize);
    if data.len() < expected_len {
        return Err(LayerError::InvalidLength);
    }

    let operation_code = read_u16_be_at(data, 6).ok_or(LayerError::InvalidLength)?;
    let operation = match operation_code {
        1 => ArpOperation::Request,
        2 => ArpOperation::Reply,
        other => ArpOperation::Unknown(other),
    };

    let sender_hardware_addr =
        read_mac_at(data, ARP_SENDER_HW_OFFSET).ok_or(LayerError::InvalidLength)?;
    let sender_protocol_addr =
        read_ipv4_at(data, ARP_SENDER_PROTO_OFFSET).ok_or(LayerError::InvalidLength)?;

    let target_hardware_addr =
        read_mac_at(data, ARP_TARGET_HW_OFFSET).ok_or(LayerError::InvalidLength)?;
    let target_protocol_addr =
        read_ipv4_at(data, ARP_TARGET_PROTO_OFFSET).ok_or(LayerError::InvalidLength)?;

    Ok(ArpPacket {
        hardware_type,
        protocol_type,
        hardware_len,
        protocol_len,
        operation,
        sender_hardware_addr,
        sender_protocol_addr,
        target_hardware_addr,
        target_protocol_addr,
    })
}

pub(super) fn parse_pppoe_minimal(data: &[u8]) -> Result<PppoeInfo, LayerError> {
    if data.len() < PPPOE_HEADER_LEN {
        return Err(LayerError::InvalidLength);
    }

    let session_id =
        read_u16_be_at(data, PPPOE_SESSION_ID_OFFSET).ok_or(LayerError::InvalidLength)?;
    let length = read_u16_be_at(data, PPPOE_LENGTH_OFFSET).ok_or(LayerError::InvalidLength)?;

    Ok(PppoeInfo {
        code: data[PPPOE_CODE_OFFSET],
        session_id,
        length,
    })
}

pub(super) fn parse_mpls_stack(
    data: &[u8],
    max_labels: usize,
) -> Result<(MplsInfo, usize, bool), LayerError> {
    if data.len() < MPLS_LABEL_LEN {
        return Err(LayerError::InvalidLength);
    }

    let mut labels = Vec::new();
    let mut offset = 0usize;
    let mut depth_limit_hit = false;
    let max_labels = max_labels.max(1);

    while offset + MPLS_LABEL_LEN <= data.len() {
        if labels.len() >= max_labels {
            depth_limit_hit = true;
            break;
        }

        let entry = read_u32_be_at(data, offset).ok_or(LayerError::InvalidLength)?;
        let label = parse_mpls_label_entry(entry);
        let bottom_of_stack = label.bottom_of_stack;
        labels.push(label);
        offset += MPLS_LABEL_LEN;

        if bottom_of_stack {
            break;
        }
    }

    if labels.is_empty() {
        return Err(LayerError::InvalidLength);
    }

    Ok((MplsInfo { labels }, offset, depth_limit_hit))
}

fn parse_mpls_label_entry(entry: u32) -> MplsLabel {
    MplsLabel {
        label: (entry >> 12) & 0x000f_ffff,
        exp: ((entry >> 9) & 0x7) as u8,
        bottom_of_stack: ((entry >> 8) & 0x1) != 0,
        ttl: (entry & 0xff) as u8,
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use crate::engine::builtin::{BuiltinPacketParser, ParseWarningCode, TransportSegment};

    /// An IPv4/UDP datagram with no link header at all, as a LINKTYPE_RAW
    /// capture carries it.
    fn bare_ipv4_udp() -> Vec<u8> {
        vec![
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
            0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ]
    }

    /// A Linux cooked frame whose eight-byte address field holds a six-byte
    /// MAC and two bytes of padding that read as 0x0800 - the same position an
    /// ethernet frame carries its ethertype. Real captures contain these.
    fn sll_ipv4_udp_with_ethertype_shaped_padding() -> Vec<u8> {
        let mut frame = vec![0x00, 0x00];
        frame.extend([0x03, 0x04]);
        frame.extend([0x00, 0x06]);
        frame.extend([0x00, 0x0c, 0x29, 0xfe, 0x8c, 0x99]);
        frame.extend([0x08, 0x00]);
        frame.extend([0x08, 0x00]);
        frame.extend(&bare_ipv4_udp());
        frame
    }

    /// A caller with the packet bytes but not the capture's file header gets
    /// no linktype. Assuming ethernet then fails every packet of a raw
    /// capture, so a frame that is exactly an IP packet is read as one.
    #[test]
    fn a_bare_ip_packet_parses_without_a_linktype() {
        let parsed = BuiltinPacketParser::parse(&bare_ipv4_udp())
            .expect("a raw ip packet is not a short ethernet frame");

        let ipv4 = parsed.ipv4.expect("the addresses");
        assert_eq!(ipv4.source.to_string(), "10.0.0.1");
        let Some(TransportSegment::Udp(udp)) = &parsed.transport else {
            panic!("expected udp, got {:?}", parsed.transport);
        };
        assert_eq!((udp.source_port, udp.destination_port), (1234, 53));
    }

    /// The detection is a last resort and must stay strict: a frame whose
    /// declared length does not account for it exactly is not read as bare IP,
    /// because a mis-parse is worse than a refusal.
    #[test]
    fn a_length_that_does_not_match_is_not_taken_for_bare_ip() {
        let mut padded = bare_ipv4_udp();
        padded.extend([0u8; 8]);
        assert!(
            super::looks_like_bare_ip(&padded).is_none(),
            "a total_length that does not account for the frame was accepted"
        );

        let mut short = bare_ipv4_udp();
        short[3] = 0xff;
        assert!(super::looks_like_bare_ip(&short).is_none());
    }

    /// Reading bytes 12 and 13 as an ethertype is one weak signal; a cooked
    /// frame satisfies four. The specific check has to win, or these frames
    /// are silently parsed as ethernet.
    #[test]
    fn cooked_padding_shaped_like_an_ethertype_is_still_cooked() {
        let parsed = BuiltinPacketParser::parse(&sll_ipv4_udp_with_ethertype_shaped_padding())
            .expect("a cooked frame parses");

        let ipv4 = parsed.ipv4.expect("the addresses survived the link layer");
        assert_eq!(
            ipv4.source.to_string(),
            "10.0.0.1",
            "reading the frame as ethernet would put the ip header 14 bytes in"
        );
        let Some(TransportSegment::Udp(udp)) = &parsed.transport else {
            panic!("expected udp, got {:?}", parsed.transport);
        };
        assert_eq!((udp.source_port, udp.destination_port), (1234, 53));
    }

    /// The reorder must not cost ethernet: this frame's own MAC begins with
    /// bytes that satisfy the cooked packet-type and address-length checks, so
    /// only the protocol field keeps it ethernet.
    #[test]
    fn an_ethernet_frame_is_not_taken_for_a_cooked_one() {
        let parsed = BuiltinPacketParser::parse(&ethernet_ipv4_udp_frame()).expect("ethernet");

        let ethernet = parsed.ethernet.expect("an ethernet header");
        assert_eq!(ethernet.source, [6, 7, 8, 9, 10, 11]);
        assert_eq!(
            parsed.ipv4.expect("addresses").source.to_string(),
            "10.0.0.1"
        );
    }

    fn ethernet_ipv4_udp_frame() -> Vec<u8> {
        vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00,
            0x1c, 0x00, 0x01, 0x40, 0x00, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0x04, 0xd2, 0x00,
            0x35, 0x00, 0x08, 0x00, 0x00,
        ]
    }

    #[test]
    fn ethernet_preferred_over_sll_when_ethertype_at_12_13() {
        let frame = ethernet_ipv4_udp_frame();
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert_eq!(parsed.ethernet.as_ref().unwrap().ethertype, 0x0800);
        assert_eq!(
            parsed.ethernet.as_ref().unwrap().source,
            [6, 7, 8, 9, 10, 11]
        );
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn parses_null_ipv4_udp() {
        let mut frame = vec![2, 0, 0, 0];
        frame.extend_from_slice(&ethernet_ipv4_udp_frame()[14..]);

        let parsed =
            BuiltinPacketParser::parse_with_linktype(&frame, 0).expect("NULL frame should parse");
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn parses_raw_ipv4_udp() {
        let frame = ethernet_ipv4_udp_frame();
        let parsed = BuiltinPacketParser::parse_with_linktype(&frame[14..], 101)
            .expect("RAW frame should parse");

        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn parses_legacy_dlt_raw_ipv4_udp() {
        // BSD-derived tools may emit DLT_RAW = 12 instead of LINKTYPE_RAW = 101.
        let frame = ethernet_ipv4_udp_frame();
        let parsed = BuiltinPacketParser::parse_with_linktype(&frame[14..], 12)
            .expect("legacy DLT_RAW frame should parse");

        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn linktype_ethernet_parses_ethernet() {
        let frame = ethernet_ipv4_udp_frame();
        let parsed = BuiltinPacketParser::parse_with_linktype(&frame, 1)
            .expect("Ethernet frame should parse");

        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn unknown_linktype_falls_back_to_sniffing() {
        let frame = ethernet_ipv4_udp_frame();
        let parsed = BuiltinPacketParser::parse_with_linktype(&frame, 999)
            .expect("Ethernet frame should parse via sniffing");

        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn parses_sll_ipv4_udp() {
        let mut frame = vec![
            0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00,
        ];
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x40, 0x00, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        frame.extend_from_slice(&[0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert_eq!(parsed.ethernet.as_ref().unwrap().ethertype, 0x0800);
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn unknown_ethertype_returns_partial_parse_with_warning() {
        let frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x12, 0x34, 0x00, 0x00];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert_eq!(parsed.ethernet.as_ref().unwrap().ethertype, 0x1234);
        assert!(parsed.ipv4.is_none());
        assert!(parsed.ipv6.is_none());
        assert_eq!(parsed.warnings.len(), 1);
        assert!(matches!(
            parsed.warnings[0].code,
            ParseWarningCode::UnsupportedEthertype(0x1234)
        ));
    }

    #[test]
    fn parses_pppoe_discovery() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x63, 0x11, 0x09, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert!(parsed.pppoe.is_some());
        assert_eq!(parsed.pppoe.as_ref().unwrap().code, 0x09);
        assert_eq!(parsed.pppoe.as_ref().unwrap().session_id, 0);
        assert_eq!(parsed.pppoe.as_ref().unwrap().length, 4);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::PppoeNoPayload))
        );
    }

    #[test]
    fn pppoe_minimal_parsed_with_warning() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x64, 0x11, 0x01, 0x00, 0x01, 0x00, 0x0c,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.pppoe.is_some());
        assert_eq!(parsed.pppoe.as_ref().unwrap().code, 0x01);
        assert_eq!(parsed.pppoe.as_ref().unwrap().session_id, 1);
        assert_eq!(parsed.pppoe.as_ref().unwrap().length, 12);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::PppoeNoPayload))
        );
    }

    #[test]
    fn pppoe_session_decodes_two_byte_ppp_ipv4() {
        let mut frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x64, 0x11, 0x00, 0x00, 0x01, 0x00, 0x16,
            0x00, 0x21,
        ];
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 64, 0, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.pppoe.is_some());
        assert!(
            parsed
                .inner
                .as_ref()
                .is_some_and(|inner| inner.ipv4.is_some())
        );
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn pppoe_session_decodes_compressed_ppp_ipv6() {
        let mut frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x64, 0x11, 0x00, 0x00, 0x01, 0x00, 0x29,
            0x57,
        ];
        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        ipv6[6] = 59;
        ipv6[7] = 64;
        ipv6[23] = 1;
        ipv6[39] = 2;
        frame.extend_from_slice(&ipv6);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(
            parsed
                .inner
                .as_ref()
                .is_some_and(|inner| inner.ipv6.is_some())
        );
    }

    #[test]
    fn truncated_ppp_protocol_keeps_pppoe_in_permissive_mode() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x64, 0x11, 0x00, 0x00, 0x01, 0x00, 0x02,
            0x00,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("permissive parse should succeed");
        assert!(parsed.pppoe.is_some());
        assert!(parsed.inner.is_none());
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| matches!(warning.code, ParseWarningCode::PppoeNoPayload))
        );
    }

    #[test]
    fn parses_mpls_label_and_inner_ipv4() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x47, 0x00, 0x01, 0x01, 0x40, 0x45, 0x00,
            0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 64, 0, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.mpls.is_some());
        let mpls = parsed.mpls.as_ref().unwrap();
        assert_eq!(mpls.labels.len(), 1);
        assert_eq!(mpls.labels[0].label, 16);
        assert!(mpls.labels[0].bottom_of_stack);
        assert!(
            parsed
                .inner
                .as_ref()
                .is_some_and(|inner| inner.ipv4.is_some())
        );
    }

    #[test]
    fn parses_mpls_label_stack() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x47, 0x00, 0x01, 0x00, 0x40, 0x00, 0x02,
            0x01, 0x40, 0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let mpls = parsed.mpls.as_ref().unwrap();
        assert_eq!(mpls.labels.len(), 2);
        assert!(!mpls.labels[0].bottom_of_stack);
        assert!(mpls.labels[1].bottom_of_stack);
    }
}
