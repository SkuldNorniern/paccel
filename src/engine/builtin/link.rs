use crate::engine::constants::ethertype;
use crate::engine::cursor::Cursor;
use crate::layer::datalink::arp::{ArpOperation, ArpPacket};
use crate::layer::LayerError;

use super::types::{EthernetFrame, MplsInfo, MplsLabel, PppoeInfo};

const MAC_ADDR_LEN: usize = 6;
const ETH_HEADER_LEN: usize = 14;
const ETHERTYPE_OFFSET: usize = 12;

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

fn read_ipv4_at(raw: &[u8], offset: usize) -> Option<std::net::Ipv4Addr> {
    Some(std::net::Ipv4Addr::new(
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

fn looks_like_sll(raw: &[u8]) -> bool {
    raw.len() >= SLL_HEADER_LEN
        && matches!(read_u16_be_at(raw, SLL_PACKET_TYPE_OFFSET), Some(packet_type) if packet_type <= 4)
        && read_u16_be_at(raw, SLL_ADDR_LEN_OFFSET) == Some(u16::from(ARP_ETH_HW_LEN))
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
    if let Some(et) = ethertype_at_offset_12(raw) {
        if is_common_ethertype(et) {
            return parse_ethernet(raw);
        }
    }

    if looks_like_sll(raw) {
        return parse_sll(raw);
    }

    if looks_like_sll2(raw) {
        return parse_sll2(raw);
    }

    parse_ethernet(raw)
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
mod tests {
    use crate::engine::builtin::{BuiltinPacketParser, ParseWarningCode, TransportSegment};

    #[test]
    fn ethernet_preferred_over_sll_when_ethertype_at_12_13() {
        let frame = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00,
            0x1c, 0x00, 0x01, 0x40, 0x00, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0x04, 0xd2, 0x00,
            0x35, 0x00, 0x08, 0x00, 0x00,
        ];
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
        let frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0xcc, 0x00, 0x00];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert_eq!(parsed.ethernet.as_ref().unwrap().ethertype, 0x88cc);
        assert!(parsed.ipv4.is_none());
        assert!(parsed.ipv6.is_none());
        assert_eq!(parsed.warnings.len(), 1);
        assert!(matches!(
            parsed.warnings[0].code,
            ParseWarningCode::UnsupportedEthertype(0x88cc)
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
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::PppoeNoPayload)));
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
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::PppoeNoPayload)));
    }

    #[test]
    fn parses_mpls_label_and_emits_inner_warning() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x88, 0x47, 0x00, 0x01, 0x01, 0x40, 0x45, 0x00,
            0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.mpls.is_some());
        let mpls = parsed.mpls.as_ref().unwrap();
        assert_eq!(mpls.labels.len(), 1);
        assert_eq!(mpls.labels[0].label, 16);
        assert!(mpls.labels[0].bottom_of_stack);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| matches!(w.code, ParseWarningCode::MplsInner)));
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
