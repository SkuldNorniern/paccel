use crate::engine::cursor::Cursor;
use crate::layer::datalink::arp::{ArpOperation, ArpPacket};
use crate::layer::LayerError;

use super::types::EthernetFrame;

const SLL_HEADER_LEN: usize = 16;
const SLL2_HEADER_LEN: usize = 20;

fn looks_like_sll(raw: &[u8]) -> bool {
    raw.len() >= SLL_HEADER_LEN
        && raw[0] == 0
        && raw[1] <= 4
        && raw[4] == 0
        && raw[5] == 6
}

fn looks_like_sll2(raw: &[u8]) -> bool {
    if raw.len() < SLL2_HEADER_LEN {
        return false;
    }
    let protocol = u16::from_be_bytes([raw[0], raw[1]]);
    matches!(protocol, 0x0800 | 0x0806 | 0x86DD)
}

pub(super) fn parse_link(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    if looks_like_sll(raw) {
        let protocol = u16::from_be_bytes([raw[14], raw[15]]);
        let frame = EthernetFrame {
            destination: [0u8; 6],
            source: [0u8; 6],
            ethertype: protocol,
            vlan_tags: Vec::new(),
            payload_offset: SLL_HEADER_LEN,
        };
        return Ok((frame, SLL_HEADER_LEN));
    }
    if looks_like_sll2(raw) {
        let protocol = u16::from_be_bytes([raw[0], raw[1]]);
        let frame = EthernetFrame {
            destination: [0u8; 6],
            source: [0u8; 6],
            ethertype: protocol,
            vlan_tags: Vec::new(),
            payload_offset: SLL2_HEADER_LEN,
        };
        return Ok((frame, SLL2_HEADER_LEN));
    }
    parse_ethernet(raw)
}

pub(super) fn parse_ethernet(raw: &[u8]) -> Result<(EthernetFrame, usize), LayerError> {
    if raw.len() < 14 {
        return Err(LayerError::InvalidLength);
    }

    let mut cursor = Cursor::new(raw);
    let destination_bytes = cursor.read_exact(6).ok_or(LayerError::InvalidLength)?;
    let source_bytes = cursor.read_exact(6).ok_or(LayerError::InvalidLength)?;

    let mut destination = [0u8; 6];
    destination.copy_from_slice(destination_bytes);

    let mut source = [0u8; 6];
    source.copy_from_slice(source_bytes);

    let mut ethertype = cursor.read_u16_be().ok_or(LayerError::InvalidLength)?;
    let mut vlan_tags = Vec::new();

    while ethertype == 0x8100 || ethertype == 0x88A8 {
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
    if data.len() < 28 {
        return Err(LayerError::InvalidLength);
    }

    let hardware_type = u16::from_be_bytes([data[0], data[1]]);
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);
    let hardware_len = data[4];
    let protocol_len = data[5];

    if hardware_len != 6 || protocol_len != 4 {
        return Err(LayerError::InvalidHeader);
    }

    let expected_len = 8
        + (hardware_len as usize)
        + (protocol_len as usize)
        + (hardware_len as usize)
        + (protocol_len as usize);
    if data.len() < expected_len {
        return Err(LayerError::InvalidLength);
    }

    let operation_code = u16::from_be_bytes([data[6], data[7]]);
    let operation = match operation_code {
        1 => ArpOperation::Request,
        2 => ArpOperation::Reply,
        other => ArpOperation::Unknown(other),
    };

    let mut sender_hardware_addr = [0u8; 6];
    sender_hardware_addr.copy_from_slice(&data[8..14]);
    let sender_protocol_addr = std::net::Ipv4Addr::new(data[14], data[15], data[16], data[17]);

    let mut target_hardware_addr = [0u8; 6];
    target_hardware_addr.copy_from_slice(&data[18..24]);
    let target_protocol_addr = std::net::Ipv4Addr::new(data[24], data[25], data[26], data[27]);

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
