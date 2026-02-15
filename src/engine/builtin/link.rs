use crate::engine::cursor::Cursor;
use crate::layer::LayerError;
use crate::layer::datalink::arp::{ArpOperation, ArpPacket};

use super::types::EthernetFrame;

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
