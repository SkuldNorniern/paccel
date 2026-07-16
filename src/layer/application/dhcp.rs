use std::net::Ipv4Addr;

use crate::layer::LayerError;

const DHCP_FIXED_MESSAGE_LEN: usize = 240;
const DHCP_MAGIC_COOKIE_OFFSET: usize = 236;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub message_type: Option<u8>,
    pub options: Vec<DhcpOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpOption {
    pub code: u8,
    pub data: Vec<u8>,
}

pub fn parse_dhcp_message(payload: &[u8]) -> Result<DhcpMessage, LayerError> {
    if payload.len() < DHCP_FIXED_MESSAGE_LEN {
        return Err(LayerError::InvalidLength);
    }
    if payload[DHCP_MAGIC_COOKIE_OFFSET..DHCP_FIXED_MESSAGE_LEN] != DHCP_MAGIC_COOKIE {
        return Err(LayerError::InvalidHeader);
    }

    let mut chaddr = [0; 16];
    chaddr.copy_from_slice(&payload[28..44]);

    let mut message_type = None;
    let mut options = Vec::new();
    let mut offset = DHCP_FIXED_MESSAGE_LEN;
    while offset < payload.len() {
        let code = payload[offset];
        offset += 1;

        match code {
            0 => continue,
            255 => break,
            _ => {}
        }

        let Some(&length) = payload.get(offset) else {
            break;
        };
        offset += 1;
        let option_end = offset + length as usize;
        let Some(data) = payload.get(offset..option_end) else {
            break;
        };

        if code == 53 && message_type.is_none() {
            message_type = data.first().copied();
        }
        options.push(DhcpOption {
            code,
            data: data.to_vec(),
        });
        offset = option_end;
    }

    Ok(DhcpMessage {
        op: payload[0],
        htype: payload[1],
        hlen: payload[2],
        hops: payload[3],
        xid: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        secs: u16::from_be_bytes([payload[8], payload[9]]),
        flags: u16::from_be_bytes([payload[10], payload[11]]),
        ciaddr: Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]),
        yiaddr: Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]),
        siaddr: Ipv4Addr::new(payload[20], payload[21], payload[22], payload[23]),
        giaddr: Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]),
        chaddr,
        message_type,
        options,
    })
}
