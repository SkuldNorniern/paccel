use crate::layer::LayerError;
use crate::layer::network::ipv4::Ipv4Header;
use crate::layer::network::ipv6::Ipv6Header;

#[derive(Debug, Clone, Copy)]
pub(super) struct Ipv6TransportState {
    pub next_header: u8,
    pub l4_offset: usize,
    pub non_initial_fragment: bool,
    pub depth_limit_hit: bool,
}

pub(super) fn parse_ipv4_header(data: &[u8]) -> Result<Ipv4Header, LayerError> {
    if data.len() < 20 {
        return Err(LayerError::InvalidLength);
    }

    let first = data[0];
    let version = first >> 4;
    let ihl = first & 0x0f;
    if version != 4 || ihl < 5 {
        return Err(LayerError::InvalidHeader);
    }

    let header_len = (ihl as usize) * 4;
    if data.len() < header_len {
        return Err(LayerError::InvalidLength);
    }

    let dscp = data[1] >> 2;
    let ecn = data[1] & 0x03;
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    if data.len() < total_length as usize {
        return Err(LayerError::InvalidLength);
    }

    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_fragment = u16::from_be_bytes([data[6], data[7]]);
    let flags = (flags_fragment >> 13) as u8;
    let fragment_offset = flags_fragment & 0x1fff;
    let ttl = data[8];
    let protocol = data[9];
    let checksum = u16::from_be_bytes([data[10], data[11]]);
    let source = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let destination = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let options = if ihl > 5 {
        Some(data[20..header_len].to_vec())
    } else {
        None
    };

    Ok(Ipv4Header {
        version,
        ihl,
        dscp,
        ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        source,
        destination,
        options,
    })
}

pub(super) fn parse_ipv6_header(data: &[u8]) -> Result<Ipv6Header, LayerError> {
    if data.len() < 40 {
        return Err(LayerError::InvalidLength);
    }

    let first_word = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let version = ((first_word >> 28) & 0x0f) as u8;
    if version != 6 {
        return Err(LayerError::InvalidHeader);
    }

    let traffic_class = ((first_word >> 20) & 0xff) as u8;
    let flow_label = first_word & 0x000f_ffff;
    let payload_length = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];

    let source = std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&data[8..24]).map_err(|_| LayerError::InvalidHeader)?,
    );
    let destination = std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&data[24..40]).map_err(|_| LayerError::InvalidHeader)?,
    );

    Ok(Ipv6Header {
        version,
        traffic_class,
        flow_label,
        payload_length,
        next_header,
        hop_limit,
        source,
        destination,
    })
}

pub(super) fn resolve_ipv6_transport(
    packet: &[u8],
    initial_next_header: u8,
    max_ext_headers: usize,
) -> Result<Ipv6TransportState, LayerError> {
    let mut state = Ipv6TransportState {
        next_header: initial_next_header,
        l4_offset: 40,
        non_initial_fragment: false,
        depth_limit_hit: false,
    };
    let mut depth = 0usize;

    loop {
        if depth >= max_ext_headers {
            state.depth_limit_hit = true;
            return Ok(state);
        }

        match state.next_header {
            0 | 43 | 60 => {
                if state.l4_offset + 2 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[state.l4_offset];
                let ext_len = packet[state.l4_offset + 1] as usize;
                let header_len = (ext_len + 1) * 8;
                if state.l4_offset + header_len > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                state.next_header = ext_next;
                state.l4_offset += header_len;
                depth += 1;
            }
            44 => {
                if state.l4_offset + 8 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[state.l4_offset];
                let frag_off_flags =
                    u16::from_be_bytes([packet[state.l4_offset + 2], packet[state.l4_offset + 3]]);
                let frag_offset = (frag_off_flags & 0xFFF8) >> 3;

                state.next_header = ext_next;
                state.l4_offset += 8;
                depth += 1;

                if frag_offset != 0 {
                    state.non_initial_fragment = true;
                    return Ok(state);
                }
            }
            51 => {
                if state.l4_offset + 2 > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                let ext_next = packet[state.l4_offset];
                let payload_len = packet[state.l4_offset + 1] as usize;
                let header_len = (payload_len + 2) * 4;
                if state.l4_offset + header_len > packet.len() {
                    return Err(LayerError::InvalidLength);
                }

                state.next_header = ext_next;
                state.l4_offset += header_len;
                depth += 1;
            }
            50 | 59 => return Ok(state),
            _ => return Ok(state),
        }
    }
}
