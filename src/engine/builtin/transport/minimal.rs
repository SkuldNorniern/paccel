use super::*;

pub(super) fn parse_icmp_minimal(data: &[u8]) -> Result<IcmpHeader, LayerError> {
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

pub(super) fn parse_icmpv6_minimal(
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

pub(super) fn parse_igmp_minimal(data: &[u8]) -> Result<IgmpInfo, LayerError> {
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

pub(super) fn parse_sctp_minimal(data: &[u8]) -> Result<SctpInfo, LayerError> {
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

pub(super) fn parse_gre_minimal(data: &[u8]) -> Result<GreInfo, LayerError> {
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

pub(super) fn parse_ah_minimal(data: &[u8]) -> Result<AhInfo, LayerError> {
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

pub(super) fn parse_esp_minimal(data: &[u8]) -> Result<EspInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    Ok(EspInfo {
        spi: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        sequence: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
    })
}

pub(super) fn parse_vxlan_minimal(data: &[u8]) -> Result<VxlanInfo, LayerError> {
    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    let vni = u32::from(data[4]) << 16 | u32::from(data[5]) << 8 | u32::from(data[6]);
    Ok(VxlanInfo { vni })
}

pub(super) fn parse_geneve_minimal(data: &[u8]) -> Result<GeneveInfo, LayerError> {
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

pub(super) fn parse_l2tp_minimal(data: &[u8]) -> L2tpInfo {
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
