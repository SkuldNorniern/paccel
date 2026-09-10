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
    // RFC 2784 sec 2.3.1: the version must be zero.
    let version = data[1] & 0x07;
    let checksum_present = data[0] & 0x80 != 0;
    let routing_present = data[0] & 0x40 != 0;
    let key_present = data[0] & 0x20 != 0;
    let sequence_present = data[0] & 0x10 != 0;
    // RFC 1701 sec 4.1: the checksum and offset fields are both present if
    // either bit is set, not only the checksum one.
    let has_checksum_and_offset = checksum_present || routing_present;
    let header_len = 4
        + usize::from(has_checksum_and_offset) * 4
        + usize::from(key_present) * 4
        + usize::from(sequence_present) * 4;
    if data.len() < header_len {
        return Err(LayerError::InvalidLength);
    }
    let protocol_type = u16::from_be_bytes([data[2], data[3]]);
    let mut offset = 4;
    if has_checksum_and_offset {
        offset += 4;
    }
    let key = (key_present && version == 0).then(|| {
        let value = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
        value
    });
    let sequence = (sequence_present && version == 0).then(|| {
        u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    });
    Ok(GreInfo {
        protocol_type,
        version,
        checksum_present,
        routing_present,
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
    // RFC 7348 sec 5: the I flag "MUST be set to 1 for a valid VXLAN Network ID
    // (VNI)"
    const VNI_VALID_FLAG: u8 = 0x08;

    if data.len() < 8 {
        return Err(LayerError::InvalidLength);
    }
    if data[0] & VNI_VALID_FLAG == 0 {
        return Err(LayerError::InvalidHeader);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2637 sec 4.1: PPTP's enhanced GRE is version 1, and what sits where
    /// a version-0 key would be is a payload length and a call ID.
    #[test]
    fn a_pptp_gre_header_reports_no_version_zero_key() {
        // K and S set, version 1, protocol PPP, payload length 40, call 0x1234.
        let header = [
            0x30, 0x01, 0x88, 0x0b, 0x00, 0x28, 0x12, 0x34, 0x00, 0x00, 0x00, 0x01,
        ];

        let gre = parse_gre_minimal(&header).expect("the header parses");

        assert_eq!(gre.version, 1);
        assert!(gre.key_present, "the flag is still reported as it was set");
        assert_eq!(gre.key, None, "but there is no version-0 key to report");
        assert_eq!(gre.sequence, None);
    }

    /// A version-0 header still reports its key.
    #[test]
    fn a_version_zero_gre_header_reports_its_key() {
        let header = [0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x2a];

        let gre = parse_gre_minimal(&header).expect("the header parses");

        assert_eq!(gre.version, 0);
        assert_eq!(gre.key, Some(42));
    }

    /// RFC 7348 sec 5: "the I flag MUST be set to 1 for a valid VXLAN Network
    /// ID (VNI)"
    #[test]
    fn a_vxlan_header_without_the_i_flag_has_no_vni() {
        let without = [0x00, 0, 0, 0, 0x00, 0x00, 0x2a, 0];

        assert!(parse_vxlan_minimal(&without).is_err());
    }

    /// And the other seven flag bits are reserved and ignored on receipt, so a
    /// header that sets them is still read.
    #[test]
    fn a_vxlan_header_ignores_the_reserved_flag_bits() {
        let noisy = [0xff, 0, 0, 0, 0x00, 0x00, 0x2a, 0];

        assert_eq!(
            parse_vxlan_minimal(&noisy).expect("the I flag is set").vni,
            42
        );
    }
}
