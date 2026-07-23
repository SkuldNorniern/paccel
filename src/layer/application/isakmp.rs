use crate::layer::LayerError;

const HEADER_LEN: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsakmpHeader {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub next_payload: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub exchange_type: u8,
    pub is_initiator: bool,
    pub is_response: bool,
    pub message_id: u32,
    pub length: u32,
}

pub fn parse_isakmp_header(payload: &[u8]) -> Result<IsakmpHeader, LayerError> {
    let Some(header) = payload.get(..HEADER_LEN) else {
        return Err(LayerError::InvalidLength);
    };
    let version = header[17];
    let major_version = version >> 4;
    if !matches!(major_version, 1 | 2) {
        return Err(LayerError::InvalidHeader);
    }
    let flags = header[19];

    Ok(IsakmpHeader {
        initiator_spi: u64::from_be_bytes([
            header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7],
        ]),
        responder_spi: u64::from_be_bytes([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15],
        ]),
        next_payload: header[16],
        major_version,
        minor_version: version & 0x0f,
        exchange_type: header[18],
        is_initiator: flags & 0x08 != 0,
        is_response: flags & 0x20 != 0,
        message_id: u32::from_be_bytes([header[20], header[21], header[22], header[23]]),
        length: u32::from_be_bytes([header[24], header[25], header[26], header[27]]),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_isakmp_header;
    use crate::layer::LayerError;

    const IKE_SA_INIT: [u8; 28] = [
        0x5d, 0x48, 0xbf, 0xee, 0xb7, 0xd5, 0x74, 0xda, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8,
    ];

    #[test]
    fn parses_ikev2_sa_init_header() {
        let header = parse_isakmp_header(&IKE_SA_INIT).expect("IKEv2 header should parse");

        assert_eq!(header.initiator_spi, 0x5d48_bfee_b7d5_74da);
        assert_eq!(header.responder_spi, 0);
        assert_eq!(header.next_payload, 0x21);
        assert_eq!(header.major_version, 2);
        assert_eq!(header.minor_version, 0);
        assert_eq!(header.exchange_type, 0x22);
        assert_eq!(header.length, 232);
    }

    #[test]
    fn parses_ikev2_sa_init_flags_and_message_id() {
        let header = parse_isakmp_header(&IKE_SA_INIT).expect("IKEv2 header should parse");

        assert!(header.is_initiator);
        assert!(!header.is_response);
        assert_eq!(header.message_id, 0);
    }

    #[test]
    fn rejects_invalid_major_version_and_short_header() {
        let mut invalid = IKE_SA_INIT;
        invalid[17] = 0x30;
        assert!(matches!(
            parse_isakmp_header(&invalid),
            Err(LayerError::InvalidHeader)
        ));
        assert!(matches!(
            parse_isakmp_header(&IKE_SA_INIT[..27]),
            Err(LayerError::InvalidLength)
        ));
    }
}
