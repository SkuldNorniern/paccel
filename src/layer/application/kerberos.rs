use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

const TCP_LENGTH_PREFIX_LEN: usize = 4;
const APPLICATION_TAG_CLASS_MASK: u8 = 0xe0;
const APPLICATION_TAG_CLASS: u8 = 0x60;
const APPLICATION_TAG_NUMBER_MASK: u8 = 0x1f;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KerberosMessageType {
    AsReq,
    AsRep,
    TgsReq,
    TgsRep,
    ApReq,
    ApRep,
    KrbSafe,
    KrbPriv,
    KrbCred,
    KrbError,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KerberosMessage {
    pub message_type: KerberosMessageType,
}

pub fn parse_kerberos_udp(payload: &[u8]) -> Result<KerberosMessage, LayerError> {
    let tag = *payload.first().ok_or(LayerError::InvalidLength)?;
    classify_tag(tag)
}

pub fn parse_kerberos_tcp(payload: &[u8]) -> Result<KerberosMessage, LayerError> {
    let tag = *payload
        .get(TCP_LENGTH_PREFIX_LEN)
        .ok_or(LayerError::InvalidLength)?;
    classify_tag(tag)
}

fn classify_tag(tag: u8) -> Result<KerberosMessage, LayerError> {
    if tag & APPLICATION_TAG_CLASS_MASK != APPLICATION_TAG_CLASS {
        return Err(LayerError::InvalidHeader);
    }

    let message_type = match tag & APPLICATION_TAG_NUMBER_MASK {
        10 => KerberosMessageType::AsReq,
        11 => KerberosMessageType::AsRep,
        12 => KerberosMessageType::TgsReq,
        13 => KerberosMessageType::TgsRep,
        14 => KerberosMessageType::ApReq,
        15 => KerberosMessageType::ApRep,
        20 => KerberosMessageType::KrbSafe,
        21 => KerberosMessageType::KrbPriv,
        22 => KerberosMessageType::KrbCred,
        30 => KerberosMessageType::KrbError,
        other => KerberosMessageType::Other(other),
    };

    Ok(KerberosMessage { message_type })
}

/// Probes a Kerberos message over UDP by its ASN.1 application tag.
///
/// RFC 4120 sec 5.4.1: every message is an ASN.1 APPLICATION-tagged type, so
/// the top three bits of the first byte are fixed.
#[must_use]
pub fn probe_kerberos_udp(payload: &[u8]) -> ProbeResult<KerberosMessage> {
    let Some(&tag) = payload.first() else {
        return ProbeResult::Incomplete {
            needed: Some(1),
            available: 0,
        };
    };
    if tag & APPLICATION_TAG_CLASS_MASK != APPLICATION_TAG_CLASS {
        return ProbeResult::NoMatch;
    }

    match parse_kerberos_udp(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("kerberos"),
            0,
        )),
    }
}

/// Probes a Kerberos message over TCP, past the four-byte length prefix.
///
/// RFC 4120 sec 7.2.2: TCP carries each message behind its length.
#[must_use]
pub fn probe_kerberos_tcp(payload: &[u8]) -> ProbeResult<KerberosMessage> {
    let Some(&tag) = payload.get(TCP_LENGTH_PREFIX_LEN) else {
        return ProbeResult::Incomplete {
            needed: Some(TCP_LENGTH_PREFIX_LEN + 1),
            available: payload.len(),
        };
    };
    if tag & APPLICATION_TAG_CLASS_MASK != APPLICATION_TAG_CLASS {
        return ProbeResult::NoMatch;
    }

    match parse_kerberos_tcp(payload) {
        Ok(message) => ProbeResult::Match(message),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("kerberos"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{KerberosMessageType, parse_kerberos_tcp, parse_kerberos_udp};
    use crate::layer::LayerError;

    #[test]
    fn parses_udp_as_req() {
        let payload = [0x6a, 0x81, 0xc3, 0x30, 0x81, 0xc0];
        let msg = parse_kerberos_udp(&payload).expect("AS-REQ should parse");
        assert_eq!(msg.message_type, KerberosMessageType::AsReq);
    }

    #[test]
    fn parses_udp_krb_error() {
        let payload = [0x7e, 0x81, 0x50];
        let msg = parse_kerberos_udp(&payload).expect("KRB-ERROR should parse");
        assert_eq!(msg.message_type, KerberosMessageType::KrbError);
    }

    #[test]
    fn parses_tcp_tgs_req_after_length_prefix() {
        let payload = [0x00, 0x00, 0x06, 0x06, 0x6c, 0x82, 0x06, 0x02];
        let msg = parse_kerberos_tcp(&payload).expect("TGS-REQ should parse");
        assert_eq!(msg.message_type, KerberosMessageType::TgsReq);
    }

    #[test]
    fn rejects_non_application_tag() {
        assert!(matches!(
            parse_kerberos_udp(&[0x30, 0x0a]),
            Err(LayerError::InvalidHeader)
        ));
    }

    #[test]
    fn rejects_empty_payload() {
        assert!(matches!(
            parse_kerberos_udp(&[]),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn rejects_tcp_payload_shorter_than_prefix() {
        assert!(matches!(
            parse_kerberos_tcp(&[0x00, 0x00, 0x06]),
            Err(LayerError::InvalidLength)
        ));
    }
}
