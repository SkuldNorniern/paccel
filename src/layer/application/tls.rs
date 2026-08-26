use crate::layer::LayerError;

const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;
const SERVER_HELLO_HANDSHAKE_TYPE: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHello {
    pub record_version: u16,
    pub handshake_version: u16,
    pub client_random: [u8; 32],
    pub cipher_suites: Vec<u16>,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    /// Extension type IDs in wire order, unfiltered (including any GREASE
    /// values) - JA3/JA4-style fingerprinting needs the raw order/set, and
    /// decides its own GREASE-filtering policy on top of this.
    pub extension_types: Vec<u16>,
}

/// ServerHello (RFC 8446 sec 4.1.3). Unlike ClientHello, `cipher_suite` is a
/// single negotiated value, not a list, and ALPN carries at most one selected
/// protocol. Certificate/ServerKeyExchange are NOT covered here: TLS 1.3
/// encrypts everything after ServerHello, and even for TLS 1.2 the
/// Certificate message routinely spans multiple TCP segments in real
/// traffic, which a stateless per-packet parser can't reassemble.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerHello {
    pub record_version: u16,
    pub handshake_version: u16,
    pub cipher_suite: u16,
    pub alpn: Option<String>,
    pub supported_version: Option<u16>,
    pub extension_types: Vec<u16>,
}

pub fn parse_tls_client_hello(payload: &[u8]) -> Result<TlsClientHello, LayerError> {
    if payload.len() < 5 {
        return Err(LayerError::InvalidLength);
    }
    if payload[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return Err(LayerError::InvalidHeader);
    }

    let record_version = read_u16(payload, 1)?;
    let record_length = usize::from(read_u16(payload, 3)?);
    let record_end = 5usize
        .checked_add(record_length)
        .ok_or(LayerError::InvalidLength)?;
    if record_end > payload.len() {
        return Err(LayerError::InsufficientData);
    }
    let record = &payload[5..record_end];

    if record.len() < 4 {
        return Err(LayerError::InvalidLength);
    }
    if record[0] != CLIENT_HELLO_HANDSHAKE_TYPE {
        return Err(LayerError::InvalidHeader);
    }

    let handshake_length = read_u24(record, 1)?;
    let handshake_end = 4usize
        .checked_add(handshake_length)
        .ok_or(LayerError::InvalidLength)?;
    if handshake_end > record.len() {
        return Err(LayerError::InsufficientData);
    }
    let hello = &record[4..handshake_end];
    let mut offset = 0;

    let handshake_version = take_u16(hello, &mut offset)?;
    let client_random_bytes = take(hello, &mut offset, 32)?;
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(client_random_bytes);

    let session_id_length = usize::from(take_u8(hello, &mut offset)?);
    take(hello, &mut offset, session_id_length)?;

    let cipher_suites_length = usize::from(take_u16(hello, &mut offset)?);
    let cipher_suites_data = take(hello, &mut offset, cipher_suites_length)?;
    let cipher_suites = cipher_suites_data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&suite| u16::from_be_bytes(suite))
        .collect();

    let compression_methods_length = usize::from(take_u8(hello, &mut offset)?);
    take(hello, &mut offset, compression_methods_length)?;

    let extensions_length = usize::from(take_u16(hello, &mut offset)?);
    let extensions_end = offset
        .checked_add(extensions_length)
        .ok_or(LayerError::InvalidLength)?;
    if extensions_end > hello.len() {
        return Err(LayerError::InsufficientData);
    }
    let extensions = take(hello, &mut offset, extensions_length)?;

    let mut parsed = TlsClientHello {
        record_version,
        handshake_version,
        client_random,
        cipher_suites,
        server_name: None,
        alpn: Vec::new(),
        supported_versions: Vec::new(),
        supported_groups: Vec::new(),
        ec_point_formats: Vec::new(),
        signature_algorithms: Vec::new(),
        extension_types: Vec::new(),
    };
    if !parse_extensions(extensions, &mut parsed) {
        return Err(LayerError::InsufficientData);
    }
    Ok(parsed)
}

pub fn parse_tls_server_hello(payload: &[u8]) -> Result<TlsServerHello, LayerError> {
    if payload.len() < 5 {
        return Err(LayerError::InvalidLength);
    }
    if payload[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return Err(LayerError::InvalidHeader);
    }

    let record_version = read_u16(payload, 1)?;
    let record_length = usize::from(read_u16(payload, 3)?);
    let record_end = 5usize
        .checked_add(record_length)
        .ok_or(LayerError::InvalidLength)?;
    if record_end > payload.len() {
        return Err(LayerError::InsufficientData);
    }
    let record = &payload[5..record_end];

    if record.len() < 4 {
        return Err(LayerError::InvalidLength);
    }
    if record[0] != SERVER_HELLO_HANDSHAKE_TYPE {
        return Err(LayerError::InvalidHeader);
    }

    let handshake_length = read_u24(record, 1)?;
    let handshake_end = 4usize
        .checked_add(handshake_length)
        .ok_or(LayerError::InvalidLength)?;
    if handshake_end > record.len() {
        return Err(LayerError::InsufficientData);
    }
    let hello = &record[4..handshake_end];
    let mut offset = 0;

    let handshake_version = take_u16(hello, &mut offset)?;
    take(hello, &mut offset, 32)?;

    let session_id_length = usize::from(take_u8(hello, &mut offset)?);
    take(hello, &mut offset, session_id_length)?;

    let cipher_suite = take_u16(hello, &mut offset)?;
    take_u8(hello, &mut offset)?; // compression method

    let extensions_length = usize::from(take_u16(hello, &mut offset)?);
    let extensions_end = offset
        .checked_add(extensions_length)
        .ok_or(LayerError::InvalidLength)?;
    if extensions_end > hello.len() {
        return Err(LayerError::InsufficientData);
    }
    let extensions = take(hello, &mut offset, extensions_length)?;

    let mut parsed = TlsServerHello {
        record_version,
        handshake_version,
        cipher_suite,
        alpn: None,
        supported_version: None,
        extension_types: Vec::new(),
    };
    if !parse_server_extensions(extensions, &mut parsed) {
        return Err(LayerError::InsufficientData);
    }
    Ok(parsed)
}

fn parse_server_extensions(extensions: &[u8], parsed: &mut TlsServerHello) -> bool {
    let mut offset = 0;
    while offset < extensions.len() {
        let Some(header_end) = offset.checked_add(4) else {
            return false;
        };
        if header_end > extensions.len() {
            return false;
        }

        let extension_type = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]);
        let extension_length = usize::from(u16::from_be_bytes([
            extensions[offset + 2],
            extensions[offset + 3],
        ]));
        let Some(data_end) = header_end.checked_add(extension_length) else {
            return false;
        };
        if data_end > extensions.len() {
            return false;
        }
        parsed.extension_types.push(extension_type);

        let data = &extensions[header_end..data_end];
        match extension_type {
            // ALPN (16): server selects exactly one protocol.
            16 => {
                if let Some((protocol_length, rest)) = data.get(2).zip(data.get(3..)) {
                    let protocol_length = usize::from(*protocol_length);
                    if let Some(protocol) = rest.get(..protocol_length) {
                        parsed.alpn = Some(String::from_utf8_lossy(protocol).into_owned());
                    }
                }
            }
            // supported_versions (43): server sends a single selected version, not a list.
            43 => {
                if let Some(bytes) = data.get(..2) {
                    parsed.supported_version = Some(u16::from_be_bytes([bytes[0], bytes[1]]));
                }
            }
            _ => {}
        }

        offset = data_end;
    }
    true
}

fn parse_extensions(extensions: &[u8], parsed: &mut TlsClientHello) -> bool {
    let mut offset = 0;
    while offset < extensions.len() {
        let Some(header_end) = offset.checked_add(4) else {
            return false;
        };
        if header_end > extensions.len() {
            return false;
        }

        let extension_type = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]);
        let extension_length = usize::from(u16::from_be_bytes([
            extensions[offset + 2],
            extensions[offset + 3],
        ]));
        let Some(data_end) = header_end.checked_add(extension_length) else {
            return false;
        };
        if data_end > extensions.len() {
            return false;
        }
        parsed.extension_types.push(extension_type);

        let data = &extensions[header_end..data_end];
        let valid = match extension_type {
            0 => parse_server_name(data, parsed),
            10 => parse_u16_list(data, &mut parsed.supported_groups),
            11 => parse_u8_list(data, &mut parsed.ec_point_formats),
            13 => parse_u16_list(data, &mut parsed.signature_algorithms),
            16 => parse_alpn(data, parsed),
            43 => parse_supported_versions(data, parsed),
            _ => true,
        };
        if !valid {
            return false;
        }
        offset = data_end;
    }
    true
}

fn parse_u16_list(data: &[u8], values: &mut Vec<u16>) -> bool {
    let Some(length_bytes) = data.get(..2) else {
        return false;
    };
    let list_length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
    let Some(list) = data.get(2..2usize.saturating_add(list_length)) else {
        return false;
    };
    if list_length % 2 != 0 {
        return false;
    }
    values.extend(
        list.as_chunks::<2>()
            .0
            .iter()
            .map(|&value| u16::from_be_bytes(value)),
    );
    true
}

fn parse_u8_list(data: &[u8], values: &mut Vec<u8>) -> bool {
    let Some((&list_length, rest)) = data.split_first() else {
        return false;
    };
    let Some(list) = rest.get(..usize::from(list_length)) else {
        return false;
    };
    values.extend_from_slice(list);
    true
}

fn parse_server_name(data: &[u8], parsed: &mut TlsClientHello) -> bool {
    let Some(list_length) = data
        .get(..2)
        .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    else {
        return false;
    };
    let Some(list_end) = 2usize.checked_add(list_length) else {
        return false;
    };
    if list_end > data.len() || list_length < 3 {
        return false;
    }

    let name_type = data[2];
    let name_length = usize::from(u16::from_be_bytes([data[3], data[4]]));
    let Some(name_end) = 5usize.checked_add(name_length) else {
        return false;
    };
    if name_end > list_end {
        return false;
    }
    if name_type == 0 {
        parsed.server_name = Some(String::from_utf8_lossy(&data[5..name_end]).into_owned());
    }
    true
}

fn parse_alpn(data: &[u8], parsed: &mut TlsClientHello) -> bool {
    if data.len() < 2 {
        return false;
    }
    let list_length = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let Some(list_end) = 2usize.checked_add(list_length) else {
        return false;
    };
    if list_end > data.len() {
        return false;
    }

    let mut offset = 2;
    while offset < list_end {
        let protocol_length = usize::from(data[offset]);
        offset += 1;
        let Some(protocol_end) = offset.checked_add(protocol_length) else {
            return false;
        };
        if protocol_end > list_end {
            return false;
        }
        parsed
            .alpn
            .push(String::from_utf8_lossy(&data[offset..protocol_end]).into_owned());
        offset = protocol_end;
    }
    true
}

fn parse_supported_versions(data: &[u8], parsed: &mut TlsClientHello) -> bool {
    let Some((&list_length, versions)) = data.split_first() else {
        return false;
    };
    let list_length = usize::from(list_length);
    if list_length > versions.len() || list_length % 2 != 0 {
        return false;
    }
    parsed.supported_versions.extend(
        versions[..list_length]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&version| u16::from_be_bytes(version)),
    );
    true
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, LayerError> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or(LayerError::InvalidLength)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u24(data: &[u8], offset: usize) -> Result<usize, LayerError> {
    let bytes = data
        .get(offset..offset + 3)
        .ok_or(LayerError::InvalidLength)?;
    Ok((usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2]))
}

fn take_u8(data: &[u8], offset: &mut usize) -> Result<u8, LayerError> {
    let value = *data.get(*offset).ok_or(LayerError::InvalidLength)?;
    *offset += 1;
    Ok(value)
}

fn take_u16(data: &[u8], offset: &mut usize) -> Result<u16, LayerError> {
    let value = read_u16(data, *offset)?;
    *offset += 2;
    Ok(value)
}

fn take<'a>(data: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], LayerError> {
    let end = offset
        .checked_add(length)
        .ok_or(LayerError::InvalidLength)?;
    let value = data.get(*offset..end).ok_or(LayerError::InvalidLength)?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello() -> TlsClientHello {
        TlsClientHello {
            record_version: 0,
            handshake_version: 0,
            client_random: [0u8; 32],
            cipher_suites: Vec::new(),
            server_name: None,
            alpn: Vec::new(),
            supported_versions: Vec::new(),
            supported_groups: Vec::new(),
            ec_point_formats: Vec::new(),
            signature_algorithms: Vec::new(),
            extension_types: Vec::new(),
        }
    }

    fn client_hello_record(extensions: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.extend_from_slice(&[1, 0]);
        let extensions_length =
            u16::try_from(extensions.len()).expect("test extension length fits");
        hello.extend_from_slice(&extensions_length.to_be_bytes());
        hello.extend_from_slice(extensions);
        handshake_record(CLIENT_HELLO_HANDSHAKE_TYPE, &hello)
    }

    fn server_hello_record(extensions: &[u8]) -> Vec<u8> {
        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.push(0);
        let extensions_length =
            u16::try_from(extensions.len()).expect("test extension length fits");
        hello.extend_from_slice(&extensions_length.to_be_bytes());
        hello.extend_from_slice(extensions);
        handshake_record(SERVER_HELLO_HANDSHAKE_TYPE, &hello)
    }

    fn handshake_record(handshake_type: u8, hello: &[u8]) -> Vec<u8> {
        let record_length = u16::try_from(4 + hello.len()).expect("test record length fits");
        let handshake_length = u32::try_from(hello.len()).expect("test handshake length fits");
        let handshake_length_bytes = handshake_length.to_be_bytes();
        let mut record = vec![TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03];
        record.extend_from_slice(&record_length.to_be_bytes());
        record.push(handshake_type);
        record.extend_from_slice(&handshake_length_bytes[1..]);
        record.extend_from_slice(hello);
        record
    }

    #[test]
    fn rejects_truncated_tls_record_bodies() {
        let mut client = client_hello_record(&[]);
        client.pop();
        assert!(matches!(
            parse_tls_client_hello(&client),
            Err(LayerError::InsufficientData)
        ));

        let mut server = server_hello_record(&[]);
        server.pop();
        assert!(matches!(
            parse_tls_server_hello(&server),
            Err(LayerError::InsufficientData)
        ));
    }

    #[test]
    fn rejects_truncated_tls_handshake_bodies() {
        let mut client = client_hello_record(&[]);
        client[8] += 1;
        assert!(matches!(
            parse_tls_client_hello(&client),
            Err(LayerError::InsufficientData)
        ));

        let mut server = server_hello_record(&[]);
        server[8] += 1;
        assert!(matches!(
            parse_tls_server_hello(&server),
            Err(LayerError::InsufficientData)
        ));
    }

    #[test]
    fn rejects_truncated_tls_extension_blocks() {
        let mut client = client_hello_record(&[]);
        let client_last = client.len() - 1;
        client[client_last] = 1;
        assert!(matches!(
            parse_tls_client_hello(&client),
            Err(LayerError::InsufficientData)
        ));

        let mut server = server_hello_record(&[]);
        let server_last = server.len() - 1;
        server[server_last] = 1;
        assert!(matches!(
            parse_tls_server_hello(&server),
            Err(LayerError::InsufficientData)
        ));
    }

    #[test]
    fn rejects_incompletely_parsed_tls_extensions() {
        let client = client_hello_record(&[0, 0, 0, 2, 0, 1]);
        assert!(matches!(
            parse_tls_client_hello(&client),
            Err(LayerError::InsufficientData)
        ));

        let server = server_hello_record(&[0, 0]);
        assert!(matches!(
            parse_tls_server_hello(&server),
            Err(LayerError::InsufficientData)
        ));
    }

    #[test]
    fn parses_fingerprint_extension_fields_in_wire_order() {
        let extensions = [
            0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x0a, 0x0a, 0x00, 0x18, 0x00, 0x0b,
            0x00, 0x03, 0x02, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x08, 0x04, 0x04,
            0x03, 0x08, 0x05,
        ];
        let mut hello = client_hello();

        assert!(parse_extensions(&extensions, &mut hello));

        assert_eq!(hello.extension_types, vec![10, 11, 13]);
        assert_eq!(hello.supported_groups, vec![23, 0x0a0a, 24]);
        assert_eq!(hello.ec_point_formats, vec![0, 1]);
        assert_eq!(hello.signature_algorithms, vec![0x0804, 0x0403, 0x0805]);
    }

    #[test]
    fn rejects_truncated_fingerprint_extension_lists_without_appending() {
        let mut hello = client_hello();

        assert!(!parse_u16_list(
            &[0x00, 0x04, 0x00, 0x17],
            &mut hello.supported_groups
        ));
        assert!(!parse_u16_list(
            &[0x00, 0x03, 0x00, 0x17, 0x00],
            &mut hello.signature_algorithms
        ));
        assert!(!parse_u8_list(
            &[0x03, 0x00, 0x01],
            &mut hello.ec_point_formats
        ));
        assert!(hello.supported_groups.is_empty());
        assert!(hello.signature_algorithms.is_empty());
        assert!(hello.ec_point_formats.is_empty());
    }
}
