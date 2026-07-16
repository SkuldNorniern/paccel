use crate::layer::LayerError;

const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 22;
const CLIENT_HELLO_HANDSHAKE_TYPE: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHello {
    pub record_version: u16,
    pub handshake_version: u16,
    pub cipher_suites: Vec<u16>,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
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
    let record_end = 5usize.saturating_add(record_length).min(payload.len());
    let record = &payload[5..record_end];

    if record.len() < 4 {
        return Err(LayerError::InvalidLength);
    }
    if record[0] != CLIENT_HELLO_HANDSHAKE_TYPE {
        return Err(LayerError::InvalidHeader);
    }

    let handshake_length = read_u24(record, 1)?;
    let handshake_end = 4usize.saturating_add(handshake_length).min(record.len());
    let hello = &record[4..handshake_end];
    let mut offset = 0;

    let handshake_version = take_u16(hello, &mut offset)?;
    take(hello, &mut offset, 32)?;

    let session_id_length = usize::from(take_u8(hello, &mut offset)?);
    take(hello, &mut offset, session_id_length)?;

    let cipher_suites_length = usize::from(take_u16(hello, &mut offset)?);
    let cipher_suites_data = take(hello, &mut offset, cipher_suites_length)?;
    let cipher_suites = cipher_suites_data
        .chunks_exact(2)
        .map(|suite| u16::from_be_bytes([suite[0], suite[1]]))
        .collect();

    let compression_methods_length = usize::from(take_u8(hello, &mut offset)?);
    take(hello, &mut offset, compression_methods_length)?;

    let extensions_length = usize::from(take_u16(hello, &mut offset)?);
    let available_extensions_length = extensions_length.min(hello.len() - offset);
    let extensions = take(hello, &mut offset, available_extensions_length)?;

    let mut parsed = TlsClientHello {
        record_version,
        handshake_version,
        cipher_suites,
        server_name: None,
        alpn: Vec::new(),
        supported_versions: Vec::new(),
    };
    parse_extensions(extensions, &mut parsed);
    Ok(parsed)
}

fn parse_extensions(extensions: &[u8], parsed: &mut TlsClientHello) {
    let mut offset = 0;
    while offset < extensions.len() {
        let Some(header_end) = offset.checked_add(4) else {
            break;
        };
        if header_end > extensions.len() {
            break;
        }

        let extension_type = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]);
        let extension_length = usize::from(u16::from_be_bytes([
            extensions[offset + 2],
            extensions[offset + 3],
        ]));
        let Some(data_end) = header_end.checked_add(extension_length) else {
            break;
        };
        if data_end > extensions.len() {
            break;
        }

        let data = &extensions[header_end..data_end];
        let valid = match extension_type {
            0 => parse_server_name(data, parsed),
            16 => parse_alpn(data, parsed),
            43 => parse_supported_versions(data, parsed),
            _ => true,
        };
        if !valid {
            break;
        }
        offset = data_end;
    }
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
            .chunks_exact(2)
            .map(|version| u16::from_be_bytes([version[0], version[1]])),
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
