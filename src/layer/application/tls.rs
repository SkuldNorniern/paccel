use std::borrow::Cow;

use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

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
    /// An extension did not fit, so the ones after it are missing.
    pub truncated: bool,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    /// Unfiltered extension IDs in wire order, including GREASE values. JA3/JA4
    /// code applies its own GREASE policy.
    pub extension_types: Vec<u16>,
}

/// ServerHello (RFC 8446 sec 4.1.3). `cipher_suite` is the negotiated value and
/// ALPN has at most one protocol. Certificate and ServerKeyExchange are omitted:
/// TLS 1.3 encrypts them, while TLS 1.2 certificates often span TCP segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerHello {
    pub record_version: u16,
    pub handshake_version: u16,
    pub cipher_suite: u16,
    pub alpn: Option<String>,
    pub supported_version: Option<u16>,
    pub extension_types: Vec<u16>,
}

fn coalesced_handshake(payload: &[u8]) -> Result<Cow<'_, [u8]>, LayerError> {
    let first = record_body(payload, 0)?;

    // Enough of the handshake header to know how long the message is, and
    // enough of the message to have all of it.
    if first.len() >= 4 && 4usize.saturating_add(read_u24(first, 1)?) <= first.len() {
        return Ok(Cow::Borrowed(first));
    }

    let mut buffer = first.to_vec();
    let mut offset = 5 + first.len();
    loop {
        // Once the header is in, stop as soon as the message is complete.
        if buffer.len() >= 4 && 4usize.saturating_add(read_u24(&buffer, 1)?) <= buffer.len() {
            break;
        }
        if offset >= payload.len() || payload[offset] != TLS_HANDSHAKE_CONTENT_TYPE {
            return Err(LayerError::InsufficientData);
        }
        let next = record_body(payload, offset)?;
        if next.is_empty() {
            // Sec 5.1: "Implementations MUST NOT send zero-length fragments of
            // Handshake types", and accepting one would never make progress.
            return Err(LayerError::InvalidHeader);
        }
        offset += 5 + next.len();
        buffer.extend_from_slice(next);
    }

    Ok(Cow::Owned(buffer))
}

/// The body of the TLS record starting at `at`.
fn record_body(payload: &[u8], at: usize) -> Result<&[u8], LayerError> {
    let header_end = at.checked_add(5).ok_or(LayerError::InvalidLength)?;
    if header_end > payload.len() {
        return Err(LayerError::InsufficientData);
    }
    let length = usize::from(read_u16(payload, at + 3)?);
    let end = header_end
        .checked_add(length)
        .ok_or(LayerError::InvalidLength)?;
    if end > payload.len() {
        return Err(LayerError::InsufficientData);
    }

    Ok(&payload[header_end..end])
}

pub fn parse_tls_client_hello(payload: &[u8]) -> Result<TlsClientHello, LayerError> {
    if payload.len() < 5 {
        return Err(LayerError::InvalidLength);
    }
    if payload[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return Err(LayerError::InvalidHeader);
    }

    let record_version = read_u16(payload, 1)?;
    let record = coalesced_handshake(payload)?;
    let record = record.as_ref();

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
        truncated: false,
        alpn: Vec::new(),
        supported_versions: Vec::new(),
        supported_groups: Vec::new(),
        ec_point_formats: Vec::new(),
        signature_algorithms: Vec::new(),
        extension_types: Vec::new(),
    };
    parsed.truncated = !parse_extensions(extensions, &mut parsed);
    Ok(parsed)
}

/// Probes a TLS ClientHello using the record and handshake framing signals.
#[must_use]
pub fn probe_tls_client_hello(payload: &[u8]) -> ProbeResult<TlsClientHello> {
    let Some(&content_type) = payload.first() else {
        return ProbeResult::Incomplete {
            needed: Some(1),
            available: 0,
        };
    };
    if content_type != TLS_HANDSHAKE_CONTENT_TYPE {
        return ProbeResult::NoMatch;
    }
    if payload.len() < 5 {
        return ProbeResult::Incomplete {
            needed: Some(5),
            available: payload.len(),
        };
    }

    let record_length = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
    let Some(record_end) = 5usize.checked_add(record_length) else {
        return malformed_tls_probe(LayerError::InvalidLength);
    };
    if record_end > payload.len() {
        return ProbeResult::Incomplete {
            needed: Some(record_end),
            available: payload.len(),
        };
    }
    let record = &payload[5..record_end];
    let Some(&handshake_type) = record.first() else {
        return malformed_tls_probe(LayerError::InvalidLength);
    };
    if handshake_type != CLIENT_HELLO_HANDSHAKE_TYPE {
        return ProbeResult::NoMatch;
    }
    if record.len() < 4 {
        return malformed_tls_probe(LayerError::InvalidLength);
    }

    let handshake_length =
        (usize::from(record[1]) << 16) | (usize::from(record[2]) << 8) | usize::from(record[3]);
    let Some(handshake_end) = 4usize.checked_add(handshake_length) else {
        return malformed_tls_probe(LayerError::InvalidLength);
    };
    // Past here the message may still be spread over records that follow, so
    // the decision belongs to the same gathering the parse uses. Computing a
    // length from this record alone assumed the handshake continued straight
    // after its header, and called a legitimately fragmented ClientHello
    // malformed - bytes the direct parser reads without trouble.
    match parse_tls_client_hello(payload) {
        Ok(hello) => ProbeResult::Match(hello),
        Err(LayerError::InsufficientData) => ProbeResult::Incomplete {
            needed: records_needed_for(payload, handshake_end),
            available: payload.len(),
        },
        Err(error) => malformed_tls_probe(error),
    }
}

fn records_needed_for(payload: &[u8], handshake_end: usize) -> Option<usize> {
    let mut gathered = 0usize;
    let mut offset = 0usize;

    while gathered < handshake_end {
        if offset >= payload.len() || payload[offset] != TLS_HANDSHAKE_CONTENT_TYPE {
            break;
        }
        let body = record_body(payload, offset).ok()?;
        gathered += body.len();
        offset += 5 + body.len();
    }

    // What is still missing sits in at least one more record.
    let missing = handshake_end.checked_sub(gathered)?;
    if missing == 0 {
        return Some(offset);
    }

    offset.checked_add(5)?.checked_add(missing)
}

fn malformed_tls_probe(error: LayerError) -> ProbeResult<TlsClientHello> {
    ProbeResult::Malformed(ParseError::from_layer_error(
        &error,
        Layer::Application,
        Some("tls"),
        0,
    ))
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

    // RFC 6066 sec 3: ServerNameList is a list. Reading only its first entry
    // misses a host_name behind an entry of any other type - which a server
    // still finds, because it walks the list.
    let mut offset = 2;
    while offset + 3 <= list_end {
        let name_type = data[offset];
        let name_length = usize::from(u16::from_be_bytes([data[offset + 1], data[offset + 2]]));
        let Some(name_end) = offset
            .checked_add(3)
            .and_then(|start| start.checked_add(name_length))
        else {
            return false;
        };
        if name_end > list_end {
            return false;
        }
        if name_type == 0 {
            parsed.server_name =
                Some(String::from_utf8_lossy(&data[offset + 3..name_end]).into_owned());
            return true;
        }
        offset = name_end;
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
    use crate::layer::ProbeResult;

    fn client_hello() -> TlsClientHello {
        TlsClientHello {
            truncated: false,
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

    /// A server_name extension naming `host`.
    fn sni_extension(host: &[u8]) -> Vec<u8> {
        let host_len = u16::try_from(host.len()).expect("fits");
        let mut sni = Vec::new();
        sni.extend_from_slice(&(host_len + 3).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&host_len.to_be_bytes());
        sni.extend_from_slice(host);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&u16::try_from(sni.len()).expect("fits").to_be_bytes());
        extensions.extend_from_slice(&sni);
        extensions
    }

    /// Builds `count` handshake records carrying `body` split evenly.
    fn fragment_records(body: &[u8], split: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for piece in [&body[..split], &body[split..]] {
            out.extend_from_slice(&[TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03]);
            out.extend_from_slice(&u16::try_from(piece.len()).expect("fits").to_be_bytes());
            out.extend_from_slice(piece);
        }
        out
    }

    /// The probe has to gather records the same way the parse does, or the
    /// stateful path refuses bytes the direct parser accepts.
    #[test]
    fn the_probe_matches_a_client_hello_split_across_records() {
        let whole = client_hello_record(&sni_extension(b"example.com"));
        let body = &whole[5..];
        let fragmented = fragment_records(body, body.len() / 2);

        // Every byte is present, just spread over two records.
        let probed = probe_tls_client_hello(&fragmented);

        assert!(
            matches!(
                &probed,
                ProbeResult::Match(hello) if hello.server_name.as_deref() == Some("example.com")
            ),
            "expected a match, got {probed:?}"
        );
    }

    /// And a genuinely short buffer still asks for more rather than matching.
    #[test]
    fn the_probe_asks_for_more_when_a_fragment_is_missing() {
        let whole = client_hello_record(&sni_extension(b"example.com"));
        let body = &whole[5..];
        let fragmented = fragment_records(body, body.len() / 2);
        // Everything except the last few bytes of the second record.
        let cut = &fragmented[..fragmented.len() - 4];

        assert!(matches!(
            probe_tls_client_hello(cut),
            ProbeResult::Incomplete { .. }
        ));
    }

    /// RFC 8446 sec 5.1: "Handshake messages MUST NOT be interleaved with other
    /// record types. That is, if a handshake message is split over two or more
    /// records, there MUST NOT be any other records between them."
    #[test]
    fn a_handshake_split_around_another_record_type_is_not_gathered() {
        let whole = client_hello_record(&[]);
        let body = &whole[5..];
        let split = body.len() / 2;

        let mut interleaved = Vec::new();
        interleaved.extend_from_slice(&[TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03]);
        interleaved.extend_from_slice(&u16::try_from(split).expect("fits").to_be_bytes());
        interleaved.extend_from_slice(&body[..split]);
        // An alert record between the two halves of the handshake message.
        interleaved.extend_from_slice(&[21, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]);
        interleaved.extend_from_slice(&[TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03]);
        interleaved.extend_from_slice(
            &u16::try_from(body.len() - split)
                .expect("fits")
                .to_be_bytes(),
        );
        interleaved.extend_from_slice(&body[split..]);

        assert!(
            matches!(
                coalesced_handshake(&interleaved),
                Err(LayerError::InsufficientData)
            ),
            "the message stops at the record that is not a handshake"
        );

        // The same two fragments with nothing between them are gathered.
        let clean = fragment_records(body, split);
        assert_eq!(
            coalesced_handshake(&clean).expect("gathered").as_ref(),
            body
        );
    }

    /// Sec 5.1: "Implementations MUST NOT send zero-length fragments of
    /// Handshake types". Accepting one gathers nothing and asks for more.
    #[test]
    fn a_zero_length_handshake_fragment_is_refused() {
        let whole = client_hello_record(&[]);
        let body = &whole[5..];
        let split = body.len() / 2;

        let mut with_empty = Vec::new();
        with_empty.extend_from_slice(&[TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03]);
        with_empty.extend_from_slice(&u16::try_from(split).expect("fits").to_be_bytes());
        with_empty.extend_from_slice(&body[..split]);
        with_empty.extend_from_slice(&[TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03, 0x00, 0x00]);
        with_empty.extend_from_slice(&[TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03]);
        with_empty.extend_from_slice(
            &u16::try_from(body.len() - split)
                .expect("fits")
                .to_be_bytes(),
        );
        with_empty.extend_from_slice(&body[split..]);

        assert!(matches!(
            coalesced_handshake(&with_empty),
            Err(LayerError::InvalidHeader)
        ));
    }

    /// RFC 8446 sec 5.1: a handshake message "MAY be coalesced into a single
    /// TLSPlaintext record or fragmented across several records"
    #[test]
    fn a_client_hello_split_across_records_still_parses() {
        let mut sni = Vec::new();
        let host = b"example.com";
        let host_len = u16::try_from(host.len()).expect("fits");
        sni.extend_from_slice(&(host_len + 3).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&host_len.to_be_bytes());
        sni.extend_from_slice(host);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&u16::try_from(sni.len()).expect("fits").to_be_bytes());
        extensions.extend_from_slice(&sni);

        let whole = client_hello_record(&extensions);

        // Same bytes, cut into two records at an arbitrary point inside the
        // handshake message.
        let body = &whole[5..];
        let split = body.len() / 2;
        let mut fragmented = Vec::new();
        for piece in [&body[..split], &body[split..]] {
            fragmented.extend_from_slice(&[TLS_HANDSHAKE_CONTENT_TYPE, 0x03, 0x03]);
            fragmented.extend_from_slice(&u16::try_from(piece.len()).expect("fits").to_be_bytes());
            fragmented.extend_from_slice(piece);
        }

        let hello = parse_tls_client_hello(&fragmented)
            .expect("a fragmented ClientHello is still a ClientHello");
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
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

    /// RFC 6066 sec 3: ServerNameList is a list, and a server walks it. Reading
    /// only the first entry lets a decoy of another name_type hide the real
    /// host_name from anything watching, while the connection still works.
    #[test]
    fn a_host_name_behind_another_entry_is_still_found() {
        let entry = |name_type: u8, name: &[u8]| {
            let mut out = vec![name_type];
            out.extend(u16::try_from(name.len()).expect("short name").to_be_bytes());
            out.extend(name);
            out
        };
        let mut list = entry(99, b"decoy");
        list.extend(entry(0, b"real.example.com"));
        let mut body = u16::try_from(list.len())
            .expect("short list")
            .to_be_bytes()
            .to_vec();
        body.extend(&list);

        let mut hello = client_hello();
        hello.server_name = None;
        assert!(parse_server_name(&body, &mut hello));
        assert_eq!(hello.server_name.as_deref(), Some("real.example.com"));
    }

    #[test]
    fn an_extension_that_does_not_fit_is_reported_not_fatal() {
        let client = client_hello_record(&[0, 0, 0, 2, 0, 1]);
        let hello = parse_tls_client_hello(&client).expect("what parsed is kept");
        assert!(hello.truncated);

        let server = server_hello_record(&[0, 0]);
        assert!(matches!(
            parse_tls_server_hello(&server),
            Err(LayerError::InsufficientData)
        ));
    }

    /// A ClientHello cut by a snaplen loses its trailing extensions. The name
    /// is usually the first one, and is the field worth keeping.
    #[test]
    fn a_later_extension_that_does_not_fit_keeps_the_server_name() {
        let mut extensions = Vec::new();
        let host = b"example.com";
        let list_len = u16::try_from(host.len() + 3).expect("short host");
        extensions.extend([0x00, 0x00]);
        extensions.extend(
            u16::try_from(host.len() + 5)
                .expect("short host")
                .to_be_bytes(),
        );
        extensions.extend(list_len.to_be_bytes());
        extensions.push(0);
        extensions.extend(u16::try_from(host.len()).expect("short host").to_be_bytes());
        extensions.extend(host);
        // supported_groups claiming far more than it carries
        extensions.extend([0x00, 0x0a, 0x00, 0xff, 0x00, 0x02, 0x00, 0x17]);

        let hello =
            parse_tls_client_hello(&client_hello_record(&extensions)).expect("the name survives");
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
        assert!(hello.truncated);
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

    #[test]
    fn probe_matches_a_client_hello_record() {
        assert!(matches!(
            probe_tls_client_hello(&client_hello_record(&[])),
            ProbeResult::Match(_)
        ));
    }

    #[test]
    fn probe_reports_no_match_for_a_server_hello() {
        assert_eq!(
            probe_tls_client_hello(&server_hello_record(&[])),
            ProbeResult::NoMatch
        );
    }

    #[test]
    fn probe_reports_incomplete_for_a_truncated_record() {
        let mut client = client_hello_record(&[]);
        let needed = client.len();
        client.pop();
        assert_eq!(
            probe_tls_client_hello(&client),
            ProbeResult::Incomplete {
                needed: Some(needed),
                available: client.len(),
            }
        );
    }

    #[test]
    fn probe_reports_incomplete_for_a_truncated_handshake() {
        let mut client = client_hello_record(&[]);
        client[8] += 1;

        assert_eq!(
            probe_tls_client_hello(&client),
            ProbeResult::Incomplete {
                needed: Some(client.len() + 5 + 1),
                available: client.len(),
            }
        );
    }
}
