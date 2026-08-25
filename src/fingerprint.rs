use crate::layer::application::{
    ssh::SshKexInit,
    tls::{TlsClientHello, TlsServerHello},
};
use md5::{Digest as _, Md5};
use sha2::Sha256;

fn is_grease_u16(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a
}

pub fn ja3_string(hello: &TlsClientHello) -> String {
    let cipher_suites = join_decimal_u16(
        hello
            .cipher_suites
            .iter()
            .copied()
            .filter(|value| !is_grease_u16(*value)),
    );
    let extensions = join_decimal_u16(
        hello
            .extension_types
            .iter()
            .copied()
            .filter(|value| !is_grease_u16(*value)),
    );
    let supported_groups = join_decimal_u16(
        hello
            .supported_groups
            .iter()
            .copied()
            .filter(|value| !is_grease_u16(*value)),
    );
    let point_formats = hello
        .ec_point_formats
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join("-");

    format!(
        "{},{cipher_suites},{extensions},{supported_groups},{point_formats}",
        hello.handshake_version
    )
}

pub fn ja3_hash(hello: &TlsClientHello) -> String {
    lowercase_hex(&Md5::digest(ja3_string(hello).as_bytes()))
}

pub fn ja3s_string(hello: &TlsServerHello) -> String {
    let extensions = join_decimal_u16(hello.extension_types.iter().copied());

    format!(
        "{},{},{extensions}",
        hello.handshake_version, hello.cipher_suite
    )
}

pub fn ja3s_hash(hello: &TlsServerHello) -> String {
    lowercase_hex(&Md5::digest(ja3s_string(hello).as_bytes()))
}

pub fn hassh_algorithms_string(kex: &SshKexInit) -> String {
    format!(
        "{};{};{};{}",
        kex.kex_algorithms.join(","),
        kex.encryption_algorithms_client_to_server.join(","),
        kex.mac_algorithms_client_to_server.join(","),
        kex.compression_algorithms_client_to_server.join(",")
    )
}

pub fn hassh(kex: &SshKexInit) -> String {
    lowercase_hex(&Md5::digest(hassh_algorithms_string(kex).as_bytes()))
}

pub fn hassh_server_algorithms_string(kex: &SshKexInit) -> String {
    format!(
        "{};{};{};{}",
        kex.kex_algorithms.join(","),
        kex.encryption_algorithms_server_to_client.join(","),
        kex.mac_algorithms_server_to_client.join(","),
        kex.compression_algorithms_server_to_client.join(",")
    )
}

pub fn hassh_server(kex: &SshKexInit) -> String {
    lowercase_hex(&Md5::digest(hassh_server_algorithms_string(kex).as_bytes()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4Transport {
    Tcp,
    Quic,
    Dtls,
}

pub fn ja4_string(hello: &TlsClientHello, transport: Ja4Transport) -> String {
    let transport_code = match transport {
        Ja4Transport::Tcp => 't',
        Ja4Transport::Quic => 'q',
        Ja4Transport::Dtls => 'd',
    };
    let version = hello
        .supported_versions
        .iter()
        .copied()
        .filter(|value| !is_grease_u16(*value))
        .max()
        .unwrap_or(hello.handshake_version);
    let sni_code = if hello.server_name.is_some() {
        'd'
    } else {
        'i'
    };
    let cipher_count = hello
        .cipher_suites
        .iter()
        .filter(|value| !is_grease_u16(**value))
        .count()
        .min(99);
    let extension_count = hello
        .extension_types
        .iter()
        .filter(|value| !is_grease_u16(**value))
        .count()
        .min(99);
    let alpn_code = ja4_alpn_code(&hello.alpn);
    let ja4_a = format!(
        "{transport_code}{}{sni_code}{cipher_count:02}{extension_count:02}{alpn_code}",
        ja4_version_code(version)
    );

    format!(
        "{ja4_a}_{}_{}",
        ja4_cipher_hash(hello),
        ja4_extension_hash(hello)
    )
}

fn join_decimal_u16(values: impl Iterator<Item = u16>) -> String {
    values
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn ja4_version_code(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn ja4_alpn_code(alpn: &[String]) -> String {
    let Some(protocol) = alpn.first().filter(|protocol| !protocol.is_empty()) else {
        return "00".to_string();
    };
    let mut characters = protocol.chars();
    let Some(first) = characters.next() else {
        return "00".to_string();
    };
    let last = characters.next_back().unwrap_or(first);
    format!("{first}{last}")
}

fn ja4_cipher_hash(hello: &TlsClientHello) -> String {
    let mut ciphers = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|value| !is_grease_u16(*value))
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>();
    ciphers.sort_unstable();
    truncated_sha256(&ciphers.join(","))
}

fn ja4_extension_hash(hello: &TlsClientHello) -> String {
    let mut extensions = hello
        .extension_types
        .iter()
        .copied()
        .filter(|value| !is_grease_u16(*value) && *value != 0x0000 && *value != 0x0010)
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>();
    extensions.sort_unstable();
    let signature_algorithms = hello
        .signature_algorithms
        .iter()
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    truncated_sha256(&format!(
        "{}_{}",
        extensions.join(","),
        signature_algorithms
    ))
}

fn truncated_sha256(input: &str) -> String {
    let mut digest = lowercase_hex(&Sha256::digest(input.as_bytes()));
    digest.truncate(12);
    digest
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        output.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> TlsClientHello {
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

    #[test]
    fn ja3_reference_vector_a() {
        let hello = TlsClientHello {
            handshake_version: 769,
            cipher_suites: vec![47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
            extension_types: vec![0, 10, 11],
            supported_groups: vec![23, 24, 25],
            ec_point_formats: vec![0],
            ..hello()
        };

        assert_eq!(
            ja3_string(&hello),
            "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
        );
        assert_eq!(ja3_hash(&hello), "ada70206e40642a3e4461f35503241d5");
    }

    #[test]
    fn ja3_reference_vector_b() {
        let hello = TlsClientHello {
            handshake_version: 769,
            cipher_suites: vec![4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99],
            ..hello()
        };

        assert_eq!(ja3_string(&hello), "769,4-5-10-9-100-98-3-6-19-18-99,,,");
        assert_eq!(ja3_hash(&hello), "de350869b8c85de67a350c8d186f11e6");
    }

    #[test]
    fn ja3s_reference_vector() {
        let hello = TlsServerHello {
            record_version: 0,
            handshake_version: 771,
            cipher_suite: 49199,
            alpn: None,
            supported_version: None,
            extension_types: vec![65281, 0, 11, 16, 23],
        };

        assert_eq!(ja3s_string(&hello), "771,49199,65281-0-11-16-23");
        assert_eq!(ja3s_hash(&hello), "5d79edf64e03689ff559a54e9d9487bc");
    }

    #[test]
    fn hassh_reference_vector() {
        let kex = SshKexInit {
            kex_algorithms: vec!["curve25519-sha256".to_string(), "ext-info-c".to_string()],
            server_host_key_algorithms: Vec::new(),
            encryption_algorithms_client_to_server: vec!["aes128-gcm@openssh.com".to_string()],
            encryption_algorithms_server_to_client: Vec::new(),
            mac_algorithms_client_to_server: vec!["hmac-sha2-256".to_string()],
            mac_algorithms_server_to_client: Vec::new(),
            compression_algorithms_client_to_server: vec![
                "none".to_string(),
                "zlib@openssh.com".to_string(),
                "zlib".to_string(),
            ],
            compression_algorithms_server_to_client: Vec::new(),
        };

        assert_eq!(
            hassh_algorithms_string(&kex),
            "curve25519-sha256,ext-info-c;aes128-gcm@openssh.com;hmac-sha2-256;none,zlib@openssh.com,zlib"
        );
        assert_eq!(hassh(&kex), "bf34b97113a976f3eb1a7f7f86ad9d3a");
    }

    #[test]
    fn hassh_server_reference_vector() {
        let kex = SshKexInit {
            kex_algorithms: vec!["curve25519-sha256".to_string()],
            server_host_key_algorithms: Vec::new(),
            encryption_algorithms_client_to_server: Vec::new(),
            encryption_algorithms_server_to_client: vec![
                "aes128-gcm@openssh.com".to_string(),
                "aes256-gcm@openssh.com".to_string(),
                "aes256-ctr".to_string(),
                "aes192-ctr".to_string(),
                "aes128-ctr".to_string(),
                "chacha20-poly1305@openssh.com".to_string(),
            ],
            mac_algorithms_client_to_server: Vec::new(),
            mac_algorithms_server_to_client: vec!["hmac-sha2-256".to_string()],
            compression_algorithms_client_to_server: Vec::new(),
            compression_algorithms_server_to_client: vec!["none".to_string()],
        };

        assert_eq!(
            hassh_server_algorithms_string(&kex),
            "curve25519-sha256;aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,chacha20-poly1305@openssh.com;hmac-sha2-256;none"
        );
        assert_eq!(hassh_server(&kex), "213537e42e69a72c32c68fabc65c572f");
    }

    #[test]
    fn ja4_hash_reference_vector() {
        let hello = TlsClientHello {
            server_name: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
            supported_versions: vec![0x1a1a, 0x0304],
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extension_types: vec![
                0x0005, 0x000a, 0x000d, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x4469, 0xff01,
                0x000b, 0x002b, 0x002d, 0x0033,
            ],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            ..hello()
        };

        assert_eq!(ja4_cipher_hash(&hello), "8daaf6152771");
        assert_eq!(ja4_extension_hash(&hello), "e5627efa2ab1");
        assert_eq!(
            ja4_string(&hello, Ja4Transport::Tcp),
            "t13d1514h2_8daaf6152771_e5627efa2ab1"
        );
    }
}
