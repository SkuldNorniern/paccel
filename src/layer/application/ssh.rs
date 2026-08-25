use std::str;

use crate::layer::LayerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBanner {
    pub protocol_version: String,
    pub software_version: String,
}

const SSH_MSG_KEXINIT: u8 = 20;
const KEXINIT_COOKIE_LEN: usize = 16;

/// SSH_MSG_KEXINIT (RFC 4253 sec 7.1). Sent in the clear before either side's
/// keys take effect, so this is reachable without decryption. Only the
/// algorithm name-lists needed for HASSH-style fingerprinting are kept;
/// `languages_*` and `first_kex_packet_follows` are parsed-through but not
/// stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKexInit {
    pub kex_algorithms: Vec<String>,
    pub server_host_key_algorithms: Vec<String>,
    pub encryption_algorithms_client_to_server: Vec<String>,
    pub encryption_algorithms_server_to_client: Vec<String>,
    pub mac_algorithms_client_to_server: Vec<String>,
    pub mac_algorithms_server_to_client: Vec<String>,
    pub compression_algorithms_client_to_server: Vec<String>,
    pub compression_algorithms_server_to_client: Vec<String>,
}

pub fn parse_ssh_kex_init(payload: &[u8]) -> Result<SshKexInit, LayerError> {
    // Direct-TCP SSH binary packet framing (RFC 4253 sec 6): packet_length(4)
    // + padding_length(1) + payload. No length sanity check beyond what's
    // available - this only ever runs on payload already known to be at
    // least this long via the slices below.
    let packet_length = payload
        .get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(LayerError::InvalidLength)?;
    let declared_total = usize::try_from(packet_length)
        .ok()
        .and_then(|len| len.checked_add(4))
        .ok_or(LayerError::InvalidLength)?;
    if declared_total > payload.len() {
        return Err(LayerError::InvalidLength);
    }
    if *payload.get(5).ok_or(LayerError::InvalidLength)? != SSH_MSG_KEXINIT {
        return Err(LayerError::InvalidHeader);
    }

    let mut offset = 6 + KEXINIT_COOKIE_LEN;
    let mut next_list = || read_name_list(payload, &mut offset);

    Ok(SshKexInit {
        kex_algorithms: next_list()?,
        server_host_key_algorithms: next_list()?,
        encryption_algorithms_client_to_server: next_list()?,
        encryption_algorithms_server_to_client: next_list()?,
        mac_algorithms_client_to_server: next_list()?,
        mac_algorithms_server_to_client: next_list()?,
        compression_algorithms_client_to_server: next_list()?,
        compression_algorithms_server_to_client: next_list()?,
    })
}

fn read_name_list(payload: &[u8], offset: &mut usize) -> Result<Vec<String>, LayerError> {
    let length_bytes = payload
        .get(*offset..*offset + 4)
        .ok_or(LayerError::InvalidLength)?;
    let length = usize::try_from(u32::from_be_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]))
    .map_err(|_| LayerError::InvalidLength)?;
    let start = *offset + 4;
    let end = start.checked_add(length).ok_or(LayerError::InvalidLength)?;
    let raw = payload.get(start..end).ok_or(LayerError::InvalidLength)?;
    *offset = end;

    let text = str::from_utf8(raw).map_err(|_| LayerError::InvalidHeader)?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    Ok(text.split(',').map(str::to_owned).collect())
}

pub fn parse_ssh_banner(payload: &[u8]) -> Result<SshBanner, LayerError> {
    if !payload.starts_with(b"SSH-") {
        return Err(LayerError::InvalidHeader);
    }

    let line_end = payload
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(LayerError::InvalidLength)?;
    let mut line = &payload[..line_end];
    if line.ends_with(b"\r") {
        line = &line[..line.len() - 1];
    }

    let line = str::from_utf8(line).map_err(|_| LayerError::InvalidHeader)?;
    let banner = line.strip_prefix("SSH-").ok_or(LayerError::InvalidHeader)?;
    let (protocol_version, remainder) = banner.split_once('-').ok_or(LayerError::InvalidHeader)?;
    let software_version = remainder
        .split_once(' ')
        .map_or(remainder, |(software, _)| software);

    Ok(SshBanner {
        protocol_version: protocol_version.to_owned(),
        software_version: software_version.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::parse_ssh_kex_init;
    use crate::layer::LayerError;

    // Byte-exact real SSH_MSG_KEXINIT payload (OpenSSH client), verified
    // against tshark's own field extraction before writing this test.
    const KEXINIT: &str = "000000e40814cc19299decf0e8ff36bd64a590cd7fac0000001c637572766532353531392d7368613235362c6578742d696e666f2d63000000077373682d727361000000166165733132382d67636d406f70656e7373682e636f6d000000166165733132382d67636d406f70656e7373682e636f6d0000000d686d61632d736861322d3235360000000d686d61632d736861322d3235360000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c69620000001a6e6f6e652c7a6c6962406f70656e7373682e636f6d2c7a6c6962000000000000000000000000000000000000000000";

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn parses_real_openssh_kexinit() {
        let payload = from_hex(KEXINIT);
        let kex = parse_ssh_kex_init(&payload).expect("KEXINIT should parse");

        assert_eq!(kex.kex_algorithms, vec!["curve25519-sha256", "ext-info-c"]);
        assert_eq!(
            kex.encryption_algorithms_client_to_server,
            vec!["aes128-gcm@openssh.com"]
        );
        assert_eq!(kex.mac_algorithms_client_to_server, vec!["hmac-sha2-256"]);
        assert_eq!(
            kex.compression_algorithms_client_to_server,
            vec!["none", "zlib@openssh.com", "zlib"]
        );
    }

    #[test]
    fn rejects_non_kexinit_message_type() {
        let mut payload = from_hex(KEXINIT);
        payload[5] = 21; // SSH_MSG_NEWKEYS, not KEXINIT
        assert!(matches!(
            parse_ssh_kex_init(&payload),
            Err(LayerError::InvalidHeader)
        ));
    }
}
