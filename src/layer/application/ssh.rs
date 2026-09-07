use std::str;

use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBanner {
    pub protocol_version: String,
    pub software_version: String,
}

const SSH_MSG_KEXINIT: u8 = 20;
const KEXINIT_COOKIE_LEN: usize = 16;

/// SSH_MSG_KEXINIT (RFC 4253 sec 7.1), sent before encryption. Stores only the
/// algorithm lists needed for HASSH; language lists and
/// `first_kex_packet_follows` are parsed but discarded.
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
    // RFC 4253 sec 6 framing: packet_length(4) + padding_length(1) + payload.
    // The slices below already enforce the available length.
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

    // A name-list is US-ASCII per RFC 4253 sec 5, but a byte outside it is no
    // reason to drop the whole key exchange.
    let text = &String::from_utf8_lossy(raw);
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

    // RFC 4253 sec 4.2 lets the identification string carry a free-text
    // comment after the software version. Refusing the banner because that
    // comment is not UTF-8 loses a session paccel has already identified by
    // its "SSH-" prefix.
    let line = &String::from_utf8_lossy(line);
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

/// Probes an SSH identification banner using its required line prefix.
#[must_use]
pub fn probe_ssh_banner(payload: &[u8]) -> ProbeResult<SshBanner> {
    if payload.len() < 4 {
        return if b"SSH-".starts_with(payload) {
            ProbeResult::Incomplete {
                needed: Some(4),
                available: payload.len(),
            }
        } else {
            ProbeResult::NoMatch
        };
    }
    if !payload.starts_with(b"SSH-") {
        return ProbeResult::NoMatch;
    }
    if !payload.contains(&b'\n') {
        return ProbeResult::Incomplete {
            needed: None,
            available: payload.len(),
        };
    }

    match parse_ssh_banner(payload) {
        Ok(banner) => ProbeResult::Match(banner),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("ssh"),
            0,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_ssh_kex_init, probe_ssh_banner};
    use crate::layer::{LayerError, ProbeResult};

    // OpenSSH SSH_MSG_KEXINIT payload verified against tshark field extraction.
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

    #[test]
    fn probe_matches_a_real_openssh_banner() {
        assert!(matches!(
            probe_ssh_banner(b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5\r\n"),
            ProbeResult::Match(_)
        ));
    }

    #[test]
    fn probe_reports_no_match_for_a_non_ssh_line() {
        assert_eq!(
            probe_ssh_banner(b"HTTP/1.1 200 OK\r\n"),
            ProbeResult::NoMatch
        );
    }

    #[test]
    fn probe_reports_incomplete_for_an_unterminated_banner() {
        let banner = b"SSH-2.0-OpenSSH_7.6p1";
        assert_eq!(
            probe_ssh_banner(banner),
            ProbeResult::Incomplete {
                needed: None,
                available: banner.len(),
            }
        );
    }
}
