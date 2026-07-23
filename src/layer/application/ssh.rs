use std::str;

use crate::layer::LayerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBanner {
    pub protocol_version: String,
    pub software_version: String,
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
