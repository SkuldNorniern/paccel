use crate::layer::LayerError;

const IAC: u8 = 0xff;
const WILL: u8 = 0xfb;
const WONT: u8 = 0xfc;
const DO: u8 = 0xfd;
const DONT: u8 = 0xfe;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelnetCommand {
    pub command: u8,
    pub option: u8,
}

pub fn parse_telnet_command(payload: &[u8]) -> Result<TelnetCommand, LayerError> {
    if payload.len() < 3 {
        return Err(LayerError::InvalidLength);
    }
    if payload[0] != IAC || !matches!(payload[1], WILL | WONT | DO | DONT) {
        return Err(LayerError::InvalidHeader);
    }

    Ok(TelnetCommand {
        command: payload[1],
        option: payload[2],
    })
}
