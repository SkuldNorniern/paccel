use crate::layer::{Layer, LayerError, ParseError, ProbeResult};

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

/// Probes a Telnet negotiation by its IAC command sequence.
///
/// RFC 854: option negotiation opens with IAC followed by WILL, WONT, DO or
/// DONT. A Telnet stream carrying only data has nothing to probe for, so this
/// reports a mismatch rather than guessing from the port.
#[must_use]
pub fn probe_telnet(payload: &[u8]) -> ProbeResult<TelnetCommand> {
    let Some(&first) = payload.first() else {
        return ProbeResult::Incomplete {
            needed: Some(3),
            available: 0,
        };
    };
    if first != IAC {
        return ProbeResult::NoMatch;
    }
    if let Some(&command) = payload.get(1)
        && !matches!(command, WILL | WONT | DO | DONT)
    {
        return ProbeResult::NoMatch;
    }
    if payload.len() < 3 {
        return ProbeResult::Incomplete {
            needed: Some(3),
            available: payload.len(),
        };
    }

    match parse_telnet_command(payload) {
        Ok(command) => ProbeResult::Match(command),
        Err(error) => ProbeResult::Malformed(ParseError::from_layer_error(
            &error,
            Layer::Application,
            Some("telnet"),
            0,
        )),
    }
}
