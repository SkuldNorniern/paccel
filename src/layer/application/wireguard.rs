use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// Enumerates the recognized WireGuard message types.
/// (These are based on the WireGuard specification as a simplified example.)
#[derive(Debug, PartialEq, Eq)]
pub enum WireGuardMessage {
    HandshakeInitiation {
        message_type: u32,
        // Other fields like sender, receiver, and timestamp can be added here.
    },
    // Additional message types (e.g. HandshakeResponse, CookieReply, Data) go here.
}

/// Processor for WireGuard messages.
pub struct WireGuardProcessor;

impl ProtocolProcessor<WireGuardMessage> for WireGuardProcessor {
    fn parse(&self, packet: &mut Packet) -> Result<WireGuardMessage, LayerError> {
        // WireGuard messages must be at least 4 bytes long to extract the message type.
        if packet.packet.len() < 4 {
            return Err(LayerError::InvalidLength);
        }
        // Parse the first 4 bytes (assuming little-endian for WireGuard).
        let msg_type_bytes: [u8; 4] = packet.packet[..4]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?;
        let message_type = u32::from_le_bytes(msg_type_bytes);
        
        // Dispatch based on the message type.
        // For instance, assume '1' indicates a Handshake Initiation message.
        match message_type {
            1 => {
                // Check the packet length for handshake initiation.
                // (The real handshake initiation message is longer; this is illustrative.)
                if packet.packet.len() < 16 {
                    return Err(LayerError::InvalidLength);
                }
                // Parse additional handshake fields as needed.
                Ok(WireGuardMessage::HandshakeInitiation { message_type })
            }
            other => {
                // Unrecognized WireGuard message.
                Err(LayerError::UnsupportedProtocol(u8::try_from(other).unwrap_or(u8::MAX)))
            }
        }
    }
} 