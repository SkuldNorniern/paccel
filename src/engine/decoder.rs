use super::context::{DecodeConfig, DecodeContext};
use super::error::{DecodeError, DecodeWarning};
use super::registry::DissectorRegistry;
use super::tree::DecodeTree;
use crate::packet::{Packet, PacketView};

#[derive(Debug, Default)]
pub struct DecodeReport {
    pub tree: DecodeTree,
    pub warnings: Vec<DecodeWarning>,
    pub matched_dissector: Option<&'static str>,
}

#[derive(Default)]
pub struct Decoder {
    pub config: DecodeConfig,
    pub registry: DissectorRegistry,
}

impl Decoder {
    pub fn with_config(config: DecodeConfig) -> Self {
        Self {
            config,
            registry: DissectorRegistry::default(),
        }
    }

    pub fn decode_packet(&self, packet: &Packet) -> Result<DecodeReport, DecodeError> {
        if packet.packet.len() > self.config.max_packet_bytes {
            return Err(DecodeError::InsufficientBytes {
                needed: packet.packet.len(),
                available: self.config.max_packet_bytes,
            });
        }

        let view = PacketView::new(&packet.packet);
        let mut context = DecodeContext::default();
        let mut tree = DecodeTree::default();

        let matched = self.registry.decode_best(&view, &mut context, &mut tree)?;

        Ok(DecodeReport {
            tree,
            warnings: context.warnings,
            matched_dissector: matched,
        })
    }
}
