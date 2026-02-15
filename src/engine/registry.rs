use super::context::DecodeContext;
use super::error::DecodeError;
use super::tree::DecodeTree;
use crate::packet::PacketView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    NoMatch,
    Match { priority: u8 },
}

pub trait Dissector: Send + Sync {
    fn name(&self) -> &'static str;

    fn probe(&self, view: &PacketView<'_>, context: &DecodeContext) -> ProbeResult;

    fn decode(
        &self,
        view: &PacketView<'_>,
        context: &mut DecodeContext,
        tree: &mut DecodeTree,
    ) -> Result<(), DecodeError>;
}

#[derive(Default)]
pub struct DissectorRegistry {
    dissectors: Vec<Box<dyn Dissector>>,
}

impl DissectorRegistry {
    pub fn register<D>(&mut self, dissector: D)
    where
        D: Dissector + 'static,
    {
        self.dissectors.push(Box::new(dissector));
    }

    pub fn is_empty(&self) -> bool {
        self.dissectors.is_empty()
    }

    pub fn decode_best(
        &self,
        view: &PacketView<'_>,
        context: &mut DecodeContext,
        tree: &mut DecodeTree,
    ) -> Result<Option<&'static str>, DecodeError> {
        let mut best: Option<(u8, usize)> = None;

        for (idx, dissector) in self.dissectors.iter().enumerate() {
            if let ProbeResult::Match { priority } = dissector.probe(view, context) {
                match best {
                    Some((best_priority, _)) if best_priority >= priority => {}
                    _ => best = Some((priority, idx)),
                }
            }
        }

        if let Some((_, idx)) = best {
            let dissector = &self.dissectors[idx];
            dissector.decode(view, context, tree)?;
            return Ok(Some(dissector.name()));
        }

        Ok(None)
    }
}
