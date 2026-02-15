use super::error::DecodeWarning;

#[derive(Debug, Clone, Copy, Default)]
pub enum DecodeMode {
    Strict,
    #[default]
    Permissive,
}

#[derive(Debug, Clone)]
pub struct DecodeConfig {
    pub mode: DecodeMode,
    pub max_depth: usize,
    pub max_packet_bytes: usize,
}

impl Default for DecodeConfig {
    fn default() -> Self {
        Self {
            mode: DecodeMode::Permissive,
            max_depth: 8,
            max_packet_bytes: 65_535,
        }
    }
}

#[derive(Debug, Default)]
pub struct DecodeContext {
    pub depth: usize,
    pub warnings: Vec<DecodeWarning>,
}

impl DecodeContext {
    pub fn push_warning(&mut self, warning: DecodeWarning) {
        self.warnings.push(warning);
    }
}
