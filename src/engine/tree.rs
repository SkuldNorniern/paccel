#[derive(Debug, Clone)]
pub struct DecodeEvent {
    pub protocol: &'static str,
    pub offset: usize,
    pub length: usize,
    pub message: String,
}

#[derive(Debug, Default, Clone)]
pub struct DecodeTree {
    events: Vec<DecodeEvent>,
}

impl DecodeTree {
    pub fn push(&mut self, event: DecodeEvent) {
        self.events.push(event);
    }

    pub fn events(&self) -> &[DecodeEvent] {
        &self.events
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}
