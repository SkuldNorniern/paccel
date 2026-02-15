use std::time::SystemTime;

#[derive(Debug, Clone, Default)]
pub struct PacketMetadata {
    pub timestamp: Option<SystemTime>,
    pub interface: Option<String>,
    pub snaplen: Option<usize>,
    pub direction: Option<PacketDirection>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum PacketDirection {
    Ingress,
    Egress,
    #[default]
    Unknown,
}
