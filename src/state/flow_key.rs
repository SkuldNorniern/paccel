use std::hash::{Hash, Hasher};
use std::net::IpAddr;

#[derive(Debug, Clone, Eq)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub vlan_tag: Option<u16>,
}

impl FlowKey {
    pub fn reverse(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
            src_port: self.dst_port,
            dst_port: self.src_port,
            vlan_tag: self.vlan_tag,
        }
    }
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.src == other.src
            && self.dst == other.dst
            && self.protocol == other.protocol
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
            && self.vlan_tag == other.vlan_tag
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src.hash(state);
        self.dst.hash(state);
        self.protocol.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
        self.vlan_tag.hash(state);
    }
}
