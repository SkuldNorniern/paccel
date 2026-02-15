use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4FragmentKey {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub identification: u16,
    pub protocol: u8,
}

#[derive(Debug, Clone)]
pub struct Ipv4Fragment {
    pub offset_bytes: u16,
    pub more_fragments: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Ipv4Reassembler {
    buckets: HashMap<Ipv4FragmentKey, Vec<Ipv4Fragment>>,
}

impl Ipv4Reassembler {
    pub fn insert(&mut self, key: Ipv4FragmentKey, fragment: Ipv4Fragment) -> Option<Vec<u8>> {
        let parts = self.buckets.entry(key.clone()).or_default();
        parts.push(fragment);
        parts.sort_by_key(|f| f.offset_bytes);

        let has_last = parts.iter().any(|f| !f.more_fragments);
        if !has_last {
            return None;
        }

        let mut next_offset = 0usize;
        let mut out = Vec::new();
        for frag in parts.iter() {
            let frag_offset = frag.offset_bytes as usize;
            if frag_offset != next_offset {
                return None;
            }
            out.extend_from_slice(&frag.payload);
            next_offset += frag.payload.len();
        }

        self.buckets.remove(&key);
        Some(out)
    }
}
