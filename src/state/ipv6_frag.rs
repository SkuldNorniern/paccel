use std::collections::HashMap;
use std::net::Ipv6Addr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv6FragmentKey {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub identification: u32,
    pub next_header: u8,
}

#[derive(Debug, Clone)]
pub struct Ipv6Fragment {
    pub offset_bytes: u16,
    pub more_fragments: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Ipv6Reassembler {
    buckets: HashMap<Ipv6FragmentKey, Vec<Ipv6Fragment>>,
}

impl Ipv6Reassembler {
    pub fn insert(&mut self, key: Ipv6FragmentKey, fragment: Ipv6Fragment) -> Option<Vec<u8>> {
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
