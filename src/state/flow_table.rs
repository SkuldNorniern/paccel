use std::collections::HashMap;

use super::flow_key::FlowKey;

#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub packet_count: u64,
    pub byte_count: u64,
}

#[derive(Debug)]
pub struct FlowTable {
    entries: HashMap<FlowKey, FlowEntry>,
    max_entries: usize,
}

impl FlowTable {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    pub fn upsert(&mut self, key: FlowKey, now_ms: u64, packet_bytes: usize) {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_seen_ms = now_ms;
            entry.packet_count += 1;
            entry.byte_count += packet_bytes as u64;
            return;
        }

        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        self.entries.insert(
            key,
            FlowEntry {
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                packet_count: 1,
                byte_count: packet_bytes as u64,
            },
        );
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowEntry> {
        self.entries.get(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_seen_ms)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{FlowKey, FlowTable};

    fn key(src_last: u8, dst_last: u8, src_port: u16, dst_port: u16) -> FlowKey {
        FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, src_last)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, dst_last)),
            protocol: 6,
            src_port,
            dst_port,
            vlan_tag: None,
        }
    }

    #[test]
    fn upsert_updates_existing_flow() {
        let mut table = FlowTable::new(1024);
        let flow = key(1, 2, 1234, 80);

        table.upsert(flow.clone(), 1000, 60);
        table.upsert(flow.clone(), 2000, 120);

        let entry = table.get(&flow).expect("flow should exist");
        assert_eq!(entry.packet_count, 2);
        assert_eq!(entry.byte_count, 180);
        assert_eq!(entry.first_seen_ms, 1000);
        assert_eq!(entry.last_seen_ms, 2000);
    }

    #[test]
    fn evicts_oldest_when_capacity_hit() {
        let mut table = FlowTable::new(2);
        let flow_a = key(1, 2, 1111, 80);
        let flow_b = key(3, 4, 2222, 80);
        let flow_c = key(5, 6, 3333, 80);

        table.upsert(flow_a.clone(), 1000, 60);
        table.upsert(flow_b.clone(), 2000, 60);
        table.upsert(flow_c.clone(), 3000, 60);

        assert!(table.get(&flow_a).is_none());
        assert!(table.get(&flow_b).is_some());
        assert!(table.get(&flow_c).is_some());
        assert_eq!(table.len(), 2);
    }
}
