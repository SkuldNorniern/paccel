use std::net::IpAddr;

use crate::layer::LayerError;
use crate::state::{FlowKey, FlowTable, Ipv4Reassembler, Ipv6Reassembler};

use super::builtin::{BuiltinPacketParser, ParseConfig, ParsedPacket, TransportSegment};

#[derive(Debug, Clone, Copy)]
pub struct StatefulConfig {
    pub parser: ParseConfig,
    pub enable_flow_table: bool,
    pub max_flows: usize,
    pub enable_ipv4_reassembly: bool,
    pub enable_ipv6_reassembly: bool,
}

impl Default for StatefulConfig {
    fn default() -> Self {
        Self {
            parser: ParseConfig::default(),
            enable_flow_table: false,
            max_flows: 100_000,
            enable_ipv4_reassembly: false,
            enable_ipv6_reassembly: false,
        }
    }
}

#[derive(Debug)]
pub struct StatefulDecoder {
    config: StatefulConfig,
    flow_table: Option<FlowTable>,
    #[allow(dead_code)]
    ipv4_reassembler: Option<Ipv4Reassembler>,
    #[allow(dead_code)]
    ipv6_reassembler: Option<Ipv6Reassembler>,
}

impl StatefulDecoder {
    pub fn new(config: StatefulConfig) -> Self {
        let flow_table = if config.enable_flow_table {
            Some(FlowTable::new(config.max_flows))
        } else {
            None
        };

        let ipv4_reassembler = config.enable_ipv4_reassembly.then(Ipv4Reassembler::default);
        let ipv6_reassembler = config.enable_ipv6_reassembly.then(Ipv6Reassembler::default);

        Self {
            config,
            flow_table,
            ipv4_reassembler,
            ipv6_reassembler,
        }
    }

    pub fn parse_packet(&mut self, raw: &[u8], now_ms: u64) -> Result<ParsedPacket, LayerError> {
        let parsed = BuiltinPacketParser::parse_with_config(raw, self.config.parser)?;

        if let Some(table) = self.flow_table.as_mut()
            && let Some(flow_key) = flow_key_from_parsed(&parsed)
        {
            table.upsert(flow_key, now_ms, raw.len());
        }

        Ok(parsed)
    }

    pub fn flow_table(&self) -> Option<&FlowTable> {
        self.flow_table.as_ref()
    }
}

fn flow_key_from_parsed(parsed: &ParsedPacket) -> Option<FlowKey> {
    let (src, dst, protocol) = if let Some(ipv4) = parsed.ipv4.as_ref() {
        (
            IpAddr::V4(ipv4.source),
            IpAddr::V4(ipv4.destination),
            ipv4.protocol,
        )
    } else if let Some(ipv6) = parsed.ipv6.as_ref() {
        (
            IpAddr::V6(ipv6.source),
            IpAddr::V6(ipv6.destination),
            ipv6.next_header,
        )
    } else {
        return None;
    };

    let (src_port, dst_port, final_protocol) = match parsed.transport.as_ref() {
        Some(TransportSegment::Tcp(tcp)) => (tcp.source_port, tcp.destination_port, 6),
        Some(TransportSegment::Udp(udp)) => (udp.source_port, udp.destination_port, 17),
        None => (0, 0, protocol),
    };

    Some(FlowKey {
        src,
        dst,
        protocol: final_protocol,
        src_port,
        dst_port,
        vlan_tag: parsed
            .ethernet
            .as_ref()
            .and_then(|eth| eth.vlan_tags.last().copied()),
    })
}

#[cfg(test)]
mod tests {
    use super::{StatefulConfig, StatefulDecoder};

    #[test]
    fn updates_flow_table_when_enabled() {
        let mut decoder = StatefulDecoder::new(StatefulConfig {
            enable_flow_table: true,
            ..StatefulConfig::default()
        });

        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x12,
            0x34, 0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50,
            0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let parsed = decoder
            .parse_packet(&frame, 1_000)
            .expect("parse should succeed");
        assert!(parsed.transport.is_some());

        let flow_len = decoder
            .flow_table()
            .expect("flow table should be enabled")
            .len();
        assert_eq!(flow_len, 1);
    }
}
