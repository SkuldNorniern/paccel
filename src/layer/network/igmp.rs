use std::net::Ipv4Addr;

use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// IGMP protocol messages supporting v1, v2, and v3.
#[derive(Debug, PartialEq, Eq)]
pub enum IgmpMessage {
    /// IGMP Query message.
    Query(IgmpQuery),
    /// IGMP Membership Report.
    Report(IgmpReport),
    /// IGMP Leave Group (used in IGMPv2).
    LeaveGroup {
        typ: u8,
        checksum: u16,
        group_address: Ipv4Addr,
    },
}

/// IGMP Query message variants.
#[derive(Debug, PartialEq, Eq)]
pub enum IgmpQuery {
    /// IGMPv1/IGMPv2 Query has an 8-byte header.
    V1V2 {
        typ: u8,
        max_resp_time: u8,
        checksum: u16,
        group_address: Ipv4Addr,
    },
    /// IGMPv3 Query includes additional fields and an optional list of source addresses.
    V3 {
        typ: u8,
        max_resp_code: u8,
        checksum: u16,
        group_address: Ipv4Addr,
        s_flag: bool,
        qrv: u8,
        qqic: u8,
        num_sources: u16,
        source_addresses: Vec<Ipv4Addr>,
    },
}

/// IGMP Membership Report variants.
#[derive(Debug, PartialEq, Eq)]
pub enum IgmpReport {
    /// IGMPv1 Report.
    V1 {
        typ: u8,
        checksum: u16,
        group_address: Ipv4Addr,
    },
    /// IGMPv2 Report.
    V2 {
        typ: u8,
        checksum: u16,
        group_address: Ipv4Addr,
    },
    /// IGMPv3 Report contains one or more group records.
    V3 {
        typ: u8,
        reserved: u8,
        checksum: u16,
        num_group_records: u16,
        group_records: Vec<IgmpGroupRecord>,
    },
}

/// A group record provided in an IGMPv3 Membership Report.
/// See RFC 3376 for details.
#[derive(Debug, PartialEq, Eq)]
pub struct IgmpGroupRecord {
    pub record_type: u8,
    pub aux_data_len: u8, // In 32-bit words.
    pub num_sources: u16,
    pub multicast_address: Ipv4Addr,
    pub source_addresses: Vec<Ipv4Addr>,
    pub aux_data: Vec<u8>,
}

/// Processor for handling IGMP packet parsing.
pub struct IgmpProcessor;

impl ProtocolProcessor<IgmpMessage> for IgmpProcessor {
    fn parse(&self, packet: &mut Packet) -> Result<IgmpMessage, LayerError> {
        let data = &packet.packet;
        if data.len() < 8 {
            return Err(LayerError::InvalidLength);
        }
        let typ = data[0];

        match typ {
            0x11 => {
                // Membership Query (common for all IGMP versions)
                // For IGMPv1/v2 query, the header is 8 bytes.
                if data.len() == 8 {
                    // Layout:
                    // Byte 0: Type (0x11)
                    // Byte 1: Maximum Response Time
                    // Bytes 2-3: Checksum
                    // Bytes 4-7: Group Address
                    let max_resp_time = data[1];
                    let checksum = u16::from_be_bytes([data[2], data[3]]);
                    let group_address = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                    if compute_igmp_checksum(data) != 0 {
                        return Err(LayerError::InvalidHeader);
                    }
                    Ok(IgmpMessage::Query(IgmpQuery::V1V2 {
                        typ,
                        max_resp_time,
                        checksum,
                        group_address,
                    }))
                }
                // For IGMPv3, the query message is longer.
                else if data.len() >= 13 {
                    // Layout:
                    // Byte 0: Type (0x11)
                    // Byte 1: Maximum Response Code
                    // Bytes 2-3: Checksum
                    // Bytes 4-7: Group Address
                    // Byte 8: Reserved
                    // Byte 9: S flag and QRV (S flag in bit 7, QRV in lower 3 bits)
                    // Byte 10: QQIC
                    // Bytes 11-12: Number of Sources (16-bit)
                    // Bytes 13...: Source Addresses (4 bytes each)
                    let max_resp_code = data[1];
                    let checksum = u16::from_be_bytes([data[2], data[3]]);
                    let group_address = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                    // Skip byte 8 (Reserved).
                    let s_flag = (data[9] & 0x80) != 0;
                    let qrv = data[9] & 0x07;
                    let qqic = data[10];
                    let num_sources = u16::from_be_bytes([data[11], data[12]]);
                    let expected_len = 13 + (num_sources as usize) * 4;
                    if data.len() < expected_len {
                        return Err(LayerError::InvalidLength);
                    }
                    let mut source_addresses = Vec::with_capacity(num_sources as usize);
                    for i in 0..num_sources {
                        let start = 13 + (i as usize) * 4;
                        let addr = Ipv4Addr::new(
                            data[start],
                            data[start + 1],
                            data[start + 2],
                            data[start + 3],
                        );
                        source_addresses.push(addr);
                    }
                    if compute_igmp_checksum(data) != 0 {
                        return Err(LayerError::InvalidHeader);
                    }
                    Ok(IgmpMessage::Query(IgmpQuery::V3 {
                        typ,
                        max_resp_code,
                        checksum,
                        group_address,
                        s_flag,
                        qrv,
                        qqic,
                        num_sources,
                        source_addresses,
                    }))
                } else {
                    Err(LayerError::InvalidLength)
                }
            }
            0x12 => {
                // IGMPv1 Membership Report (8 bytes)
                if data.len() < 8 {
                    return Err(LayerError::InvalidLength);
                }
                let checksum = u16::from_be_bytes([data[2], data[3]]);
                let group_address = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                if compute_igmp_checksum(data) != 0 {
                    return Err(LayerError::InvalidHeader);
                }
                Ok(IgmpMessage::Report(IgmpReport::V1 {
                    typ,
                    checksum,
                    group_address,
                }))
            }
            0x16 => {
                // IGMPv2 Membership Report (8 bytes)
                if data.len() < 8 {
                    return Err(LayerError::InvalidLength);
                }
                let checksum = u16::from_be_bytes([data[2], data[3]]);
                let group_address = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                if compute_igmp_checksum(data) != 0 {
                    return Err(LayerError::InvalidHeader);
                }
                Ok(IgmpMessage::Report(IgmpReport::V2 {
                    typ,
                    checksum,
                    group_address,
                }))
            }
            0x17 => {
                // IGMPv2 Leave Group (8 bytes)
                if data.len() < 8 {
                    return Err(LayerError::InvalidLength);
                }
                let checksum = u16::from_be_bytes([data[2], data[3]]);
                let group_address = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                if compute_igmp_checksum(data) != 0 {
                    return Err(LayerError::InvalidHeader);
                }
                Ok(IgmpMessage::LeaveGroup {
                    typ,
                    checksum,
                    group_address,
                })
            }
            0x22 => {
                // IGMPv3 Membership Report.
                // Layout:
                // Byte 0: Type (0x22)
                // Byte 1: Reserved
                // Bytes 2-3: Checksum
                // Bytes 4-5: Reserved
                // Bytes 6-7: Number of Group Records (M)
                // Then for each group record:
                //   1 byte: Record Type
                //   1 byte: Aux Data Len (in 32-bit words)
                //   2 bytes: Number of Sources
                //   4 bytes: Multicast Address
                //   (Num Sources * 4 bytes): Source Addresses
                //   (Aux Data Len * 4 bytes): Auxiliary Data
                if data.len() < 8 {
                    return Err(LayerError::InvalidLength);
                }
                let reserved = data[1];
                let checksum = u16::from_be_bytes([data[2], data[3]]);
                let num_group_records = u16::from_be_bytes([data[6], data[7]]);
                let mut offset = 8;
                let mut group_records = Vec::with_capacity(num_group_records as usize);
                for _ in 0..num_group_records {
                    // Each group record must have at least 8 bytes (header for the record).
                    if offset + 8 > data.len() {
                        return Err(LayerError::InvalidLength);
                    }
                    let record_type = data[offset];
                    let aux_data_len = data[offset + 1];
                    let num_sources = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                    let multicast_address = Ipv4Addr::new(
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    );
                    offset += 8;
                    let sources_len = (num_sources as usize) * 4;
                    if offset + sources_len > data.len() {
                        return Err(LayerError::InvalidLength);
                    }
                    let mut source_addresses = Vec::with_capacity(num_sources as usize);
                    for i in 0..num_sources {
                        let start = offset + (i as usize) * 4;
                        let addr = Ipv4Addr::new(
                            data[start],
                            data[start + 1],
                            data[start + 2],
                            data[start + 3],
                        );
                        source_addresses.push(addr);
                    }
                    offset += sources_len;
                    let aux_len = (aux_data_len as usize) * 4;
                    if offset + aux_len > data.len() {
                        return Err(LayerError::InvalidLength);
                    }
                    let aux_data = data[offset..offset + aux_len].to_vec();
                    offset += aux_len;
                    group_records.push(IgmpGroupRecord {
                        record_type,
                        aux_data_len,
                        num_sources,
                        multicast_address,
                        source_addresses,
                        aux_data,
                    });
                }
                if compute_igmp_checksum(data) != 0 {
                    return Err(LayerError::InvalidHeader);
                }
                Ok(IgmpMessage::Report(IgmpReport::V3 {
                    typ,
                    reserved,
                    checksum,
                    num_group_records,
                    group_records,
                }))
            }
            _ => Err(LayerError::UnsupportedProtocol(typ)),
        }
    }

    fn can_parse(&self, packet: &Packet) -> bool {
        // IGMP v2 packets are 8 bytes, v3 packets are longer
        if packet.packet.len() < 8 {
            return false;
        }

        // Check IGMP type (common types: 0x11, 0x12, 0x16, 0x17, 0x22)
        let igmp_type = packet.packet[0];
        matches!(igmp_type, 0x11 | 0x12 | 0x16 | 0x17 | 0x22)
    }

    fn is_valid(&self, packet: &Packet) -> bool {
        if packet.packet.len() < 8 {
            return false;
        }

        // Verify IGMP checksum
        let mut sum = 0u32;
        for i in (0..packet.packet.len()).step_by(2) {
            let word = if i + 1 < packet.packet.len() {
                u16::from_be_bytes([packet.packet[i], packet.packet[i + 1]])
            } else {
                u16::from_be_bytes([packet.packet[i], 0])
            } as u32;
            sum += word;
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum == 0xFFFF
    }
}

/// Computes the IGMP checksum over the entire IGMP message.
/// The checksum is the one's complement of the one's complement sum of all 16-bit words.
/// For an odd-length message, the last byte is padded with zero.
fn compute_igmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(word);
    }
    if let Some(&rem) = chunks.remainder().first() {
        // Pad the remaining byte as the high-order byte.
        sum = sum.wrapping_add((rem as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    /// Constructs an IGMPv1/v2 Query payload (8 bytes).
    fn create_igmp_query_v1v2_payload(
        max_resp_time: u8,
        group_address: Ipv4Addr,
        typ: u8,
    ) -> Vec<u8> {
        let mut payload = vec![
            typ,
            max_resp_time,
            0,
            0, // Checksum placeholder.
            group_address.octets()[0],
            group_address.octets()[1],
            group_address.octets()[2],
            group_address.octets()[3],
        ];
        let chk = compute_igmp_checksum(&payload);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        // Ensure checksum is correct.
        assert_eq!(compute_igmp_checksum(&payload), 0);
        payload
    }

    /// Constructs an IGMPv3 Query payload with a list of source addresses.
    fn create_igmp_query_v3_payload(
        max_resp_code: u8,
        group_address: Ipv4Addr,
        s_flag: bool,
        qrv: u8,
        qqic: u8,
        source_addresses: Vec<Ipv4Addr>,
    ) -> Vec<u8> {
        let num_sources = source_addresses.len() as u16;
        let mut payload = vec![
            0x11, // Type.
            max_resp_code,
            0,
            0, // Checksum placeholder.
        ];
        payload.extend_from_slice(&group_address.octets());
        payload.push(0); // Reserved.
        let s_qrv = if s_flag {
            0x80 | (qrv & 0x07)
        } else {
            qrv & 0x07
        };
        payload.push(s_qrv);
        payload.push(qqic);
        payload.extend_from_slice(&num_sources.to_be_bytes());
        for addr in &source_addresses {
            payload.extend_from_slice(&addr.octets());
        }
        let chk = compute_igmp_checksum(&payload);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        assert_eq!(compute_igmp_checksum(&payload), 0);
        payload
    }

    /// Constructs an IGMPv1 Membership Report payload.
    fn create_igmp_report_v1_payload(group_address: Ipv4Addr) -> Vec<u8> {
        let typ = 0x12;
        let mut payload = vec![
            typ, 0, // Unused.
            0, 0, // Checksum placeholder.
        ];
        payload.extend_from_slice(&group_address.octets());
        let chk = compute_igmp_checksum(&payload);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        assert_eq!(compute_igmp_checksum(&payload), 0);
        payload
    }

    /// Constructs an IGMPv2 Membership Report payload.
    fn create_igmp_report_v2_payload(group_address: Ipv4Addr) -> Vec<u8> {
        let typ = 0x16;
        let mut payload = vec![typ, 0, 0, 0];
        payload.extend_from_slice(&group_address.octets());
        let chk = compute_igmp_checksum(&payload);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        assert_eq!(compute_igmp_checksum(&payload), 0);
        payload
    }

    /// Constructs an IGMPv2 Leave Group payload.
    fn create_igmp_leave_group_payload(group_address: Ipv4Addr) -> Vec<u8> {
        let typ = 0x17;
        let mut payload = vec![typ, 0, 0, 0];
        payload.extend_from_slice(&group_address.octets());
        let chk = compute_igmp_checksum(&payload);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        assert_eq!(compute_igmp_checksum(&payload), 0);
        payload
    }

    /// Constructs an IGMPv3 Membership Report payload with a single group record.
    fn create_igmp_report_v3_payload(record: IgmpGroupRecord) -> Vec<u8> {
        let typ = 0x22;
        let reserved: u8 = 0;
        // Header: Type, Reserved, Checksum placeholder, Reserved (2 bytes), Number of Group Records.
        let mut payload = vec![
            typ, reserved, 0, 0, // Checksum placeholder.
            0, 0, // Reserved.
        ];
        let num_group_records: u16 = 1;
        payload.extend_from_slice(&num_group_records.to_be_bytes());
        // Group Record:
        payload.push(record.record_type);
        payload.push(record.aux_data_len);
        payload.extend_from_slice(&record.num_sources.to_be_bytes());
        payload.extend_from_slice(&record.multicast_address.octets());
        for addr in &record.source_addresses {
            payload.extend_from_slice(&addr.octets());
        }
        payload.extend_from_slice(&record.aux_data);
        let chk = compute_igmp_checksum(&payload);
        payload[2] = (chk >> 8) as u8;
        payload[3] = (chk & 0xff) as u8;
        assert_eq!(compute_igmp_checksum(&payload), 0);
        payload
    }

    #[test]
    fn test_parse_igmp_query_v1v2() {
        let group_addr = Ipv4Addr::new(224, 0, 0, 1);
        let payload = create_igmp_query_v1v2_payload(10, group_addr, 0x11);
        let mut packet = Packet::new(payload);
        let processor = IgmpProcessor;
        let msg = processor
            .parse(&mut packet)
            .expect("Should parse IGMP query v1/v2");
        match msg {
            IgmpMessage::Query(IgmpQuery::V1V2 {
                typ,
                max_resp_time,
                checksum: _,
                group_address,
            }) => {
                assert_eq!(typ, 0x11);
                assert_eq!(max_resp_time, 10);
                assert_eq!(group_address, group_addr);
            }
            _ => panic!("Expected IGMP query v1/v2"),
        }
    }

    #[test]
    fn test_parse_igmp_query_v3() {
        let group_addr = Ipv4Addr::new(224, 0, 0, 1);
        let source_addrs = vec![
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 101),
        ];
        let payload =
            create_igmp_query_v3_payload(20, group_addr, true, 3, 100, source_addrs.clone());
        let mut packet = Packet::new(payload);
        let processor = IgmpProcessor;
        let msg = processor
            .parse(&mut packet)
            .expect("Should parse IGMP query v3");
        match msg {
            IgmpMessage::Query(IgmpQuery::V3 {
                typ,
                max_resp_code,
                checksum: _,
                group_address,
                s_flag,
                qrv,
                qqic,
                num_sources,
                source_addresses,
            }) => {
                assert_eq!(typ, 0x11);
                assert_eq!(max_resp_code, 20);
                assert_eq!(group_address, group_addr);
                assert!(s_flag);
                assert_eq!(qrv, 3);
                assert_eq!(qqic, 100);
                assert_eq!(num_sources, 2);
                assert_eq!(source_addresses, source_addrs);
            }
            _ => panic!("Expected IGMP query v3"),
        }
    }

    #[test]
    fn test_parse_igmp_report_v1() {
        let group_addr = Ipv4Addr::new(224, 0, 0, 1);
        let payload = create_igmp_report_v1_payload(group_addr);
        let mut packet = Packet::new(payload);
        let processor = IgmpProcessor;
        let msg = processor
            .parse(&mut packet)
            .expect("Should parse IGMP report v1");
        match msg {
            IgmpMessage::Report(IgmpReport::V1 {
                typ,
                checksum: _,
                group_address,
            }) => {
                assert_eq!(typ, 0x12);
                assert_eq!(group_address, group_addr);
            }
            _ => panic!("Expected IGMP report v1"),
        }
    }

    #[test]
    fn test_parse_igmp_report_v2() {
        let group_addr = Ipv4Addr::new(224, 0, 0, 1);
        let payload = create_igmp_report_v2_payload(group_addr);
        let mut packet = Packet::new(payload);
        let processor = IgmpProcessor;
        let msg = processor
            .parse(&mut packet)
            .expect("Should parse IGMP report v2");
        match msg {
            IgmpMessage::Report(IgmpReport::V2 {
                typ,
                checksum: _,
                group_address,
            }) => {
                assert_eq!(typ, 0x16);
                assert_eq!(group_address, group_addr);
            }
            _ => panic!("Expected IGMP report v2"),
        }
    }

    #[test]
    fn test_parse_igmp_leave_group() {
        let group_addr = Ipv4Addr::new(224, 0, 0, 2);
        let payload = create_igmp_leave_group_payload(group_addr);
        let mut packet = Packet::new(payload);
        let processor = IgmpProcessor;
        let msg = processor
            .parse(&mut packet)
            .expect("Should parse IGMP leave group");
        match msg {
            IgmpMessage::LeaveGroup {
                typ,
                checksum: _,
                group_address,
            } => {
                assert_eq!(typ, 0x17);
                assert_eq!(group_address, group_addr);
            }
            _ => panic!("Expected IGMP leave group"),
        }
    }

    #[test]
    fn test_parse_igmp_report_v3() {
        let group_addr = Ipv4Addr::new(224, 0, 0, 1);
        let record = IgmpGroupRecord {
            record_type: 1,
            aux_data_len: 0,
            num_sources: 1,
            multicast_address: group_addr,
            source_addresses: vec![Ipv4Addr::new(192, 168, 1, 200)],
            aux_data: vec![],
        };
        let payload = create_igmp_report_v3_payload(record);
        let mut packet = Packet::new(payload);
        let processor = IgmpProcessor;
        let msg = processor
            .parse(&mut packet)
            .expect("Should parse IGMP report v3");
        match msg {
            IgmpMessage::Report(IgmpReport::V3 {
                typ,
                reserved: _,
                checksum: _,
                num_group_records,
                group_records,
            }) => {
                assert_eq!(typ, 0x22);
                assert_eq!(num_group_records, 1);
                assert_eq!(group_records.len(), 1);
                let rec = &group_records[0];
                assert_eq!(rec.record_type, 1);
                assert_eq!(rec.num_sources, 1);
                assert_eq!(rec.multicast_address, group_addr);
                assert_eq!(rec.source_addresses[0], Ipv4Addr::new(192, 168, 1, 200));
            }
            _ => panic!("Expected IGMP report v3"),
        }
    }

    #[test]
    fn test_igmp_can_parse_valid() {
        // Create a valid IGMP v1/v2 Query payload (8 bytes) using the helper.
        let group_addr = Ipv4Addr::new(224, 0, 0, 1);
        let payload = create_igmp_query_v1v2_payload(10, group_addr, 0x11);
        let packet = Packet::new(payload);
        let processor = IgmpProcessor;
        assert!(processor.can_parse(&packet));
    }

    #[test]
    fn test_igmp_can_parse_invalid_short() {
        // Provide a packet that is too short to be an IGMP message.
        let packet = Packet::new(vec![0x11, 0x00, 0x00]); // Only 3 bytes.
        let processor = IgmpProcessor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_igmp_can_parse_invalid_type() {
        // Create a valid packet then change the IGMP type to an unsupported value.
        let mut payload = create_igmp_query_v1v2_payload(10, Ipv4Addr::new(224, 0, 0, 1), 0x11);
        payload[0] = 0x99; // Change type to an unsupported value.
        let packet = Packet::new(payload);
        let processor = IgmpProcessor;
        assert!(!processor.can_parse(&packet));
    }

    #[test]
    fn test_igmp_is_valid_valid() {
        // Use the helper to create a valid IGMP query (checksum computed correctly).
        let group_addr = Ipv4Addr::new(224, 0, 0, 1);
        let payload = create_igmp_query_v1v2_payload(10, group_addr, 0x11);
        let packet = Packet::new(payload);
        let processor = IgmpProcessor;
        assert!(processor.is_valid(&packet));
    }

    #[test]
    fn test_igmp_is_valid_invalid_checksum() {
        // Create a packet with a valid IGMP header then modify a byte to break its checksum.
        let group_addr = Ipv4Addr::new(224, 0, 0, 1);
        let mut payload = create_igmp_query_v1v2_payload(10, group_addr, 0x11);
        // Alter one byte (e.g., in the group address) so that the checksum calculation fails.
        payload[7] ^= 0xFF;
        let packet = Packet::new(payload);
        let processor = IgmpProcessor;
        assert!(!processor.is_valid(&packet));
    }
}
