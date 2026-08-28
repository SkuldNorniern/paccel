use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

use crate::layer::LayerError;

/// DNS header (the first 12 message bytes).
#[derive(Debug)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authorities: u16,
    pub additionals: u16,
}

/// A DNS question: queried name, query type, query class. `qname` is owned
/// since DNS labels are non-contiguous in the wire format.
#[derive(Debug)]
pub struct DnsQuestion {
    // TODO: borrow `qname` instead of allocating a `String`.
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// DNS resource record.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

/// Decoded data from a DNS resource record.
#[derive(Debug, PartialEq, Eq)]
pub enum DnsData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ns(String),
    Ptr(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Opt {
        udp_payload_size: u16,
        ext_rcode: u8,
        version: u8,
        flags: u16,
    },
    Other {
        rtype: u16,
        data: Vec<u8>,
    },
}

/// Alternate name for decoded DNS resource record data.
pub type DnsRdata = DnsData;

/// A parsed DNS message: header, questions, answers, authority and
/// additional records.
#[derive(Debug)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

/// Parses a DNS message. Used by the engine path.
pub fn parse_dns_message(packet: &[u8]) -> Result<DnsMessage, LayerError> {
    if packet.len() < 12 {
        return Err(LayerError::InvalidLength);
    }

    let id = u16::from_be_bytes(
        packet[0..2]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    let flags = u16::from_be_bytes(
        packet[2..4]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    let qdcount = u16::from_be_bytes(
        packet[4..6]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    let ancount = u16::from_be_bytes(
        packet[6..8]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    let nscount = u16::from_be_bytes(
        packet[8..10]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    let arcount = u16::from_be_bytes(
        packet[10..12]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );

    let header = DnsHeader {
        transaction_id: id,
        flags,
        questions: qdcount,
        answers: ancount,
        authorities: nscount,
        additionals: arcount,
    };

    let mut offset = 12;
    // A question needs at least one root-name byte, plus qtype and qclass.
    let question_capacity = (header.questions as usize).min((packet.len() - 12) / 5);
    let mut questions = Vec::with_capacity(question_capacity);
    for _ in 0..header.questions {
        let (question, new_offset) = parse_question(packet, offset)?;
        questions.push(question);
        offset = new_offset;
    }

    let (answers, new_offset) = parse_records(packet, offset, header.answers)?;
    offset = new_offset;
    let (authorities, new_offset) = parse_records(packet, offset, header.authorities)?;
    offset = new_offset;
    let (additionals, _) = parse_records(packet, offset, header.additionals)?;

    Ok(DnsMessage {
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

/// Parses an RFC 1035 name, following compression pointers. Returns the name
/// and its end offset.
///
/// # Errors
/// Returns `InvalidLength` for truncated data or `MalformedPacket` for an
/// invalid name.
fn parse_domain_name(packet: &[u8], mut pos: usize) -> Result<(String, usize), LayerError> {
    let mut name = String::new();
    let mut jumped = false;
    let mut pointer_end: Option<usize> = None;
    let mut iterations = 0;
    let max_iterations = packet.len();
    let mut encoded_len = 0;

    loop {
        if iterations > max_iterations {
            return Err(LayerError::MalformedPacket);
        }
        if pos >= packet.len() {
            return Err(LayerError::InvalidLength);
        }

        let len = packet[pos];
        // Zero length ends the domain name.
        if len == 0 {
            encoded_len += 1;
            if encoded_len > 255 {
                return Err(LayerError::MalformedPacket);
            }
            pos += 1;
            break;
        }

        // RFC 1035 limits labels to 63 bytes.
        if len > 63 && (len & 0xC0) != 0xC0 {
            return Err(LayerError::MalformedPacket);
        }

        // Compression pointers have the high bits 0xC0.
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= packet.len() {
                return Err(LayerError::InvalidLength);
            }
            // A compression pointer occupies two bytes.
            let b2 = packet[pos + 1];
            let pointer_offset = (((len & 0x3F) as usize) << 8) | (b2 as usize);

            // Validate pointer offset
            if pointer_offset >= pos {
                return Err(LayerError::MalformedPacket); // Forward references are invalid
            }

            // Preserve the resume offset across the first jump.
            if !jumped {
                pointer_end = Some(pos + 2);
            }
            pos = pointer_offset;
            jumped = true;
            iterations += 1;
            continue;
        }

        // Regular label: length followed by label bytes.
        let label_len = len as usize;
        encoded_len += label_len + 1;
        if encoded_len > 255 {
            return Err(LayerError::MalformedPacket);
        }
        pos += 1;
        if pos + label_len > packet.len() {
            return Err(LayerError::InvalidLength);
        }

        let label_bytes = &packet[pos..pos + label_len];
        // DNS labels are ASCII.
        let label = str::from_utf8(label_bytes).map_err(|_| LayerError::MalformedPacket)?;

        // Validate label characters (letters, digits, hyphens, and underscores only)
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(LayerError::MalformedPacket);
        }

        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        pos += label_len;
        iterations += 1;
    }

    // After a jump, resume after the original pointer.
    let final_pos = if jumped {
        pointer_end.ok_or(LayerError::MalformedPacket)?
    } else {
        pos
    };

    Ok((name, final_pos))
}

/// Parses a DNS question at `pos`.
///
/// Questions contain a name, 2-byte type, and 2-byte class.
///
/// # Errors
/// Returns an error for truncated or malformed fields.
fn parse_question(packet: &[u8], pos: usize) -> Result<(DnsQuestion, usize), LayerError> {
    let (qname, pos) = parse_domain_name(packet, pos)?;
    if pos + 4 > packet.len() {
        return Err(LayerError::InvalidLength);
    }
    let qtype = u16::from_be_bytes(
        packet[pos..pos + 2]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    let qclass = u16::from_be_bytes(
        packet[pos + 2..pos + 4]
            .try_into()
            .map_err(|_| LayerError::MalformedPacket)?,
    );
    Ok((
        DnsQuestion {
            qname,
            qtype,
            qclass,
        },
        pos + 4,
    ))
}

fn parse_records(
    packet: &[u8],
    mut offset: usize,
    count: u16,
) -> Result<(Vec<DnsRecord>, usize), LayerError> {
    let remaining = packet.len().saturating_sub(offset);
    let capacity = (count as usize).min(remaining / 11);
    let mut records = Vec::with_capacity(capacity);

    for _ in 0..count {
        let (record, new_offset) = parse_record(packet, offset)?;
        records.push(record);
        offset = new_offset;
    }

    Ok((records, offset))
}

/// Parses a DNS resource record at `pos`.
fn parse_record(packet: &[u8], pos: usize) -> Result<(DnsRecord, usize), LayerError> {
    let (name, pos) = parse_domain_name(packet, pos)?;
    let fields_end = pos.checked_add(10).ok_or(LayerError::InvalidLength)?;
    if fields_end > packet.len() {
        return Err(LayerError::InvalidLength);
    }

    let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let rclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    let ttl = u32::from_be_bytes([
        packet[pos + 4],
        packet[pos + 5],
        packet[pos + 6],
        packet[pos + 7],
    ]);
    let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
    let rdata_end = fields_end
        .checked_add(rdlength)
        .ok_or(LayerError::InvalidLength)?;
    if rdata_end > packet.len() {
        return Err(LayerError::InvalidLength);
    }

    let rdata =
        parse_rdata(packet, fields_end, rdata_end, rtype, rclass, ttl).unwrap_or_else(|| {
            DnsData::Other {
                rtype,
                data: packet[fields_end..rdata_end].to_vec(),
            }
        });

    Ok((
        DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        rdata_end,
    ))
}

fn parse_rdata(
    packet: &[u8],
    start: usize,
    end: usize,
    rtype: u16,
    rclass: u16,
    ttl: u32,
) -> Option<DnsData> {
    match rtype {
        1 if end - start == 4 => Some(DnsData::A(Ipv4Addr::new(
            packet[start],
            packet[start + 1],
            packet[start + 2],
            packet[start + 3],
        ))),
        28 if end - start == 16 => {
            let bytes: [u8; 16] = packet[start..end].try_into().ok()?;
            Some(DnsData::Aaaa(Ipv6Addr::from(bytes)))
        }
        5 => parse_rdata_name(packet, start, end).map(DnsData::Cname),
        2 => parse_rdata_name(packet, start, end).map(DnsData::Ns),
        12 => parse_rdata_name(packet, start, end).map(DnsData::Ptr),
        15 => {
            let mut pos = start;
            let preference = read_u16(packet, &mut pos, end)?;
            let exchange = parse_rdata_name(packet, pos, end)?;
            Some(DnsData::Mx {
                preference,
                exchange,
            })
        }
        16 => parse_txt(packet, start, end).map(DnsData::Txt),
        6 => parse_soa(packet, start, end),
        33 => parse_srv(packet, start, end),
        41 => {
            let ttl_bytes = ttl.to_be_bytes();
            Some(DnsData::Opt {
                udp_payload_size: rclass,
                ext_rcode: ttl_bytes[0],
                version: ttl_bytes[1],
                flags: u16::from_be_bytes([ttl_bytes[2], ttl_bytes[3]]),
            })
        }
        _ => None,
    }
}

fn parse_rdata_name(packet: &[u8], pos: usize, end: usize) -> Option<String> {
    let (name, new_pos) = parse_name_within(packet, pos, end)?;
    (new_pos == end).then_some(name)
}

fn parse_name_within(packet: &[u8], pos: usize, end: usize) -> Option<(String, usize)> {
    let mut encoded_end = pos;
    loop {
        if encoded_end >= end {
            return None;
        }
        let length = packet[encoded_end];
        encoded_end += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 == 0xc0 {
            encoded_end = encoded_end.checked_add(1)?;
            if encoded_end > end {
                return None;
            }
            break;
        }
        if length > 63 {
            return None;
        }
        encoded_end = encoded_end.checked_add(length as usize)?;
        if encoded_end > end {
            return None;
        }
    }

    let (name, new_pos) = parse_domain_name(packet, pos).ok()?;
    (new_pos == encoded_end).then_some((name, new_pos))
}

fn parse_txt(packet: &[u8], mut pos: usize, end: usize) -> Option<Vec<String>> {
    let mut strings = Vec::new();
    while pos < end {
        let length = *packet.get(pos)? as usize;
        pos += 1;
        let string_end = pos.checked_add(length)?;
        if string_end > end {
            return None;
        }
        strings.push(str::from_utf8(&packet[pos..string_end]).ok()?.to_owned());
        pos = string_end;
    }
    Some(strings)
}

fn parse_soa(packet: &[u8], start: usize, end: usize) -> Option<DnsData> {
    let (mname, mut pos) = parse_name_within(packet, start, end)?;
    let (rname, new_pos) = parse_name_within(packet, pos, end)?;
    pos = new_pos;
    let serial = read_u32(packet, &mut pos, end)?;
    let refresh = read_u32(packet, &mut pos, end)?;
    let retry = read_u32(packet, &mut pos, end)?;
    let expire = read_u32(packet, &mut pos, end)?;
    let minimum = read_u32(packet, &mut pos, end)?;
    if pos != end {
        return None;
    }
    Some(DnsData::Soa {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    })
}

fn parse_srv(packet: &[u8], start: usize, end: usize) -> Option<DnsData> {
    let mut pos = start;
    let priority = read_u16(packet, &mut pos, end)?;
    let weight = read_u16(packet, &mut pos, end)?;
    let port = read_u16(packet, &mut pos, end)?;
    let target = parse_rdata_name(packet, pos, end)?;
    Some(DnsData::Srv {
        priority,
        weight,
        port,
        target,
    })
}

fn read_u16(packet: &[u8], pos: &mut usize, end: usize) -> Option<u16> {
    let field_end = pos.checked_add(2)?;
    if field_end > end {
        return None;
    }
    let value = u16::from_be_bytes([packet[*pos], packet[*pos + 1]]);
    *pos = field_end;
    Some(value)
}

fn read_u32(packet: &[u8], pos: &mut usize, end: usize) -> Option<u32> {
    let field_end = pos.checked_add(4)?;
    if field_end > end {
        return None;
    }
    let value = u32::from_be_bytes([
        packet[*pos],
        packet[*pos + 1],
        packet[*pos + 2],
        packet[*pos + 3],
    ]);
    *pos = field_end;
    Some(value)
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_n;

    use super::*;

    /// Builds a valid DNS query packet.
    fn create_test_dns_query() -> Vec<u8> {
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Question section: "www.example.com" Type A, Class IN
            0x03, b'w', b'w', b'w', // First label: "www"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // Second label: "example"
            0x03, b'c', b'o', b'm', // Third label: "com"
            0x00, // End of name
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        packet
    }

    /// Builds a valid DNS response packet.
    fn create_test_dns_response() -> Vec<u8> {
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags (standard response)
            0x00, 0x01, // Questions: 1
            0x00, 0x01, // Answer RRs: 1
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Question section (same as query)
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            // Answer section
            0xc0, 0x0c, // Name pointer to offset 12
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x0e, 0x10, // TTL: 3600
            0x00, 0x04, // Data length: 4
            0xc0, 0xa8, 0x01, 0x01, // IP: 192.168.1.1
        ];
        packet
    }

    fn append_name(packet: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            packet.push(u8::try_from(label.len()).expect("test label fits in a byte"));
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
    }

    fn append_record(
        packet: &mut Vec<u8>,
        name: &str,
        rtype: u16,
        rclass: u16,
        ttl: u32,
        rdata: &[u8],
    ) {
        if name.is_empty() {
            packet.push(0);
        } else {
            append_name(packet, name);
        }
        packet.extend_from_slice(&rtype.to_be_bytes());
        packet.extend_from_slice(&rclass.to_be_bytes());
        packet.extend_from_slice(&ttl.to_be_bytes());
        packet.extend_from_slice(
            &u16::try_from(rdata.len())
                .expect("test rdata fits in a DNS record")
                .to_be_bytes(),
        );
        packet.extend_from_slice(rdata);
    }

    fn create_multi_record_response() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags (standard response)
            0x00, 0x00, // Questions: 0
            0x00, 0x05, // Answer RRs: 5
            0x00, 0x01, // Authority RRs: 1
            0x00, 0x01, // Additional RRs: 1
        ];

        let mut cname = Vec::new();
        append_name(&mut cname, "alias.example");
        append_record(&mut packet, "www.example", 5, 1, 300, &cname);

        let mut mx = 10_u16.to_be_bytes().to_vec();
        append_name(&mut mx, "mail.example");
        append_record(&mut packet, "example", 15, 1, 300, &mx);

        let txt = [
            5, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd',
        ];
        append_record(&mut packet, "example", 16, 1, 300, &txt);

        let mut srv = Vec::new();
        srv.extend_from_slice(&1_u16.to_be_bytes());
        srv.extend_from_slice(&2_u16.to_be_bytes());
        srv.extend_from_slice(&443_u16.to_be_bytes());
        append_name(&mut srv, "service.example");
        append_record(&mut packet, "_https._tcp.example", 33, 1, 300, &srv);

        let address = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        append_record(&mut packet, "ipv6.example", 28, 1, 300, &address.octets());

        let mut soa = Vec::new();
        append_name(&mut soa, "ns.example");
        append_name(&mut soa, "hostmaster.example");
        for value in 1_u32..=5 {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        append_record(&mut packet, "example", 6, 1, 300, &soa);

        append_record(&mut packet, "", 41, 1232, 0x0100_8000, &[]);
        packet
    }

    #[test]
    fn test_parse_valid_query() {
        let packet = create_test_dns_query();
        let result = parse_dns_message(&packet);
        assert!(result.is_ok());

        if let Ok(dns_msg) = result {
            assert_eq!(dns_msg.header.transaction_id, 0x1234);
            assert_eq!(dns_msg.header.questions, 1);
            assert_eq!(dns_msg.questions.len(), 1);
            assert_eq!(dns_msg.questions[0].qname, "www.example.com");
            assert_eq!(dns_msg.questions[0].qtype, 1); // A record
            assert_eq!(dns_msg.questions[0].qclass, 1); // IN class
        }
    }

    #[test]
    fn test_parse_query_with_underscore_labels() {
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            0x06, b'_', b'd', b'n', b's', b's', b'd', // First label: "_dnssd"
            0x04, b'_', b'u', b'd', b'p', // Second label: "_udp"
            0x05, b'l', b'o', b'c', b'a', b'l', // Third label: "local"
            0x00, // End of name
            0x00, 0x0c, // Type: PTR
            0x00, 0x01, // Class: IN
        ];

        let result = parse_dns_message(&packet);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().questions[0].qname, "_dnssd._udp.local");
    }

    #[test]
    fn test_parse_name_exceeding_encoded_length_limit() {
        let mut packet = Vec::new();
        for label in *b"abcd" {
            packet.push(63);
            packet.extend(repeat_n(label, 63));
        }
        packet.push(0);

        let result = parse_domain_name(&packet, 0);

        assert!(matches!(result, Err(LayerError::MalformedPacket)));
    }

    #[test]
    fn test_parse_valid_response() {
        let packet = create_test_dns_response();
        let result = parse_dns_message(&packet);
        assert!(result.is_ok());

        if let Ok(dns_msg) = result {
            assert_eq!(dns_msg.header.transaction_id, 0x1234);
            assert_eq!(dns_msg.header.questions, 1);
            assert_eq!(dns_msg.header.answers, 1);
            assert_eq!(dns_msg.questions.len(), 1);
            assert_eq!(dns_msg.questions[0].qname, "www.example.com");
            assert_eq!(dns_msg.answers.len(), 1);
            assert_eq!(
                dns_msg.answers[0].rdata,
                DnsData::A(Ipv4Addr::new(192, 168, 1, 1))
            );
        }
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_parse_common_resource_records_and_edns() {
        let message = parse_dns_message(&create_multi_record_response()).unwrap();

        assert_eq!(message.answers.len(), 5);
        assert_eq!(
            message.answers[0].rdata,
            DnsData::Cname("alias.example".to_owned())
        );
        assert_eq!(
            message.answers[1].rdata,
            DnsData::Mx {
                preference: 10,
                exchange: "mail.example".to_owned(),
            }
        );
        assert_eq!(
            message.answers[2].rdata,
            DnsData::Txt(vec!["hello".to_owned(), "world".to_owned()])
        );
        assert_eq!(
            message.answers[3].rdata,
            DnsData::Srv {
                priority: 1,
                weight: 2,
                port: 443,
                target: "service.example".to_owned(),
            }
        );
        assert_eq!(
            message.answers[4].rdata,
            DnsData::Aaaa(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(message.authorities.len(), 1);
        assert_eq!(
            message.authorities[0].rdata,
            DnsData::Soa {
                mname: "ns.example".to_owned(),
                rname: "hostmaster.example".to_owned(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            }
        );
        assert_eq!(message.additionals.len(), 1);
        assert_eq!(message.additionals[0].name, "");
        assert_eq!(
            message.additionals[0].rdata,
            DnsData::Opt {
                udp_payload_size: 1232,
                ext_rcode: 1,
                version: 0,
                flags: 0x8000,
            }
        );
    }

    #[test]
    fn test_parse_truncated_record_rdata() {
        let mut packet = create_test_dns_response();
        let rdlength = packet.len() - 6;
        packet[rdlength..rdlength + 2].copy_from_slice(&5_u16.to_be_bytes());

        assert!(matches!(
            parse_dns_message(&packet),
            Err(LayerError::InvalidLength)
        ));
    }

    #[test]
    fn test_parse_truncated_packet() {
        let mut packet = create_test_dns_query();
        packet.truncate(20); // Truncate in the middle of question section
        let result = parse_dns_message(&packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::InvalidLength)));
    }

    #[test]
    fn test_parse_large_question_count_without_questions() {
        let mut packet = vec![0; 12];
        packet[4] = 0xff;
        packet[5] = 0xff;

        let result = parse_dns_message(&packet);
        assert!(matches!(result, Err(LayerError::InvalidLength)));
    }

    #[test]
    fn test_parse_invalid_name() {
        let mut packet = create_test_dns_query();
        // Set an invalid label length
        packet[12] = 64; // Too long for a single label
        let result = parse_dns_message(&packet);
        assert!(result.is_err());
        assert!(matches!(result, Err(LayerError::MalformedPacket)));
    }

    #[test]
    fn test_parse_compressed_name() {
        let packet = create_test_dns_response();
        let result = parse_dns_message(&packet);
        assert!(result.is_ok());
        // Compression resolves to www.example.com.
        if let Ok(dns_msg) = result {
            assert_eq!(dns_msg.questions[0].qname, "www.example.com");
        }
    }
}
