use super::{Encode, EncodeError, WriteCursor};

/// One VLAN tag: the tag protocol id that introduces it and its control
/// information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    pub tpid: u16,
    pub tci: u16,
}

impl VlanTag {
    /// An 802.1Q tag, which is the common case.
    pub fn new(vlan_id: u16) -> Self {
        Self {
            tpid: 0x8100,
            tci: vlan_id & 0x0fff,
        }
    }
}

/// An Ethernet II header, with room for QinQ.
///
/// Two tags rather than a list, because 802.1ad stacks two and a list would
/// mean either an allocation or a bound nobody asked for. Deeper stacks are
/// not encodable yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EthernetHeader {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
    pub outer_vlan: Option<VlanTag>,
    pub inner_vlan: Option<VlanTag>,
}

impl EthernetHeader {
    pub fn new(destination: [u8; 6], source: [u8; 6], ethertype: u16) -> Self {
        Self {
            destination,
            source,
            ethertype,
            outer_vlan: None,
            inner_vlan: None,
        }
    }

    fn tags(&self) -> impl Iterator<Item = VlanTag> {
        self.outer_vlan.into_iter().chain(self.inner_vlan)
    }
}

impl Encode for EthernetHeader {
    fn encoded_len(&self) -> usize {
        14 + 4 * self.tags().count()
    }

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let mut cursor = WriteCursor::new(buffer);
        cursor.write_bytes(&self.destination)?;
        cursor.write_bytes(&self.source)?;
        for tag in self.tags() {
            cursor.write_u16_be(tag.tpid)?;
            cursor.write_u16_be(tag.tci)?;
        }
        cursor.write_u16_be(self.ethertype)?;
        Ok(cursor.position())
    }
}

#[cfg(test)]
mod tests {
    use super::{Encode, EthernetHeader, VlanTag};
    use crate::engine::BuiltinPacketParser;

    /// Craft then parse: the parser is the independent check that the bytes
    /// mean what the header said.
    #[test]
    fn a_crafted_ethernet_header_parses_back() {
        let mut header = EthernetHeader::new([0xff; 6], [0x11; 6], 0x0806);
        header.outer_vlan = Some(VlanTag::new(100));
        header.inner_vlan = Some(VlanTag::new(200));

        let mut frame = header.build().expect("room");
        assert_eq!(frame.len(), header.encoded_len());
        frame.extend([0; 28]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("the frame parses");
        let eth = parsed.ethernet.as_ref().expect("the ethernet header");
        assert_eq!(eth.destination, [0xff; 6]);
        assert_eq!(eth.source, [0x11; 6]);
        assert_eq!(eth.ethertype, 0x0806);
        assert_eq!(eth.vlan_tags, vec![100, 200]);
    }

    #[test]
    fn a_short_buffer_is_refused_rather_than_truncated() {
        let header = EthernetHeader::new([0; 6], [0; 6], 0x0800);
        let mut buffer = [0u8; 13];
        assert!(header.encode_into(&mut buffer).is_err());
    }
}
