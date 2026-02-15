//! The datalink layer (Layer 2) modules.
//! This layer handles protocols like Ethernet and ARP.
//! Currently, we support ARP for IPv4 over Ethernet.

pub mod arp;

use arp::ArpProcessor;

use super::{LayerProcessor, ProtocolProcessor};
use crate::packet::Packet;
use crate::LayerError;

pub struct DatalinkProcessor;

impl LayerProcessor for DatalinkProcessor {
    fn process(&self, packet: &mut Packet) -> Result<(), LayerError> {
        if packet.packet.len() < 14 {
            return Err(LayerError::InvalidLength);
        }

        let ethertype = u16::from_be_bytes([packet.packet[12], packet.packet[13]]);
        packet.payload = packet.packet[14..].to_vec();

        if ethertype != 0x0806 {
            return Ok(());
        }

        let arp_processor = ArpProcessor;
        let mut arp_packet_view = Packet::new(packet.payload.clone());
        let _arp_packet = arp_processor.parse(&mut arp_packet_view)?;
        Ok(())
    }
}
