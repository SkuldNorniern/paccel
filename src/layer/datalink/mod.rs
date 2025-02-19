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
        let arp_processor = ArpProcessor;
        let arp_packet = arp_processor.parse(packet)?;
        Ok(())
    }
}