pub mod dns;

use crate::layer::transport::TransportInfo;
use crate::layer::{LayerError, ProtocolProcessor};
use crate::packet::Packet;

/// Application layer data types
#[derive(Debug)]
pub enum ApplicationData {
    Dns(dns::DnsMessage),
    // Add other application protocols here
    Unknown,
}

/// Application layer processor
pub struct ApplicationProcessor;

impl ApplicationProcessor {
    /// Process a packet at the application layer based on transport info
    pub fn process_with_info(
        &self,
        packet: &mut Packet,
        transport_info: Option<&TransportInfo>,
    ) -> Result<ApplicationData, LayerError> {
        if let Some(transport) = transport_info {
            let port = transport.destination_port();

            // DNS - Port 53
            if port == 53 {
                let dns_processor = dns::DnsProcessor;
                if dns_processor.can_parse(packet) {
                    if let Ok(dns_message) = dns_processor.parse(packet) {
                        return Ok(ApplicationData::Dns(dns_message));
                    }
                }
            }

            // Add other application protocols here based on port numbers
        }

        // Default case if no specific protocol is detected
        Ok(ApplicationData::Unknown)
    }
}
