/// Represents different types of packet capture formats
#[derive(Debug, PartialEq)]
pub enum CaptureFormat {
    /// Linux Cooked Capture v1 (SLL) - 16 bytes header
    LinuxCookedV1,
    /// Ethernet II - 14 bytes header
    EthernetII,
}

/// Represents the header offset information for different capture formats
#[derive(Debug)]
pub struct CaptureInfo {
    /// The format of the captured packet
    pub format: CaptureFormat,
    /// Offset to the network layer (e.g., IPv4, IPv6)
    pub network_offset: usize,
}

impl CaptureInfo {
    /// Detects the capture format and returns appropriate header information
    pub fn detect(packet: &[u8]) -> Result<Self, &'static str> {
        // Minimum length check - at least need enough bytes to determine format
        if packet.len() < 14 {
            return Err("Packet too short to determine format");
        }

        // Check for Linux Cooked Capture v1 [Tipically used on Linux Devices]
        // First 2 bytes are packet type: 0x0000 (unicast to us) or 0x0004 (sent by us)
        if (packet[0] == 0x00 && (packet[1] == 0x00 || packet[1] == 0x04)) &&
           // Link-layer address length is at offset 4-5, typically 0x0006
           packet[4] == 0x00 && packet[5] == 0x06 &&
           // Check if it has a valid protocol type at offset 14-15
           (u16::from_be_bytes([packet[14], packet[15]]) == 0x0800 || // IPv4
            u16::from_be_bytes([packet[14], packet[15]]) == 0x86DD || // IPv6
            u16::from_be_bytes([packet[14], packet[15]]) == 0x0806)
        // ARP
        {
            return Ok(CaptureInfo {
                format: CaptureFormat::LinuxCookedV1,
                network_offset: 16,
            });
        }

        // Check for Ethernet II [Tipically used on macOS Devices]
        // Look for valid EtherType values at offset 12
        let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
        if ethertype == 0x0800 || // IPv4
           ethertype == 0x86DD || // IPv6
           ethertype == 0x0806
        {
            // ARP
            return Ok(CaptureInfo {
                format: CaptureFormat::EthernetII,
                network_offset: 14,
            });
        }

        Err("Unknown capture format")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_linux_cooked() {
        let packet = [
            0x00, 0x00, 0x03, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, // Linux Cooked Capture v1 header
            0x45, // IPv4 header starts here
        ]
        .to_vec();

        let info = CaptureInfo::detect(&packet).unwrap();
        assert_eq!(info.format, CaptureFormat::LinuxCookedV1);
        assert_eq!(info.network_offset, 16);
    }

    #[test]
    fn test_detect_ethernet_ii() {
        let packet = [
            0x58, 0x86, 0x94, 0x96, 0x6b, 0xfa, 0x8e, 0x7e, 0xef, 0x4c, 0x9c, 0x6f, 0x08,
            0x00, // EtherType (IPv4)
            0x45, // IPv4 header starts here
        ]
        .to_vec();

        let info = CaptureInfo::detect(&packet).unwrap();
        assert_eq!(info.format, CaptureFormat::EthernetII);
        assert_eq!(info.network_offset, 14);
    }

    #[test]
    fn test_packet_too_short() {
        let packet = [0x00, 0x00, 0x03].to_vec();
        assert!(CaptureInfo::detect(&packet).is_err());
    }
}
