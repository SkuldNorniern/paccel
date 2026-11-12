//! Checks crafted frames against an independent dissector.
//!
//! paccel parsing what paccel crafted only proves the two agree. tshark is
//! the outside opinion, and it validates checksums, which is the part most
//! worth a second opinion. Skipped when tshark is not installed.

use std::env::temp_dir;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use paccel::craft::{
    EthernetHeader, IcmpHeader, Ipv4Header, Ipv6Header, PacketBuilder, TcpHeader, UdpHeader,
    VlanTag,
};

fn tshark_is_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// A pcap file holding `frames`, as Ethernet.
fn pcap_of(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(0xa1b2_c3d4u32.to_le_bytes());
    out.extend(2u16.to_le_bytes());
    out.extend(4u16.to_le_bytes());
    out.extend(0i32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(65_535u32.to_le_bytes());
    out.extend(1u32.to_le_bytes());

    for (index, frame) in frames.iter().enumerate() {
        let len = u32::try_from(frame.len()).expect("a short frame");
        out.extend(u32::try_from(index).expect("few frames").to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend(len.to_le_bytes());
        out.extend(len.to_le_bytes());
        out.extend(frame);
    }
    out
}

fn crafted_frames() -> Vec<Vec<u8>> {
    let v4_source = Ipv4Addr::new(192, 0, 2, 1);
    let v4_destination = Ipv4Addr::new(198, 51, 100, 2);
    let v6_source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let v6_destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    let mut tagged = EthernetHeader::new([0xff; 6], [0x11; 6], 0);
    tagged.outer_vlan = Some(VlanTag::new(100));

    vec![
        PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv4(Ipv4Header::new(v4_source, v4_destination, 0, 0))
            .udp(UdpHeader::new(1234, 53, 0))
            .build(b"paccel")
            .expect("builds"),
        PacketBuilder::new()
            .ethernet(tagged)
            .ipv4(Ipv4Header::new(v4_source, v4_destination, 0, 0))
            .tcp(TcpHeader::new(443, 51_000, 0))
            .build(b"an odd length")
            .expect("builds"),
        PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv4(Ipv4Header::new(v4_source, v4_destination, 0, 0))
            .icmp(IcmpHeader::echo_request(0x1234, 1))
            .build(b"ping")
            .expect("builds"),
        PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv6(Ipv6Header::new(v6_source, v6_destination, 0, 0))
            .tcp(TcpHeader::new(443, 51_000, 0))
            .build(b"paccel")
            .expect("builds"),
        PacketBuilder::new()
            .ethernet(EthernetHeader::new([0xff; 6], [0x11; 6], 0))
            .ipv6(Ipv6Header::new(v6_source, v6_destination, 0, 0))
            .icmp(IcmpHeader::echo_request_v6(0x1234, 1))
            .build(b"ping")
            .expect("builds"),
    ]
}

#[test]
fn tshark_reads_crafted_frames_and_their_checksums() {
    if !tshark_is_available() {
        eprintln!("skipping: tshark is not installed");
        return;
    }

    let frames = crafted_frames();
    let path = temp_dir().join("paccel-craft-differential.pcap");
    fs::write(&path, pcap_of(&frames)).expect("the capture is written");

    let output = Command::new("tshark")
        .args(["-r", path.to_str().expect("a utf-8 path")])
        .args(["-o", "ip.check_checksum:TRUE"])
        .args(["-o", "udp.check_checksum:TRUE"])
        .args(["-o", "tcp.check_checksum:TRUE"])
        // ICMP and ICMPv6 checksums are always validated; they have no
        // preference to turn on.
        .arg("-V")
        .output()
        .expect("tshark runs");
    assert!(
        output.status.success(),
        "tshark failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dissection = String::from_utf8_lossy(&output.stdout);
    let _ = fs::remove_file(&path);

    // tshark writes one "checksum status" line per checksum it validated.
    // Counting them matters as much as reading them: a preference that did
    // not take would leave every checksum unverified and nothing to fail on.
    let statuses: Vec<String> = dissection
        .lines()
        .map(str::trim)
        .filter(|line| line.to_ascii_lowercase().contains("checksum status:"))
        .map(str::to_owned)
        .collect();
    assert_eq!(
        statuses.len(),
        8,
        "expected three IPv4 headers, UDP, TCP, ICMP, TCP over IPv6 and \
         ICMPv6; got {statuses:?}"
    );
    for status in &statuses {
        assert!(
            status.to_ascii_lowercase().contains("good"),
            "tshark rejected a crafted checksum: {status}"
        );
    }

    // Every frame was dissected as the protocol it was built as, rather than
    // as filler tshark could not place.
    for expected in [
        "Src: 192.0.2.1",
        "Dst: 198.51.100.2",
        "Src Port: 1234",
        "Src Port: 443",
        "2001:db8::1",
        "Echo (ping) request",
        "802.1Q Virtual LAN, PRI: 0, DEI: 0, ID: 100",
    ] {
        assert!(
            dissection.contains(expected),
            "tshark did not report {expected}"
        );
    }
}
