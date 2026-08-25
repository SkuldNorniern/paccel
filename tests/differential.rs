//! Differential test: parse each fixture with paccel and with tshark, then
//! compare the fields both tools expose. Skipped automatically when tshark is
//! not on PATH, so the suite stays green on hosts without Wireshark.
#![allow(clippy::panic, clippy::absolute_paths)]

use std::process::Command;

use paccel::engine::{BuiltinPacketParser, TransportSegment, parse_capture_frames};

const FIXTURES: &[&str] = &[
    "dns_udp_ipv4.pcap",
    "dns_response_ipv4.pcap",
    "tcp_syn_ipv4.pcap",
    "icmp_echo_ipv4.pcap",
    "icmpv6_echo_ipv6.pcap",
    "arp_request.pcap",
    "multi_frame.pcap",
    "dns_udp_ipv4.pcapng",
];

/// One tshark row: the fields we cross-check, in extraction order.
struct TsharkRow {
    ip_src: String,
    ip_dst: String,
    ipv6_src: String,
    ipv6_dst: String,
    tcp_sport: String,
    tcp_dport: String,
    udp_sport: String,
    udp_dport: String,
    dns_qname: String,
}

fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Set in CI's dedicated differential job so a missing tshark fails the
/// build instead of silently skipping - the soft-skip below stays the
/// default for local `cargo test` on hosts without Wireshark installed.
fn tshark_required() -> bool {
    std::env::var("PACCEL_REQUIRE_TSHARK").is_ok()
}

fn tshark_rows(path: &str) -> Vec<TsharkRow> {
    let output = Command::new("tshark")
        .args([
            "-r",
            path,
            "-T",
            "fields",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.srcport",
            "-e",
            "udp.dstport",
            "-e",
            "dns.qry.name",
            "-E",
            "occurrence=f",
        ])
        .output()
        .expect("tshark should run");
    assert!(output.status.success(), "tshark failed on {path}");

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            let get = |i: usize| f.get(i).copied().unwrap_or("").to_string();
            TsharkRow {
                ip_src: get(0),
                ip_dst: get(1),
                ipv6_src: get(2),
                ipv6_dst: get(3),
                tcp_sport: get(4),
                tcp_dport: get(5),
                udp_sport: get(6),
                udp_dport: get(7),
                dns_qname: get(8),
            }
        })
        .collect()
}

/// Requires exact agreement, symmetrically: if tshark extracted a value,
/// paccel must have extracted the same one (a paccel `None` here is a real
/// false negative, not a benign gap) - and if tshark found nothing, paccel
/// asserting a value would be paccel hallucinating a field tshark didn't see.
fn compare(field: &str, path: &str, idx: usize, paccel: Option<String>, tshark: &str) {
    let expected = (!tshark.is_empty()).then(|| tshark.to_lowercase());
    let actual = paccel.map(|value| value.to_lowercase());
    assert_eq!(
        actual, expected,
        "{field} mismatch in {path} frame {idx}: paccel={actual:?} tshark={tshark:?}"
    );
}

#[test]
fn paccel_agrees_with_tshark_on_fixtures() {
    if !tshark_available() {
        assert!(
            !tshark_required(),
            "tshark is required (PACCEL_REQUIRE_TSHARK set) but not found on PATH"
        );
        eprintln!("tshark not found on PATH; skipping differential test");
        return;
    }

    for name in FIXTURES {
        let path = format!(
            "{}/tests/pcaps/happy-path/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(&path).expect("fixture should read");
        let frames = parse_capture_frames(&bytes).expect("capture should parse");
        let rows = tshark_rows(&path);

        assert_eq!(
            frames.len(),
            rows.len(),
            "frame count mismatch in {name}: paccel={} tshark={}",
            frames.len(),
            rows.len()
        );

        for (idx, (frame, row)) in frames.iter().zip(rows.iter()).enumerate() {
            let parsed = BuiltinPacketParser::parse(frame.data).expect("frame should parse");

            let (v4_src, v4_dst) = parsed
                .ipv4
                .as_ref()
                .map(|h| (Some(h.source.to_string()), Some(h.destination.to_string())))
                .unwrap_or((None, None));
            compare("ip.src", name, idx, v4_src, &row.ip_src);
            compare("ip.dst", name, idx, v4_dst, &row.ip_dst);

            let (v6_src, v6_dst) = parsed
                .ipv6
                .as_ref()
                .map(|h| (Some(h.source.to_string()), Some(h.destination.to_string())))
                .unwrap_or((None, None));
            compare("ipv6.src", name, idx, v6_src, &row.ipv6_src);
            compare("ipv6.dst", name, idx, v6_dst, &row.ipv6_dst);

            match &parsed.transport {
                Some(TransportSegment::Tcp(tcp)) => {
                    compare(
                        "tcp.srcport",
                        name,
                        idx,
                        Some(tcp.source_port.to_string()),
                        &row.tcp_sport,
                    );
                    compare(
                        "tcp.dstport",
                        name,
                        idx,
                        Some(tcp.destination_port.to_string()),
                        &row.tcp_dport,
                    );
                }
                Some(TransportSegment::Udp(udp)) => {
                    compare(
                        "udp.srcport",
                        name,
                        idx,
                        Some(udp.source_port.to_string()),
                        &row.udp_sport,
                    );
                    compare(
                        "udp.dstport",
                        name,
                        idx,
                        Some(udp.destination_port.to_string()),
                        &row.udp_dport,
                    );
                }
                None => {}
            }

            let qname = parsed
                .dns
                .as_ref()
                .and_then(|d| d.questions.first())
                .map(|q| q.qname.clone());
            compare("dns.qry.name", name, idx, qname, &row.dns_qname);
        }
    }
}
