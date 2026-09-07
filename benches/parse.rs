//! Baseline for the parse paths. Several commits have moved work off the hot
//! path; without these numbers a later cleanup can undo that quietly.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use paccel::engine::builtin::{ParseConfig, ParsedPacket, StopLayer};
use paccel::engine::{
    BuiltinPacketParser, QuicConnectionTracker, QuicStreamReassembler, SessionTracker,
    TcpStreamReassembler,
};
use paccel::engine::{iter_capture_frames, parse_capture_frames};

const ETH: [u8; 14] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
];

fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut f = ETH.to_vec();
    f.extend_from_slice(&[0x45, 0x00]);
    f.extend_from_slice(&u16::try_from(total).unwrap_or(u16::MAX).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, protocol, 0x00, 0x00]);
    f.extend_from_slice(&[10, 0, 0, 1]);
    f.extend_from_slice(&[192, 168, 0, 1]);
    f.extend_from_slice(payload);
    f
}

fn tcp_frame() -> Vec<u8> {
    let tcp = [
        0x04, 0x00, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0,
    ];
    ipv4(6, &tcp)
}

fn dns_frame() -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["www", "example", "com"] {
        dns.push(u8::try_from(label.len()).unwrap_or(0));
        dns.extend_from_slice(label.as_bytes());
    }
    dns.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut udp = vec![0xc0, 0x00, 0x00, 0x35];
    udp.extend_from_slice(
        &u16::try_from(8 + dns.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&dns);
    ipv4(17, &udp)
}

fn quic_frame() -> Vec<u8> {
    let mut quic = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 8];
    quic.extend_from_slice(&[0xab; 8]);
    quic.push(8);
    quic.extend_from_slice(&[0xcd; 8]);
    quic.extend_from_slice(&[0x00; 16]);
    let mut udp = vec![0xc0, 0x00, 0x01, 0xbb];
    udp.extend_from_slice(
        &u16::try_from(8 + quic.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&quic);
    ipv4(17, &udp)
}

/// A minimal classic pcap holding `count` copies of `frame`.
fn capture_of(frame: &[u8], count: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    let len = u32::try_from(frame.len()).unwrap_or(0);
    for i in 0..count {
        out.extend_from_slice(&u32::try_from(i).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(frame);
    }
    out
}

fn transport(c: &mut Criterion) {
    let cfg = ParseConfig {
        stop_after: StopLayer::Transport,
        ..Default::default()
    };
    let tcp = tcp_frame();
    let mut group = c.benchmark_group("transport");

    group.bench_function("tcp by value", |b| {
        b.iter(|| {
            BuiltinPacketParser::parse_with_config_and_linktype(black_box(&tcp), cfg, Some(1))
        });
    });
    group.bench_function("tcp parse_into", |b| {
        let mut out = ParsedPacket::default();
        b.iter(|| {
            let _ = BuiltinPacketParser::parse_into(black_box(&tcp), cfg, Some(1), &mut out);
            black_box(&out);
        });
    });
    group.bench_function("reset only", |b| {
        let mut out = ParsedPacket::default();
        b.iter(|| {
            out.reset();
            black_box(&out);
        });
    });
    group.finish();
}

fn application(c: &mut Criterion) {
    let cfg = ParseConfig::default();
    let dns = dns_frame();
    let quic = quic_frame();
    let mut group = c.benchmark_group("application");

    group.bench_function("dns", |b| {
        b.iter(|| {
            BuiltinPacketParser::parse_with_config_and_linktype(black_box(&dns), cfg, Some(1))
        });
    });
    group.bench_function("quic long header", |b| {
        b.iter(|| {
            BuiltinPacketParser::parse_with_config_and_linktype(black_box(&quic), cfg, Some(1))
        });
    });
    group.finish();
}

fn captures(c: &mut Criterion) {
    let pcap = capture_of(&tcp_frame(), 1_000);
    let mut group = c.benchmark_group("capture");

    group.bench_function("iter_capture_frames", |b| {
        b.iter(|| {
            if let Ok(frames) = iter_capture_frames(black_box(&pcap)) {
                for frame in frames {
                    black_box(&frame);
                }
            }
        });
    });
    group.bench_function("parse_capture_frames", |b| {
        b.iter(|| black_box(parse_capture_frames(black_box(&pcap))).is_ok());
    });
    group.finish();
}

fn reassembly(c: &mut Criterion) {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let payload = [0x41u8; 512];
    let mut group = c.benchmark_group("reassembly");

    // Out of order on purpose: the gap is what makes it buffer.
    group.bench_function("tcp out of order", |b| {
        b.iter(|| {
            let mut r = TcpStreamReassembler::new();
            r.offer(src, 4_000, dst, 80, 0, true, false, false, b"");
            for i in (1..16).rev() {
                let seq = 1 + u32::try_from(i * payload.len()).unwrap_or(0);
                black_box(r.offer(src, 4_000, dst, 80, seq, false, false, false, &payload));
            }
            black_box(r.offer(src, 4_000, dst, 80, 1, false, false, false, &payload));
        });
    });
    group.bench_function("quic stream out of order", |b| {
        b.iter(|| {
            let mut r = QuicStreamReassembler::new();
            for i in (1..16u64).rev() {
                let offset = i * payload.len() as u64;
                black_box(r.offer(src, 4_433, dst, 443, 0, offset, false, &payload));
            }
            black_box(r.offer(src, 4_433, dst, 443, 0, 0, false, &payload));
        });
    });
    group.finish();
}

/// The 0.4 stateful paths: connection tracking, expiry at scale, stream
/// classification, and what the detailed variants cost over the plain ones.
fn stateful(c: &mut Criterion) {
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let moved = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
    let cid = [9u8, 9, 9, 9];
    let mut group = c.benchmark_group("stateful");

    group.bench_function("quic tracker migration", |b| {
        b.iter(|| {
            let mut tracker = QuicConnectionTracker::new();
            tracker.observe_long_header(client, 5_000, server, 443, &[1, 1, 1, 1]);
            tracker.observe_long_header(server, 443, client, 5_000, &cid);
            black_box(tracker.observe_short_header(moved, 53_000, server, 443, &cid));
        });
    });

    group.bench_function("quic cid lookup", |b| {
        let mut tracker = QuicConnectionTracker::new();
        for index in 0..1_000u32 {
            let port = 40_000u16.wrapping_add(u16::try_from(index).unwrap_or(0));
            tracker.observe_long_header(client, port, server, 443, &index.to_be_bytes());
        }
        b.iter(|| black_box(tracker.connection_and_direction(client, 40_500, server, 443, &cid)));
    });

    for count in [10_000usize, 100_000] {
        group.bench_function(format!("quic expire_before {count}"), |b| {
            b.iter_batched(
                || {
                    let mut tracker = QuicConnectionTracker::new()
                        .with_max_flows(count * 2)
                        .with_max_tuples(count * 4, 8);
                    for index in 0..count {
                        let port = u16::try_from(index % 60_000).unwrap_or(0);
                        let value = u32::try_from(index).unwrap_or(0);
                        tracker.observe_long_header_at(
                            client,
                            port,
                            server,
                            443,
                            &value.to_be_bytes(),
                            u64::try_from(index).unwrap_or(0),
                        );
                    }
                    tracker
                },
                |mut tracker| black_box(tracker.expire_before(u64::MAX / 2)),
                BatchSize::LargeInput,
            );
        });
    }

    // What the event and stats bookkeeping costs over the plain call.
    let payload = [0x41u8; 512];
    group.bench_function("tcp offer", |b| {
        b.iter(|| {
            let mut r = TcpStreamReassembler::new();
            r.offer(client, 4_000, server, 80, 0, true, false, false, b"");
            black_box(r.offer(client, 4_000, server, 80, 1, false, false, false, &payload));
        });
    });
    group.bench_function("tcp offer_detailed", |b| {
        b.iter(|| {
            let mut r = TcpStreamReassembler::new();
            r.offer(client, 4_000, server, 80, 0, true, false, false, b"");
            black_box(
                r.offer_detailed(client, 4_000, server, 80, 1, false, false, false, &payload),
            );
        });
    });

    // Stream classification, one bench per shape the walk has to separate.
    let mut bgp = vec![0xffu8; 16];
    bgp.extend(19u16.to_be_bytes());
    bgp.push(4);
    let mut dns = vec![0x00u8, 0x1d, 0x12, 0x34, 0x01, 0x00];
    dns.extend([0, 1, 0, 0, 0, 0, 0, 0]);
    dns.extend([0x07]);
    dns.extend(b"example");
    dns.extend([0x03]);
    dns.extend(b"com");
    dns.extend([0x00, 0x00, 0x01, 0x00, 0x01]);
    let mut mqtt = vec![0x10u8, 0x0c, 0x00, 0x04];
    mqtt.extend(b"MQTT");
    mqtt.extend([0x05, 0x02, 0x00, 0x3c, 0x00, 0x00, 0x00]);

    for (name, body) in [
        (
            "http",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        ),
        ("bgp", bgp),
        ("dns", dns),
        ("mqtt", mqtt),
    ] {
        group.bench_function(format!("session classify {name}"), |b| {
            b.iter(|| {
                let mut tracker = SessionTracker::new();
                tracker.offer_frame(&tcp_stream_frame(0, true, b""));
                black_box(tracker.offer_frame(&tcp_stream_frame(1, false, &body)))
            });
        });
    }

    group.finish();
}

/// One TCP frame carrying `payload`, for the session benches.
fn tcp_stream_frame(sequence: u32, syn: bool, payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&40_000u16.to_be_bytes());
    tcp.extend_from_slice(&443u16.to_be_bytes());
    tcp.extend_from_slice(&sequence.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(0x50);
    tcp.push(if syn { 0x02 } else { 0x18 });
    tcp.extend_from_slice(&0x4000u16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    ipv4(6, &tcp)
}

criterion_group!(
    benches,
    transport,
    application,
    captures,
    reassembly,
    stateful
);
criterion_main!(benches);
