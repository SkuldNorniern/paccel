//! Baseline for the parse paths. Several commits have moved work off the hot
//! path; without these numbers a later cleanup can undo that quietly.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use paccel::engine::builtin::{ParseConfig, ParsedPacket, StopLayer};
use paccel::engine::{BuiltinPacketParser, QuicStreamReassembler, TcpStreamReassembler};
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

criterion_group!(benches, transport, application, captures, reassembly);
criterion_main!(benches);
