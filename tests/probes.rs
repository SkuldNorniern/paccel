//! Probes are only worth having if they disagree with each other. These check
//! that each one accepts its own protocol and rejects the others it shares a
//! port with, rather than merely parsing what it is handed.

use paccel::layer::ProbeResult;
use paccel::layer::application::coap::probe_coap;
use paccel::layer::application::dhcp::probe_dhcp;
use paccel::layer::application::http2::probe_http2;
use paccel::layer::application::isakmp::probe_isakmp;
use paccel::layer::application::nat_pmp::probe_nat_pmp;
use paccel::layer::application::ntp::probe_ntp;
use paccel::layer::application::pcp::probe_pcp;
use paccel::layer::application::radius::probe_radius;
use paccel::layer::application::rtcp::probe_rtcp;
use paccel::layer::application::rtp::probe_rtp;
use paccel::layer::application::sip::probe_sip;
use paccel::layer::application::snmp::probe_snmp;
use paccel::layer::application::ssdp::probe_ssdp;
use paccel::layer::application::stun::probe_stun;
use paccel::layer::application::syslog::probe_syslog;
use paccel::layer::application::tftp::probe_tftp;

/// A STUN binding request: type, length, magic cookie, transaction id.
fn stun() -> Vec<u8> {
    let mut message = vec![0x00, 0x01, 0x00, 0x00];
    message.extend([0x21, 0x12, 0xa4, 0x42]);
    message.extend([0xaa; 12]);
    message
}

/// An RTP packet carrying payload type 8 (PCMA).
fn rtp() -> Vec<u8> {
    let mut packet = vec![0x80, 0x08, 0x00, 0x01];
    packet.extend([0x00, 0x00, 0x00, 0x64]);
    packet.extend([0xde, 0xad, 0xbe, 0xef]);
    packet
}

/// An RTCP sender report.
fn rtcp() -> Vec<u8> {
    let mut packet = vec![0x80, 200, 0x00, 0x01];
    packet.extend([0xde, 0xad, 0xbe, 0xef]);
    packet
}

/// An NTP version 3 client request.
fn ntp() -> Vec<u8> {
    let mut message = vec![0x1b, 0x00, 0x06, 0xec];
    message.resize(48, 0);
    message
}

/// A CoAP confirmable GET with no token.
fn coap() -> Vec<u8> {
    vec![0x40, 0x01, 0x12, 0x34]
}

/// An IKEv2 header whose length field covers exactly the header.
fn isakmp() -> Vec<u8> {
    let mut header = vec![0u8; 28];
    header[17] = 0x20;
    header[27] = 28;
    header
}

/// A BOOTP message carrying the DHCP magic cookie.
fn dhcp() -> Vec<u8> {
    let mut message = vec![0u8; 240];
    message[0] = 1;
    message[1] = 1;
    message[2] = 6;
    message[236..240].copy_from_slice(&[99, 130, 83, 99]);
    message
}

fn http2() -> Vec<u8> {
    let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // An empty SETTINGS frame on stream 0.
    payload.extend([0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
    payload
}

#[test]
fn each_probe_matches_its_own_protocol() {
    assert!(probe_stun(&stun()).is_match());
    assert!(probe_rtp(&rtp()).is_match());
    assert!(probe_rtcp(&rtcp()).is_match());
    assert!(probe_ntp(&ntp()).is_match());
    assert!(probe_coap(&coap()).is_match());
    assert!(probe_isakmp(&isakmp()).is_match());
    assert!(probe_dhcp(&dhcp()).is_match());
    assert!(probe_http2(&http2()).is_match());
}

/// STUN, RTP, RTCP and QUIC are multiplexed onto one UDP port by WebRTC, so
/// these three have to be mutually exclusive on the same bytes.
#[test]
fn the_media_port_probes_reject_each_other() {
    for (name, payload) in [("rtp", rtp()), ("rtcp", rtcp()), ("ntp", ntp())] {
        assert!(
            matches!(probe_stun(&payload), ProbeResult::NoMatch),
            "stun accepted {name}"
        );
    }
    for (name, payload) in [("stun", stun()), ("rtcp", rtcp()), ("ntp", ntp())] {
        assert!(
            matches!(probe_rtp(&payload), ProbeResult::NoMatch),
            "rtp accepted {name}"
        );
    }
    for (name, payload) in [("stun", stun()), ("rtp", rtp()), ("ntp", ntp())] {
        assert!(
            matches!(probe_rtcp(&payload), ProbeResult::NoMatch),
            "rtcp accepted {name}"
        );
    }
}

/// RFC 5761 sec 4 reserves payload types 72 to 76 precisely so RTCP's packet
/// types cannot be read as RTP.
#[test]
fn rtp_declines_the_payload_types_reserved_for_rtcp() {
    for packet_type in 200..=204u8 {
        let mut packet = rtp();
        packet[1] = packet_type;
        assert!(
            matches!(probe_rtp(&packet), ProbeResult::NoMatch),
            "rtp accepted rtcp packet type {packet_type}"
        );
    }
}

/// Cuts one byte off a payload that would otherwise match, and checks the
/// probe says so rather than reporting a mismatch.
fn truncating_is_incomplete<T>(name: &str, probe: fn(&[u8]) -> ProbeResult<T>, full: &[u8]) {
    let cut = full.len() - 1;
    assert!(
        probe(&full[..cut]).is_incomplete(),
        "{name} reported something other than incomplete on {cut} of {} bytes",
        full.len()
    );
    assert!(
        probe(&[]).is_incomplete(),
        "{name} reported something other than incomplete on an empty payload"
    );
}

/// A probe must not report a mismatch when the answer is simply not there yet.
#[test]
fn a_truncated_payload_is_incomplete_not_a_mismatch() {
    truncating_is_incomplete("stun", probe_stun, &stun());
    truncating_is_incomplete("ntp", probe_ntp, &ntp());
    truncating_is_incomplete("dhcp", probe_dhcp, &dhcp());
    truncating_is_incomplete("isakmp", probe_isakmp, &isakmp());
    truncating_is_incomplete("rtcp", probe_rtcp, &rtcp());
}

/// The preface arrives split across segments often enough to matter.
#[test]
fn a_partial_http2_preface_is_incomplete() {
    let full = http2();
    for cut in 1..24 {
        assert!(
            probe_http2(&full[..cut]).is_incomplete(),
            "a {cut}-byte prefix of the preface was not incomplete"
        );
    }
    assert!(matches!(
        probe_http2(b"GET / HTTP/1.1\r\n"),
        ProbeResult::NoMatch
    ));
}

/// An empty payload decides nothing, and no probe may claim a match on it.
#[test]
fn no_probe_matches_an_empty_payload() {
    assert!(!probe_stun(&[]).is_match());
    assert!(!probe_rtp(&[]).is_match());
    assert!(!probe_rtcp(&[]).is_match());
    assert!(!probe_ntp(&[]).is_match());
    assert!(!probe_coap(&[]).is_match());
    assert!(!probe_isakmp(&[]).is_match());
    assert!(!probe_dhcp(&[]).is_match());
    assert!(!probe_http2(&[]).is_match());
}

/// An Access-Request whose length field covers the message.
fn radius() -> Vec<u8> {
    let mut message = vec![0u8; 20];
    message[0] = 1;
    message[1] = 42;
    message[3] = 20;
    message
}

/// A TFTP read request for "f" in octet mode.
fn tftp() -> Vec<u8> {
    let mut message = vec![0x00, 0x01];
    message.extend(b"f\0octet\0");
    message
}

/// A NAT-PMP external address request.
fn nat_pmp() -> Vec<u8> {
    vec![0x00, 0x00]
}

/// A PCP MAP request.
fn pcp() -> Vec<u8> {
    let mut header = vec![0u8; 24];
    header[0] = 2;
    header[1] = 1;
    header
}

fn syslog() -> Vec<u8> {
    b"<34>Oct 11 22:14:15 host su: failed".to_vec()
}

fn sip() -> Vec<u8> {
    b"INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: 1@host\r\n\r\n".to_vec()
}

fn ssdp() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n".to_vec()
}

/// An SNMPv2c get-request with community "public".
fn snmp() -> Vec<u8> {
    vec![
        0x30, 0x19, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x0c,
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
    ]
}

#[test]
fn the_second_batch_matches_its_own_protocols() {
    assert!(probe_radius(&radius()).is_match());
    assert!(probe_tftp(&tftp()).is_match());
    assert!(probe_nat_pmp(&nat_pmp()).is_match());
    assert!(probe_pcp(&pcp()).is_match());
    assert!(probe_syslog(&syslog()).is_match());
    assert!(probe_sip(&sip()).is_match());
    assert!(probe_ssdp(&ssdp()).is_match());
    assert!(probe_snmp(&snmp()).is_match());
}

/// RFC 6887 sec 7.1: PCP and NAT-PMP share port 5351 and are told apart by the
/// version byte alone.
#[test]
fn nat_pmp_and_pcp_do_not_claim_each_other() {
    assert!(matches!(probe_nat_pmp(&pcp()), ProbeResult::NoMatch));
    assert!(matches!(probe_pcp(&nat_pmp()), ProbeResult::NoMatch));
}

/// Both are HTTP-shaped text, and a SIP request start line ends with the
/// version rather than beginning with it.
#[test]
fn sip_and_ssdp_do_not_claim_each_other() {
    assert!(matches!(probe_sip(&ssdp()), ProbeResult::NoMatch));
    assert!(matches!(probe_ssdp(&sip()), ProbeResult::NoMatch));
    assert!(matches!(
        probe_sip(b"GET / HTTP/1.1\r\n\r\n"),
        ProbeResult::NoMatch
    ));
}

/// RFC 2865 sec 3: a length below the 20-byte header cannot be RADIUS, however
/// plausible the code byte is.
#[test]
fn radius_rejects_a_length_that_cannot_cover_the_header() {
    let mut message = radius();
    message[3] = 19;
    assert!(matches!(probe_radius(&message), ProbeResult::NoMatch));

    let mut short = radius();
    short[3] = 60;
    assert!(
        probe_radius(&short).is_incomplete(),
        "a length beyond the payload means more is coming, not a mismatch"
    );
}

/// The text protocols cannot decide anything before the first line ends.
#[test]
fn a_text_protocol_without_a_line_ending_is_incomplete() {
    assert!(probe_sip(b"INVITE sip:bob@example.com SIP/2.0").is_incomplete());
    assert!(probe_ssdp(b"M-SEARCH * HTTP/1.1").is_incomplete());
}

#[test]
fn the_second_batch_declines_each_other() {
    assert!(matches!(probe_snmp(&syslog()), ProbeResult::NoMatch));
    assert!(matches!(probe_syslog(&snmp()), ProbeResult::NoMatch));
    assert!(matches!(probe_tftp(&pcp()), ProbeResult::NoMatch));
    // A PCP header opens with 2, a legal RADIUS code, so the length field is
    // what rejects it.
    assert!(matches!(probe_radius(&pcp()), ProbeResult::NoMatch));
}

/// Too few bytes to decide is not the same answer as the wrong protocol, and a
/// probe that conflates them is worse than no probe.
#[test]
fn too_short_to_decide_is_not_a_mismatch() {
    assert!(
        probe_radius(&nat_pmp()).is_incomplete(),
        "two bytes cannot decide a 20-byte header"
    );
    assert!(matches!(probe_nat_pmp(&nat_pmp()), ProbeResult::Match(_)));
}
