//! Probes are only worth having if they disagree with each other. These check
//! that each one accepts its own protocol and rejects the others it shares a
//! port with, rather than merely parsing what it is handed.

use paccel::layer::ProbeResult;
use paccel::layer::application::coap::probe_coap;
use paccel::layer::application::dhcp::probe_dhcp;
use paccel::layer::application::http2::probe_http2;
use paccel::layer::application::isakmp::probe_isakmp;
use paccel::layer::application::ntp::probe_ntp;
use paccel::layer::application::rtcp::probe_rtcp;
use paccel::layer::application::rtp::probe_rtp;
use paccel::layer::application::stun::probe_stun;

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
