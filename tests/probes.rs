//! Probes are only worth having if they disagree with each other. These check
//! that each one accepts its own protocol and rejects the others it shares a
//! port with, rather than merely parsing what it is handed.

use paccel::layer::ProbeResult;
use paccel::layer::application::cdp::probe_cdp;
use paccel::layer::application::coap::probe_coap;
use paccel::layer::application::dhcp::probe_dhcp;
use paccel::layer::application::eigrp::probe_eigrp;
use paccel::layer::application::ftp::probe_ftp;
use paccel::layer::application::hsrp::probe_hsrp;
use paccel::layer::application::http2::probe_http2;
use paccel::layer::application::imap::probe_imap;
use paccel::layer::application::isakmp::probe_isakmp;
use paccel::layer::application::kerberos::{probe_kerberos_tcp, probe_kerberos_udp};
use paccel::layer::application::lacp::probe_lacp;
use paccel::layer::application::nat_pmp::probe_nat_pmp;
use paccel::layer::application::nntp::probe_nntp;
use paccel::layer::application::ntp::probe_ntp;
use paccel::layer::application::ospf::probe_ospf;
use paccel::layer::application::pcp::probe_pcp;
use paccel::layer::application::pim::probe_pim;
use paccel::layer::application::quic::probe_quic_long_header;
use paccel::layer::application::radius::probe_radius;
use paccel::layer::application::rip::probe_rip;
use paccel::layer::application::rpc::probe_rpc;
use paccel::layer::application::rtcp::probe_rtcp;
use paccel::layer::application::rtp::probe_rtp;
use paccel::layer::application::sip::probe_sip;
use paccel::layer::application::smtp::probe_smtp;
use paccel::layer::application::snmp::probe_snmp;
use paccel::layer::application::ssdp::probe_ssdp;
use paccel::layer::application::ssh::probe_ssh_banner;
use paccel::layer::application::stun::probe_stun;
use paccel::layer::application::syslog::probe_syslog;
use paccel::layer::application::telnet::probe_telnet;
use paccel::layer::application::tftp::probe_tftp;
use paccel::layer::application::vrrp::probe_vrrp;

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

/// Reports every probe that failed at once, rather than stopping at the first.
fn all_matched(cases: &[(&str, bool)]) {
    let missed: Vec<&str> = cases
        .iter()
        .filter(|(_, matched)| !matched)
        .map(|(name, _)| *name)
        .collect();
    assert!(
        missed.is_empty(),
        "these probes did not match their own protocol: {missed:?}"
    );
}

#[test]
fn each_probe_matches_its_own_protocol() {
    all_matched(&[
        ("stun", probe_stun(&stun()).is_match()),
        ("rtp", probe_rtp(&rtp()).is_match()),
        ("rtcp", probe_rtcp(&rtcp()).is_match()),
        ("ntp", probe_ntp(&ntp()).is_match()),
        ("coap", probe_coap(&coap()).is_match()),
        ("isakmp", probe_isakmp(&isakmp()).is_match()),
        ("dhcp", probe_dhcp(&dhcp()).is_match()),
        ("http2", probe_http2(&http2()).is_match()),
    ]);
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
    let claimed: Vec<&str> = [
        ("stun", probe_stun(&[]).is_match()),
        ("rtp", probe_rtp(&[]).is_match()),
        ("rtcp", probe_rtcp(&[]).is_match()),
        ("ntp", probe_ntp(&[]).is_match()),
        ("coap", probe_coap(&[]).is_match()),
        ("isakmp", probe_isakmp(&[]).is_match()),
        ("dhcp", probe_dhcp(&[]).is_match()),
        ("http2", probe_http2(&[]).is_match()),
        ("radius", probe_radius(&[]).is_match()),
        ("tftp", probe_tftp(&[]).is_match()),
        ("snmp", probe_snmp(&[]).is_match()),
        ("telnet", probe_telnet(&[]).is_match()),
        ("kerberos", probe_kerberos_udp(&[]).is_match()),
    ]
    .into_iter()
    .filter(|(_, matched)| *matched)
    .map(|(name, _)| name)
    .collect();
    assert!(
        claimed.is_empty(),
        "these probes claimed a match on no bytes at all: {claimed:?}"
    );
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
    all_matched(&[
        ("radius", probe_radius(&radius()).is_match()),
        ("tftp", probe_tftp(&tftp()).is_match()),
        ("nat_pmp", probe_nat_pmp(&nat_pmp()).is_match()),
        ("pcp", probe_pcp(&pcp()).is_match()),
        ("syslog", probe_syslog(&syslog()).is_match()),
        ("sip", probe_sip(&sip()).is_match()),
        ("ssdp", probe_ssdp(&ssdp()).is_match()),
        ("snmp", probe_snmp(&snmp()).is_match()),
    ]);
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

/// An OSPFv2 hello.
fn ospf() -> Vec<u8> {
    let mut header = vec![0u8; 24];
    header[0] = 2;
    header[1] = 1;
    header
}

fn eigrp() -> Vec<u8> {
    let mut header = vec![0u8; 20];
    header[0] = 2;
    header[1] = 5;
    header
}

fn rip() -> Vec<u8> {
    vec![1, 2, 0, 0]
}

/// A PIM v2 hello.
fn pim() -> Vec<u8> {
    vec![0x20, 0x00, 0x00, 0x00]
}

/// A VRRPv3 advertisement.
fn vrrp() -> Vec<u8> {
    let mut header = vec![0u8; 8];
    header[0] = 0x31;
    header[1] = 1;
    header[2] = 100;
    header
}

fn hsrp() -> Vec<u8> {
    vec![0u8; 20]
}

fn cdp() -> Vec<u8> {
    vec![0x02, 0xb4, 0x00, 0x00]
}

fn lacp() -> Vec<u8> {
    let mut header = vec![0u8; 18];
    header[0] = 1;
    header[1] = 1;
    header
}

/// An ONC RPC reply, which needs only the common header.
fn rpc() -> Vec<u8> {
    let mut message = vec![0u8; 8];
    message[3] = 0x2a;
    message[7] = 1;
    message
}

/// IAC DO ECHO.
fn telnet() -> Vec<u8> {
    vec![0xff, 0xfd, 0x01]
}

/// An AS-REQ, ASN.1 APPLICATION tag 10.
fn kerberos() -> Vec<u8> {
    vec![0x6a, 0x81, 0x00]
}

#[test]
fn the_third_batch_matches_its_own_protocols() {
    all_matched(&[
        ("ospf", probe_ospf(&ospf()).is_match()),
        ("eigrp", probe_eigrp(&eigrp()).is_match()),
        ("rip", probe_rip(&rip()).is_match()),
        ("pim", probe_pim(&pim()).is_match()),
        ("vrrp", probe_vrrp(&vrrp()).is_match()),
        ("hsrp", probe_hsrp(&hsrp()).is_match()),
        ("cdp", probe_cdp(&cdp()).is_match()),
        ("lacp", probe_lacp(&lacp()).is_match()),
        ("rpc", probe_rpc(&rpc()).is_match()),
        ("telnet", probe_telnet(&telnet()).is_match()),
        ("kerberos", probe_kerberos_udp(&kerberos()).is_match()),
    ]);
}

/// PIM and VRRP both read a version from the high nibble of byte 0 and are
/// carried over IP directly, so a version mismatch is all that separates them.
#[test]
fn pim_and_vrrp_do_not_claim_each_other() {
    assert!(matches!(probe_pim(&vrrp()), ProbeResult::NoMatch));
    assert!(matches!(probe_vrrp(&pim()), ProbeResult::NoMatch));
}

#[test]
fn the_third_batch_declines_each_other() {
    assert!(matches!(probe_lacp(&cdp()), ProbeResult::NoMatch));
    assert!(matches!(probe_telnet(&rip()), ProbeResult::NoMatch));
    assert!(matches!(probe_kerberos_udp(&rip()), ProbeResult::NoMatch));
    assert!(matches!(probe_cdp(&hsrp()), ProbeResult::NoMatch));
}

/// OSPF and EIGRP genuinely cannot be told apart by their headers: version 2
/// opcode 5 is a valid opening for both. IP protocol number 89 against 88 is
/// what separates them, one layer up, so neither probe is asked to.
#[test]
fn ospf_and_eigrp_overlap_and_the_probes_do_not_pretend_otherwise() {
    let mut ambiguous = ospf();
    ambiguous[1] = 5;
    assert!(probe_ospf(&ambiguous).is_match());

    let mut as_eigrp = ambiguous.clone();
    as_eigrp.truncate(20);
    assert!(
        probe_eigrp(&as_eigrp).is_match(),
        "the same bytes are a valid eigrp header, which is the point"
    );
}

/// RFC 4120 sec 7.2.2: over TCP the tag sits behind a four-byte length, so the
/// two probes must not accept each other's framing.
#[test]
fn kerberos_framing_differs_between_udp_and_tcp() {
    let mut over_tcp = vec![0x00, 0x00, 0x00, 0x03];
    over_tcp.extend(kerberos());

    assert!(probe_kerberos_tcp(&over_tcp).is_match());
    assert!(
        matches!(probe_kerberos_udp(&over_tcp), ProbeResult::NoMatch),
        "the length prefix is not an application tag"
    );
    assert!(
        probe_kerberos_tcp(&kerberos()).is_incomplete(),
        "three bytes do not reach past a four-byte length prefix"
    );
}

/// A Telnet stream that is carrying data rather than negotiating has nothing
/// to match on, and saying so beats guessing from the port.
#[test]
fn telnet_data_is_not_a_negotiation() {
    assert!(matches!(probe_telnet(b"login: "), ProbeResult::NoMatch));
    assert!(matches!(
        probe_telnet(&[0xff, 0x01, 0x02]),
        ProbeResult::NoMatch
    ));
    assert!(probe_telnet(&[0xff, 0xfd]).is_incomplete());
}

/// A QUIC v1 Initial: long-header bit, version 1, an 8-byte DCID, no SCID.
fn quic_long() -> Vec<u8> {
    let mut packet = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 0x08];
    packet.extend([0xab; 8]);
    packet.push(0x00);
    packet.extend([0x00, 0x41, 0x00]);
    packet
}

#[test]
fn quic_matches_its_long_header() {
    assert!(probe_quic_long_header(&quic_long()).is_match());
}

/// RFC 9000 sec 6: an endpoint must recognise a long header carrying a version
/// it does not know, or version negotiation could never happen.
#[test]
fn an_unknown_quic_version_is_still_a_long_header() {
    let mut future = quic_long();
    future[1..5].copy_from_slice(&[0xff, 0x00, 0x00, 0x22]);
    assert!(
        probe_quic_long_header(&future).is_match(),
        "an unknown version must not be read as a different protocol"
    );
}

/// STUN, RTP and RTCP share a port with QUIC under WebRTC. STUN and RTCP leave
/// the header-form bit clear, but RTP does not: its version 2 sets the same
/// bit, and only the fixed bit below it tells the two apart.
#[test]
fn quic_declines_what_shares_its_port() {
    assert!(matches!(
        probe_quic_long_header(&stun()),
        ProbeResult::NoMatch
    ));
    assert!(matches!(
        probe_quic_long_header(&rtp()),
        ProbeResult::NoMatch
    ));
    assert!(matches!(
        probe_quic_long_header(&rtcp()),
        ProbeResult::NoMatch
    ));
    assert!(
        matches!(probe_stun(&quic_long()), ProbeResult::NoMatch),
        "stun must not claim a quic initial either"
    );
}

/// RFC 9000 sec 17.2 caps a v1 connection id at 20 bytes, which is what stops
/// arbitrary bytes with the high bit set from parsing as QUIC.
#[test]
fn quic_rejects_a_connection_id_longer_than_the_version_allows() {
    let mut oversized = quic_long();
    oversized[5] = 21;
    assert!(matches!(
        probe_quic_long_header(&oversized),
        ProbeResult::NoMatch
    ));
}

/// A long header cut short is incomplete: the rest of the datagram has not
/// been seen, which is not the same as it being another protocol.
#[test]
fn a_truncated_quic_long_header_is_incomplete() {
    let full = quic_long();
    for cut in 1..7 {
        assert!(
            probe_quic_long_header(&full[..cut]).is_incomplete(),
            "a {cut}-byte long header was not incomplete"
        );
    }
    assert!(probe_quic_long_header(&full[..10]).is_incomplete());
}

/// A line holding a byte no UTF-8 decoder likes is still a protocol line.
/// RFC 2640 sec 2 (FTP), RFC 6531 (SMTP) and RFC 3977 sec 3.1 (NNTP) all admit
/// non-ASCII, and older servers send Latin-1 regardless. Reporting `NoMatch`
/// on one accented filename does not merely lose the line: the probe walk
/// falls through and a weaker protocol claims the stream.
#[test]
fn a_text_protocol_survives_a_byte_that_is_not_utf8() {
    fn with_latin1(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut line = prefix.to_vec();
        line.push(0xe9);
        line.extend(suffix);
        line.extend(b"\r\n");
        line
    }

    assert!(probe_ftp(&with_latin1(b"257 \"/home/caf", b"\" is current")).is_match());
    assert!(probe_smtp(&with_latin1(b"250 Bonjour caf", b"")).is_match());
    assert!(probe_imap(&with_latin1(b"* OK caf", b" ready")).is_match());
    assert!(probe_nntp(&with_latin1(b"200 news.caf", b".com ready")).is_match());
    assert!(probe_ssh_banner(&with_latin1(b"SSH-2.0-OpenSSH_9.6 caf", b"")).is_match());
}

/// The signal that a stream is not a text protocol is a control character, not
/// the encoding. Loosening the encoding check must not loosen that.
#[test]
fn a_line_holding_control_characters_is_still_not_text() {
    let mut binary = b"250 ".to_vec();
    binary.extend([0x00, 0x01, 0x02, 0x1b, 0x7f]);
    binary.extend(b"\r\n");

    // A TLS record must not be claimed by any of them either.
    let tls = vec![0x16u8, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc];

    let claimed: Vec<&str> = [
        ("ftp/binary", probe_ftp(&binary).is_match()),
        ("smtp/binary", probe_smtp(&binary).is_match()),
        ("imap/binary", probe_imap(&binary).is_match()),
        ("nntp/binary", probe_nntp(&binary).is_match()),
        ("ftp/tls", probe_ftp(&tls).is_match()),
        ("smtp/tls", probe_smtp(&tls).is_match()),
    ]
    .into_iter()
    .filter(|(_, matched)| *matched)
    .map(|(name, _)| name)
    .collect();
    assert!(
        claimed.is_empty(),
        "these probes claimed a binary stream: {claimed:?}"
    );
}
