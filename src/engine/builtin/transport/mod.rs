mod minimal;
mod tcp;
mod udp;

use std::net::Ipv4Addr;

use crate::engine::builtin::types::{ApplicationLayers, ParsedPacket};
use crate::engine::constants::ip_proto;
use crate::layer::LayerError;
use crate::layer::application::bgp::probe_bgp;
use crate::layer::application::coap::{CoapMessage, parse_coap_message};
use crate::layer::application::dhcp::{DhcpMessage, parse_dhcp_message};
use crate::layer::application::dhcp6::{Dhcp6Message, parse_dhcp6_message};
use crate::layer::application::dnp3::probe_dnp3;
use crate::layer::application::dns::{DnsMessage, probe_dns};
use crate::layer::application::eigrp::parse_eigrp_header;
use crate::layer::application::ftp::probe_ftp;
use crate::layer::application::hsrp::{HsrpHeader, parse_hsrp_header};
use crate::layer::application::http::probe_http;
use crate::layer::application::imap::probe_imap;
use crate::layer::application::isakmp::{IsakmpHeader, parse_isakmp_header};
use crate::layer::application::kerberos::{
    KerberosMessage, parse_kerberos_tcp, parse_kerberos_udp,
};
use crate::layer::application::ldap::probe_ldap;
use crate::layer::application::modbus::probe_modbus;
use crate::layer::application::mqtt::probe_mqtt;
use crate::layer::application::nat_pmp::{NatPmpMessage, parse_nat_pmp};
use crate::layer::application::nntp::probe_nntp;
use crate::layer::application::ntp::{NtpMessage, parse_ntp_message};
use crate::layer::application::ospf::parse_ospf_header;
use crate::layer::application::pcp::{PcpHeader, parse_pcp_header};
use crate::layer::application::pim::parse_pim_header;
use crate::layer::application::quic::parse_quic_long_header;
use crate::layer::application::radius::{RadiusMessage, parse_radius_message};
use crate::layer::application::rip::{RipHeader, parse_rip_header};
use crate::layer::application::rpc::{RpcMessage, parse_rpc_message};
use crate::layer::application::rtcp::{RtcpHeader, parse_rtcp};
use crate::layer::application::rtp::{RtpHeader, parse_rtp};
use crate::layer::application::sip::{SipMessage, parse_sip};
use crate::layer::application::smb1::probe_smb1;
use crate::layer::application::smb2::probe_smb2;
use crate::layer::application::smtp::probe_smtp;
use crate::layer::application::snmp::{SnmpMessage, parse_snmp_message};
use crate::layer::application::ssdp::{SsdpMessage, parse_ssdp};
use crate::layer::application::ssh::{parse_ssh_kex_init, probe_ssh_banner};
use crate::layer::application::stun::{StunMessage, parse_stun_message};
use crate::layer::application::syslog::{SyslogMessage, parse_syslog_message};
use crate::layer::application::telnet::parse_telnet_command;
use crate::layer::application::tftp::{TftpMessage, parse_tftp_message};
use crate::layer::application::tls::{parse_tls_server_hello, probe_tls_client_hello};
use crate::layer::application::vrrp::parse_vrrp_header;
use crate::layer::network::icmp::IcmpHeader;
use crate::layer::network::icmpv6::{Icmpv6Header, NdpMessage, parse_ndp};
use crate::layer::transport::tcp::{TcpFlags, TcpHeader};
use crate::layer::transport::udp::UdpHeader;

use super::types::{
    AhInfo, EspInfo, GeneveInfo, GreInfo, IgmpInfo, L2tpInfo, OpenVpnInfo, OpenVpnOpcode,
    ParseConfig, ParseMode, SctpChunk, SctpInfo, StopLayer, TcpOptionsParsed, TransportSegment,
    UdpAppHint, VxlanInfo, WireGuardInfo, WireGuardMessageType,
};

use self::minimal::{
    parse_ah_minimal, parse_esp_minimal, parse_gre_minimal, parse_icmp_minimal,
    parse_icmpv6_minimal, parse_igmp_minimal, parse_sctp_minimal,
};
use self::tcp::{DNP3_PORT, classify_tcp_application, parse_tcp_header, parse_tcp_options};
use self::udp::{maybe_classify_openvpn_tcp, parse_udp_transport};

const PORT_KERBEROS: u16 = 88;

pub(super) fn parse_transport(
    parsed: &mut ParsedPacket,
    protocol: u8,
    l4_bytes: &[u8],
    config: ParseConfig,
) -> Result<(), LayerError> {
    match protocol {
        ip_proto::TCP => {
            let parse_application = config.stop_after == StopLayer::Application;
            let tcp = parse_tcp_header(l4_bytes, parse_application)?;
            let header_len = usize::from(tcp.data_offset) * 4;
            let tcp_options = parse_application.then(|| {
                tcp.options
                    .as_deref()
                    .map(parse_tcp_options)
                    .unwrap_or_default()
            });
            let source_port = tcp.source_port;
            let destination_port = tcp.destination_port;
            parsed.transport = Some(TransportSegment::Tcp(tcp));
            parsed.tcp_options = tcp_options;
            if parse_application {
                let payload = &l4_bytes[header_len..];
                let dnp3 = ((source_port == DNP3_PORT || destination_port == DNP3_PORT)
                    && payload.starts_with(&[0x05, 0x64]))
                .then(|| probe_dnp3(payload).ok())
                .flatten();
                if dnp3.is_some() {
                    parsed.application_mut().dnp3 = dnp3;
                } else {
                    parsed.openvpn =
                        maybe_classify_openvpn_tcp(source_port, destination_port, payload);
                    if parsed.openvpn.is_none() {
                        classify_tcp_application(
                            parsed.application_mut(),
                            source_port,
                            destination_port,
                            payload,
                        );
                    }
                }
            }
            Ok(())
        }
        ip_proto::UDP => parse_udp_transport(parsed, l4_bytes, config),
        ip_proto::ICMP => {
            let icmp = parse_icmp_minimal(l4_bytes)?;
            {
                parsed.icmp = Some(icmp);
                Ok(())
            }
        }
        ip_proto::ICMPV6 => {
            let (icmpv6, ndp) =
                parse_icmpv6_minimal(l4_bytes, config.stop_after == StopLayer::Application)?;
            {
                parsed.icmpv6 = Some(icmpv6);
                parsed.ndp = ndp;
                Ok(())
            }
        }
        ip_proto::IGMP => {
            let igmp = parse_igmp_minimal(l4_bytes)?;
            {
                parsed.igmp = Some(igmp);
                Ok(())
            }
        }
        ip_proto::OSPF => {
            let ospf = parse_ospf_header(l4_bytes)?;
            {
                parsed.ospf = Some(ospf);
                Ok(())
            }
        }
        ip_proto::EIGRP => {
            let eigrp = parse_eigrp_header(l4_bytes)?;
            {
                parsed.eigrp = Some(eigrp);
                Ok(())
            }
        }
        ip_proto::PIM => {
            let pim = parse_pim_header(l4_bytes)?;
            {
                parsed.pim = Some(pim);
                Ok(())
            }
        }
        ip_proto::VRRP => {
            let vrrp = parse_vrrp_header(l4_bytes)?;
            {
                parsed.vrrp = Some(vrrp);
                Ok(())
            }
        }
        ip_proto::SCTP => {
            let sctp = parse_sctp_minimal(l4_bytes)?;
            {
                parsed.transport = Some(TransportSegment::Sctp(sctp.clone()));
                parsed.sctp = Some(sctp);
                Ok(())
            }
        }
        ip_proto::GRE => {
            let gre = parse_gre_minimal(l4_bytes)?;
            {
                parsed.gre = Some(gre);
                Ok(())
            }
        }
        ip_proto::AH => {
            let ah = parse_ah_minimal(l4_bytes)?;
            {
                parsed.ah = Some(ah);
                Ok(())
            }
        }
        ip_proto::ESP => {
            let esp = parse_esp_minimal(l4_bytes)?;
            {
                parsed.esp = Some(esp);
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::engine::builtin::{
        BuiltinPacketParser, Dnp3AppFunctionCode, Dnp3FunctionCode, FlowKey, FtpMessage,
        ImapMessage, NatPmpMessage, OpenVpnOpcode, ParseConfig, ParseWarningCode, PcpHeader,
        RpcMessage, SipMessage, SmtpMessage, SnmpMessage, SnmpPduType, SsdpMessage, StopLayer,
        SyslogMessage, TelnetCommand, TftpMessage, TransportSegment, UdpAppHint,
        WireGuardMessageType,
    };
    use crate::layer::application::http::HttpMessage;
    use crate::layer::network::icmpv6::NdpMessage;

    fn build_ethernet_ipv4_udp_frame(src_port: u16, dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + udp_payload.len()) as u16;
        let ip_total_len = (20 + udp_len as usize) as u16;

        let mut frame = Vec::with_capacity(14 + ip_total_len as usize);
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&ip_total_len.to_be_bytes());
        frame.extend_from_slice(&0x1234u16.to_be_bytes());
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.push(64);
        frame.push(17);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[192, 168, 1, 1]);
        frame.extend_from_slice(&[224, 0, 0, 251]);

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(udp_payload);

        frame
    }

    fn build_ethernet_ipv6_udp_frame(src_port: u16, dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
        let udp_len = (8 + udp_payload.len()) as u16;
        let mut udp = Vec::with_capacity(usize::from(udp_len));
        udp.extend_from_slice(&src_port.to_be_bytes());
        udp.extend_from_slice(&dst_port.to_be_bytes());
        udp.extend_from_slice(&udp_len.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(udp_payload);
        build_ethernet_ipv6_l4_frame(17, &udp)
    }

    fn build_ethernet_ipv4_tcp_frame(src_port: u16, dst_port: u16, tcp_payload: &[u8]) -> Vec<u8> {
        let mut tcp = Vec::with_capacity(20 + tcp_payload.len());
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&1u32.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.extend_from_slice(&[0x50, 0x18]);
        tcp.extend_from_slice(&0x4000u16.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]);
        tcp.extend_from_slice(tcp_payload);
        build_ethernet_ipv4_l4_frame(6, &tcp)
    }

    fn tls_client_hello() -> Vec<u8> {
        let mut extensions = Vec::new();

        let server_name = b"example.com";
        let server_name_list_len = 3 + server_name.len();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(2 + server_name_list_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(server_name);

        let alpn_protocols: [&[u8]; 2] = [b"h2", b"http/1.1"];
        let alpn_list_len = alpn_protocols
            .iter()
            .map(|protocol| 1 + protocol.len())
            .sum::<usize>();
        extensions.extend_from_slice(&16u16.to_be_bytes());
        extensions.extend_from_slice(&(2 + alpn_list_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(alpn_list_len as u16).to_be_bytes());
        for protocol in alpn_protocols {
            extensions.push(protocol.len() as u8);
            extensions.extend_from_slice(protocol);
        }

        extensions.extend_from_slice(&43u16.to_be_bytes());
        extensions.extend_from_slice(&5u16.to_be_bytes());
        extensions.push(4);
        extensions.extend_from_slice(&0x0304u16.to_be_bytes());
        extensions.extend_from_slice(&0x0303u16.to_be_bytes());

        let mut hello = Vec::new();
        hello.extend_from_slice(&0x0303u16.to_be_bytes());
        hello.extend_from_slice(&[0x42; 32]);
        hello.push(0);
        hello.extend_from_slice(&4u16.to_be_bytes());
        hello.extend_from_slice(&0x1301u16.to_be_bytes());
        hello.extend_from_slice(&0x1302u16.to_be_bytes());
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let handshake_len = hello.len();
        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(4 + handshake_len as u16).to_be_bytes());
        record.push(1);
        record.extend_from_slice(&[
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ]);
        record.extend_from_slice(&hello);
        record
    }

    fn build_ethernet_ipv4_l4_frame(protocol: u8, l4_payload: &[u8]) -> Vec<u8> {
        let ip_total_len = (20 + l4_payload.len()) as u16;
        let mut frame = Vec::with_capacity(14 + ip_total_len as usize);
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&ip_total_len.to_be_bytes());
        frame.extend_from_slice(&0x1234u16.to_be_bytes());
        frame.extend_from_slice(&0x4000u16.to_be_bytes());
        frame.push(64);
        frame.push(protocol);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&[10, 0, 0, 2]);
        frame.extend_from_slice(l4_payload);
        frame
    }

    fn build_ethernet_ipv6_l4_frame(next_header: u8, l4_payload: &[u8]) -> Vec<u8> {
        let payload_len = l4_payload.len() as u16;
        let mut frame = Vec::with_capacity(14 + 40 + l4_payload.len());
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());

        frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.push(next_header);
        frame.push(64);
        frame.extend_from_slice(&[0; 15]);
        frame.push(1);
        frame.extend_from_slice(&[0; 15]);
        frame.push(1);
        frame.extend_from_slice(l4_payload);
        frame
    }

    fn wireguard_payload(message_type: u8, total_len: usize) -> Vec<u8> {
        let mut payload = vec![0u8; total_len];
        payload[0] = message_type;
        payload
    }

    #[test]
    fn parses_ethernet_ipv4_tcp_minimal() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x12, 0x34,
            0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10, 0x10, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));
    }

    #[test]
    fn skips_transport_for_non_initial_ipv4_fragment() {
        let mut frame = build_ethernet_ipv4_tcp_frame(49152, 443, &[]);
        frame[20..22].copy_from_slice(&0x0001u16.to_be_bytes());

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.ipv4.is_some());
        assert!(parsed.transport.is_none());
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.code == ParseWarningCode::Ipv4Fragmented)
        );
    }

    #[test]
    fn parses_transport_for_initial_ipv4_fragment() {
        let mut frame = build_ethernet_ipv4_tcp_frame(49152, 443, &[]);
        frame[20..22].copy_from_slice(&0x2000u16.to_be_bytes());

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));
        assert!(
            parsed
                .warnings
                .iter()
                .any(|warning| warning.code == ParseWarningCode::Ipv4Fragmented)
        );
    }

    #[test]
    fn flow_key_uses_outer_ipv4_tcp_tuple_and_reverses_it() {
        let frame = build_ethernet_ipv4_tcp_frame(49152, 443, &[]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let expected = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 49152,
            dst_port: 443,
            protocol: 6,
        };

        assert_eq!(parsed.flow_key(), Some(expected));
        assert_eq!(
            parsed.reverse_flow_key(),
            Some(FlowKey {
                src_ip: expected.dst_ip,
                dst_ip: expected.src_ip,
                src_port: expected.dst_port,
                dst_port: expected.src_port,
                protocol: expected.protocol,
            })
        );
    }

    #[test]
    fn parses_tls_client_hello_from_tcp_payload() {
        let frame = build_ethernet_ipv4_tcp_frame(49152, 8443, &tls_client_hello());
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let tls = parsed.tls().expect("TLS ClientHello");

        assert_eq!(tls.server_name.as_deref(), Some("example.com"));
        assert!(tls.alpn.iter().any(|protocol| protocol == "h2"));
        assert!(tls.supported_versions.contains(&0x0304));
        assert!(!tls.cipher_suites.is_empty());
    }

    #[test]
    fn parses_dnp3_on_tcp_port_20000() {
        let payload = [
            0x05, 0x64, 0x0b, 0xc4, 0x03, 0x00, 0x04, 0x00, 0xef, 0x7a, 0xc1, 0xc1, 0x01, 0x3c,
            0x02, 0x06, 0xb5, 0x76,
        ];
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 20_000, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let dnp3 = parsed.dnp3().expect("DNP3 should be present");

        assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));
        assert_eq!(dnp3.link_function, Dnp3FunctionCode::UnconfirmedUserData);
        assert_eq!(dnp3.destination, 3);
        assert_eq!(dnp3.source, 4);
        assert_eq!(
            dnp3.application.map(|application| application.function),
            Some(Dnp3AppFunctionCode::Read)
        );
    }

    #[test]
    fn does_not_parse_dnp3_off_well_known_port() {
        let payload = [
            0x05, 0x64, 0x0b, 0xc4, 0x03, 0x00, 0x04, 0x00, 0xef, 0x7a, 0xc1, 0xc1, 0x01, 0x3c,
            0x02, 0x06, 0xb5, 0x76,
        ];
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 20_001, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.dnp3().is_none());
    }

    #[test]
    fn parses_http_request_from_tcp_payload() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(49152, 80, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        let (method, target, host) = parsed
            .http()
            .and_then(|message| match message {
                HttpMessage::Request {
                    method,
                    target,
                    host,
                    ..
                } => Some((method, target, host)),
                HttpMessage::Response { .. } => None,
            })
            .expect("HTTP request");
        assert_eq!(method, "GET");
        assert_eq!(target, "/index.html");
        assert_eq!(host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_http_response_from_tcp_payload() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(80, 49152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        let status = parsed
            .http()
            .and_then(|message| match message {
                HttpMessage::Response { status, .. } => Some(*status),
                HttpMessage::Request { .. } => None,
            })
            .expect("HTTP response");
        assert_eq!(status, 200);
    }

    #[test]
    fn rejects_non_http_tcp_payload() {
        let frame = build_ethernet_ipv4_tcp_frame(49152, 80, &[0xde, 0xad, 0xbe, 0xef]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.http().is_none());
    }

    #[test]
    fn parses_ospf_from_ip_payload() {
        let payload = [
            0x02, 0x01, 0x00, 0x2c, 0xc0, 0xa8, 0xaa, 0x08, 0x00, 0x00, 0x00, 0x01, 0x27, 0x3b,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let frame = build_ethernet_ipv4_l4_frame(89, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ospf = parsed.ospf.as_ref().expect("OSPF header");

        assert_eq!(ospf.version, 2);
        assert_eq!(ospf.message_type, 1);
        assert_eq!(ospf.router_id, Ipv4Addr::new(192, 168, 170, 8));
    }

    #[test]
    fn parses_eigrp_from_ip_payload() {
        let mut payload = [0; 20];
        payload[0] = 2;
        payload[1] = 5;
        payload[18..20].copy_from_slice(&100u16.to_be_bytes());
        let frame = build_ethernet_ipv4_l4_frame(88, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let eigrp = parsed.eigrp.as_ref().expect("EIGRP header");

        assert_eq!(eigrp.version, 2);
        assert_eq!(eigrp.opcode, 5);
        assert_eq!(eigrp.as_number, 100);
    }

    #[test]
    fn parses_pim_from_ip_payload() {
        let frame = build_ethernet_ipv4_l4_frame(103, &[0x21, 0x00, 0x12, 0x34]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let pim = parsed.pim.as_ref().expect("PIM header");

        assert_eq!(pim.version, 2);
        assert_eq!(pim.message_type, 1);
    }

    #[test]
    fn parses_vrrp_from_ip_payload() {
        let frame = build_ethernet_ipv4_l4_frame(112, &[0x21, 1, 100, 1, 0, 1, 0x12, 0x34]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let vrrp = parsed.vrrp.as_ref().expect("VRRP header");

        assert_eq!(vrrp.version, 2);
        assert_eq!(vrrp.packet_type, 1);
        assert_eq!(vrrp.virtual_router_id, 1);
        assert_eq!(vrrp.priority, 100);
        assert_eq!(vrrp.address_count, 1);
    }

    #[test]
    fn parses_hsrp_from_udp_payload() {
        let mut payload = [0; 20];
        payload[2] = 16;
        payload[5] = 90;
        payload[6] = 10;
        let frame = build_ethernet_ipv4_udp_frame(49_152, 1985, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let hsrp = parsed.hsrp().expect("HSRP header");

        assert_eq!(hsrp.version, 0);
        assert_eq!(hsrp.opcode, 0);
        assert_eq!(hsrp.state, 16);
        assert_eq!(hsrp.group, 10);
        assert_eq!(hsrp.priority, 90);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Hsrp));
    }

    #[test]
    fn parses_rpc_from_udp_payload() {
        let payload = [
            0x7b, 0x55, 0x8a, 0xeb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
            0x86, 0xa3, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49_152, 2049, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.rpc(),
            Some(&RpcMessage::Call {
                xid: 0x7b55_8aeb,
                rpc_version: 2,
                program: 100_003,
                program_version: 3,
                procedure: 1,
            })
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::Rpc));
    }

    #[test]
    fn parses_rip_from_udp_payload() {
        let frame = build_ethernet_ipv4_udp_frame(520, 520, &[1, 1, 0, 0]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let rip = parsed.rip().expect("RIP header");

        assert_eq!(rip.command, 1);
        assert_eq!(rip.version, 1);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Rip));
    }

    #[test]
    fn parses_isakmp_from_udp_payload() {
        let payload = [
            0x5d, 0x48, 0xbf, 0xee, 0xb7, 0xd5, 0x74, 0xda, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8,
        ];
        let frame = build_ethernet_ipv4_udp_frame(500, 500, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let isakmp = parsed.isakmp().expect("ISAKMP header");

        assert_eq!(isakmp.initiator_spi, 0x5d48_bfee_b7d5_74da);
        assert_eq!(isakmp.major_version, 2);
        assert_eq!(isakmp.exchange_type, 0x22);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Isakmp));
    }

    #[test]
    fn parses_sip_request_from_udp_payload() {
        let payload = b"INVITE sip:test@10.0.2.15:5060 SIP/2.0\r\nCall-ID: udp-call\r\nContent-Length: 0\r\n\r\n";
        let frame = build_ethernet_ipv4_udp_frame(5060, 5060, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(matches!(
            parsed.sip(),
            Some(SipMessage::Request { method, .. }) if method == "INVITE"
        ));
        assert!(parsed.udp_hints.contains(&UdpAppHint::Sip));
    }

    #[test]
    fn parses_sip_response_from_tcp_payload() {
        let payload = b"SIP/2.0 100 Trying\r\nCall-ID: tcp-call\r\nContent-Length: 0\r\n\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(5060, 49152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(matches!(
            parsed.sip(),
            Some(SipMessage::Response { status: 100, .. })
        ));
        assert!(parsed.http().is_none());
    }

    #[test]
    fn parses_rtp_as_last_resort_udp_payload() {
        let payload = [
            0x80, 0x80, 0x92, 0xdb, 0x00, 0x00, 0x00, 0xa0, 0x34, 0x3d, 0xa9, 0x9b, 0xaa,
        ];
        let frame = build_ethernet_ipv4_udp_frame(27_942, 6000, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let rtp = parsed.rtp().expect("RTP header");

        assert_eq!(rtp.sequence_number, 37_595);
        assert_eq!(rtp.timestamp, 160);
        assert_eq!(rtp.ssrc, 0x343d_a99b);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Rtp));
    }

    #[test]
    fn parses_rtcp_sender_report_as_last_resort_udp_payload() {
        let payload = [0x81, 0xc8, 0x00, 0x0c, 0x5d, 0x93, 0x15, 0x34];
        let frame = build_ethernet_ipv4_udp_frame(27_943, 6001, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let rtcp = parsed.rtcp().expect("RTCP header");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Rtcp));
        assert_eq!(rtcp.packet_type, 200);
        assert_eq!(rtcp.version, 2);
        assert_eq!(rtcp.ssrc, 0x5d93_1534);
    }

    #[test]
    fn parses_ssh_banner_on_nonstandard_tcp_port() {
        let payload = b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 29_418, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ssh = parsed.ssh().expect("SSH banner");

        assert_eq!(ssh.protocol_version, "2.0");
        assert_eq!(ssh.software_version, "OpenSSH_7.6p1");
    }

    #[test]
    fn parses_ftp_response_on_tcp_port_21() {
        let payload = b"220 FTP server ready.\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(21, 49_152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.ftp(),
            Some(&FtpMessage::Response {
                code: 220,
                text: "FTP server ready.".to_string(),
            })
        );
    }

    #[test]
    fn parses_ftp_command_on_tcp_port_21() {
        let payload = b"USER anonymous\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 21, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.ftp(),
            Some(&FtpMessage::Command {
                verb: "USER".to_string(),
                args: "anonymous".to_string(),
            })
        );
    }

    #[test]
    fn parses_imap_from_tcp_payload() {
        let payload = b"* OK IMAP4rev1 ready\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(143, 49_152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.imap(),
            Some(&ImapMessage::Untagged {
                text: "OK IMAP4rev1 ready".to_string(),
            })
        );
    }

    #[test]
    fn parses_syslog_from_udp_payload() {
        let payload = b"<189>message";
        let frame = build_ethernet_ipv4_udp_frame(49_152, 514, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.syslog(),
            Some(&SyslogMessage {
                facility: 23,
                severity: 5,
            })
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::Syslog));
    }

    #[test]
    fn parses_smb2_from_tcp_payload() {
        let mut payload = [0; 68];
        payload[3] = 64;
        payload[4..8].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        payload[8..10].copy_from_slice(&64u16.to_le_bytes());
        payload[20..24].copy_from_slice(&1u32.to_le_bytes());
        payload[28..36].copy_from_slice(&1u64.to_le_bytes());
        let frame = build_ethernet_ipv4_tcp_frame(445, 49_152, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let smb2 = parsed.smb2().expect("SMB2 header");

        assert_eq!(smb2.command, 0);
        assert!(smb2.is_response);
        assert_eq!(smb2.message_id, 1);
        assert_eq!(smb2.tree_id, 0);
        assert_eq!(smb2.session_id, 0);
    }

    #[test]
    fn parses_smb1_from_tcp_payload() {
        let mut payload = [0; 36];
        payload[3] = 32;
        payload[4..8].copy_from_slice(&[0xff, b'S', b'M', b'B']);
        payload[8] = 0x72;
        payload[34..36].copy_from_slice(&1u16.to_le_bytes());
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 445, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let smb1 = parsed.smb1().expect("SMB1 header");

        assert_eq!(smb1.command, 0x72);
        assert!(!smb1.is_response);
        assert_eq!(smb1.tid, 0);
        assert_eq!(smb1.pid, 0);
        assert_eq!(smb1.uid, 0);
        assert_eq!(smb1.mid, 1);
        assert!(parsed.smb2().is_none());
    }

    #[test]
    fn parses_smtp_response_on_tcp_port_25() {
        let payload = b"220-mail.example ESMTP ready\r\n220 mail.example ready\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(25, 49_152, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.smtp(),
            Some(&SmtpMessage::Response {
                code: 220,
                text: "mail.example ESMTP ready".to_string(),
            })
        );
    }

    #[test]
    fn parses_smtp_command_on_tcp_port_25() {
        let payload = b"EHLO client.example\r\n";
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 25, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.smtp(),
            Some(&SmtpMessage::Command {
                verb: "EHLO".to_string(),
                args: "client.example".to_string(),
            })
        );
    }

    #[test]
    fn parses_telnet_iac_do_on_tcp_port_23() {
        let payload = [0xff, 0xfd, 0x03, 0xff, 0xfb, 0x01];
        let frame = build_ethernet_ipv4_tcp_frame(49_152, 23, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.telnet(),
            Some(&TelnetCommand {
                command: 0xfd,
                option: 0x03,
            })
        );
    }

    #[test]
    fn parses_quic_initial_from_udp_payload() {
        let payload = [
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x01, 0x00,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 443, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let quic = parsed.quic().expect("QUIC long header");

        assert!(quic.is_initial);
        assert_eq!(quic.version, 1);
        assert_eq!(quic.dcid, [0x11, 0x22, 0x33, 0x44]);
        assert!(quic.scid.is_empty());
    }

    #[test]
    fn classifies_quic_short_header_as_hint_only() {
        let frame = build_ethernet_ipv4_udp_frame(49152, 443, &[0x40]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::QuicShort));
        assert!(parsed.quic().is_none());
    }

    #[test]
    fn parses_icmp_echo_identifier_and_sequence() {
        let frame = build_ethernet_ipv4_l4_frame(1, &[8, 0, 0, 0, 0x12, 0x34, 0xab, 0xcd]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let icmp = parsed.icmp.as_ref().expect("icmp");

        assert_eq!(icmp.echo_identifier(), Some(0x1234));
        assert_eq!(icmp.echo_sequence(), Some(0xabcd));
    }

    #[test]
    fn parses_icmpv6_echo_identifier_and_sequence() {
        let frame = build_ethernet_ipv6_l4_frame(58, &[128, 0, 0, 0, 0x56, 0x78, 0x9a, 0xbc]);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let icmpv6 = parsed.icmpv6.as_ref().expect("icmpv6");

        assert_eq!(icmpv6.echo_identifier(), Some(0x5678));
        assert_eq!(icmpv6.echo_sequence(), Some(0x9abc));
    }

    #[test]
    fn flow_key_resolves_protocol_past_ipv6_hop_by_hop_extension_header() {
        // Hop-by-Hop (next_header=0) wrapping TCP: next_header=6, hdr_ext_len=0
        // (8-byte header: 2-byte prefix + 6 bytes padding), then a minimal TCP header.
        let hop_by_hop = [6u8, 0, 0, 0, 0, 0, 0, 0];
        let tcp = [
            0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x50, 0x10,
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut l4 = hop_by_hop.to_vec();
        l4.extend_from_slice(&tcp);
        let frame = build_ethernet_ipv6_l4_frame(0, &l4);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ipv6 = parsed.ipv6.as_ref().expect("ipv6");
        assert_eq!(
            ipv6.next_header, 0,
            "base header still names the ext header"
        );
        assert_eq!(ipv6.resolved_next_header, 6, "resolved past the ext header");
        assert_eq!(ipv6.transport_header_offset, 48);
        assert!(matches!(parsed.transport, Some(TransportSegment::Tcp(_))));

        let flow_key = parsed.flow_key().expect("flow key");
        assert_eq!(flow_key.protocol, 6, "must be TCP, not the ext header's 0");
    }

    #[test]
    fn parses_ndp_neighbor_solicitation_with_source_link_addr() {
        let target = "2001:db8::1234"
            .parse::<Ipv6Addr>()
            .expect("valid target address");
        let link_addr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut message = vec![135, 0, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(&target.octets());
        message.extend_from_slice(&[1, 1]);
        message.extend_from_slice(&link_addr);

        let frame = build_ethernet_ipv6_l4_frame(58, &message);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ndp = parsed.ndp.as_ref().expect("neighbor solicitation");
        assert!(matches!(ndp, NdpMessage::NeighborSolicitation { .. }));
        if let NdpMessage::NeighborSolicitation {
            target: parsed_target,
            options,
        } = ndp
        {
            assert_eq!(*parsed_target, target);
            assert_eq!(options.len(), 1);
            assert_eq!(options[0].source_link_addr(), Some(link_addr.as_slice()));
        }
    }

    #[test]
    fn parses_ndp_router_advertisement_with_mtu() {
        let mut message = vec![134, 0, 0, 0, 64, 0x80];
        message.extend_from_slice(&1800u16.to_be_bytes());
        message.extend_from_slice(&30_000u32.to_be_bytes());
        message.extend_from_slice(&1_000u32.to_be_bytes());
        message.extend_from_slice(&[5, 1, 0, 0]);
        message.extend_from_slice(&1500u32.to_be_bytes());

        let frame = build_ethernet_ipv6_l4_frame(58, &message);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let ndp = parsed.ndp.as_ref().expect("router advertisement");
        assert!(matches!(ndp, NdpMessage::RouterAdvertisement { .. }));
        if let NdpMessage::RouterAdvertisement { options, .. } = ndp {
            assert_eq!(options.len(), 1);
            assert_eq!(options[0].mtu(), Some(1500));
        }
    }

    #[test]
    fn parses_sctp_common_header_and_init_chunk() {
        let sctp = [
            0x13, 0x88, 0x13, 0x89, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x00,
            0x00, 0x04,
        ];
        let frame = build_ethernet_ipv4_l4_frame(132, &sctp);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let sctp = parsed.sctp.as_ref().expect("sctp");

        assert_eq!(sctp.source_port, 5000);
        assert_eq!(sctp.destination_port, 5001);
        assert_eq!(sctp.verification_tag, 0x1122_3344);
        assert_eq!(sctp.chunks.len(), 1);
        assert_eq!(sctp.chunks[0].chunk_type, 1);
        assert!(matches!(
            parsed.transport,
            Some(TransportSegment::Sctp(ref transport_sctp))
                if transport_sctp.source_port == 5000
                    && transport_sctp.destination_port == 5001
        ));
    }

    #[test]
    fn parses_ethernet_vlan_ipv4_udp_dns() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, 0x00, 0x64, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x3d, 0x12, 0x34, 0x40, 0x00, 64, 17, 0x00, 0x00, 192, 168, 1, 1, 8, 8, 8, 8,
            0x30, 0x39, 0x00, 0x35, 0x00, 0x29, 0x00, 0x00, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ethernet.is_some());
        assert!(parsed.ipv4.is_some());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
        assert!(parsed.dns().is_some());
        assert!(parsed.udp_hints.contains(&UdpAppHint::Dns));
    }

    #[test]
    fn transport_mode_skips_dns_but_keeps_udp_flow_key() {
        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let frame = build_ethernet_ipv4_udp_frame(12345, 53, &dns_query);
        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                stop_after: StopLayer::Transport,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        assert!(parsed.dns().is_none());
        assert!(parsed.udp_hints.is_empty());
        assert!(matches!(parsed.transport, Some(TransportSegment::Udp(_))));
        assert_eq!(
            parsed.flow_key(),
            Some(FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                src_port: 12345,
                dst_port: 53,
                protocol: 17,
            })
        );
    }

    #[test]
    fn transport_mode_still_parses_quic_long_header() {
        // 0xc0: long header, fixed bit set, Initial. version=1, dcid_len=0,
        // scid_len=0, token_len=0 (varint), length=1 (varint), 1 PN byte.
        let quic_initial = [0xc0, 0, 0, 0, 1, 0, 0, 0x00, 0x01, 0x00];
        let frame = build_ethernet_ipv4_udp_frame(51_820, 443, &quic_initial);
        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                stop_after: StopLayer::Transport,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        let quic = parsed
            .quic()
            .expect("QUIC long header should still be structurally parsed at Transport stop");
        assert_eq!(quic.version, 1);
    }

    #[test]
    fn transport_segment_offset_locates_udp_payload() {
        let quic_initial = [0xc0, 0, 0, 0, 1, 0, 0, 0x00, 0x01, 0x00];
        let frame = build_ethernet_ipv4_udp_frame(51_820, 443, &quic_initial);
        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                stop_after: StopLayer::Transport,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        let segment_offset = parsed
            .transport_segment_offset
            .expect("transport_segment_offset should be set");
        let udp_payload = &frame[segment_offset + 8..]; // 8 = fixed UDP header length
        assert_eq!(udp_payload, quic_initial);
    }

    #[test]
    fn default_application_mode_still_parses_dns() {
        let dns_query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let frame = build_ethernet_ipv4_udp_frame(12345, 53, &dns_query);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.dns().is_some());
    }

    #[test]
    fn network_mode_stops_after_ipv4_header() {
        let frame = build_ethernet_ipv4_tcp_frame(49152, 443, &[]);
        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                stop_after: StopLayer::Network,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        assert!(parsed.ipv4.is_some());
        assert!(parsed.transport.is_none());
        assert_eq!(
            parsed.flow_key(),
            Some(FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: 0,
                dst_port: 0,
                protocol: 6,
            })
        );
    }

    #[test]
    fn parses_dhcp_discover() {
        let mut payload = vec![0u8; 244];
        payload[0] = 1;
        payload[236..240].copy_from_slice(&[99, 130, 83, 99]);
        payload[240..244].copy_from_slice(&[53, 1, 1, 255]);

        let frame = build_ethernet_ipv4_udp_frame(68, 67, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Dhcp));
        assert_eq!(parsed.dhcp().expect("dhcp").message_type, Some(1));
    }

    #[test]
    fn parses_dhcp6_solicit() {
        let payload = [
            1, 0x10, 0x08, 0x74, 0, 1, 0, 14, 0, 1, 0, 1, 0x2a, 0x2b, 0x2c, 0x2d, 0, 1, 2, 3, 4, 5,
        ];

        let frame = build_ethernet_ipv6_udp_frame(546, 547, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Dhcpv6));
        let dhcp6 = parsed.dhcp6().expect("dhcpv6");
        assert_eq!(dhcp6.msg_type, 1);
        assert_eq!(dhcp6.transaction_id, 0x10_0874);
    }

    #[test]
    fn parses_ssdp_msearch_over_udp() {
        let payload = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
            ST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n";
        let frame = build_ethernet_ipv4_udp_frame(49_152, 1900, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Ssdp));
        assert!(matches!(
            parsed.ssdp(),
            Some(SsdpMessage::Request {
                method,
                target,
                version,
                ..
            }) if method == "M-SEARCH" && target == "*" && version == "HTTP/1.1"
        ));

        let response =
            build_ethernet_ipv4_udp_frame(1900, 49_152, b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n");
        let parsed = BuiltinPacketParser::parse(&response).expect("parse should succeed");
        assert!(matches!(
            parsed.ssdp(),
            Some(SsdpMessage::Response {
                status: 200,
                reason,
                ..
            }) if reason == "OK"
        ));
        assert!(parsed.udp_hints.contains(&UdpAppHint::Ssdp));
    }

    #[test]
    fn parses_nat_pmp_requests_over_udp() {
        let external_address = build_ethernet_ipv4_udp_frame(49_152, 5351, &[0, 0]);
        let parsed = BuiltinPacketParser::parse(&external_address).expect("parse should succeed");
        assert_eq!(
            parsed.nat_pmp(),
            Some(&NatPmpMessage {
                version: 0,
                opcode: 0,
            })
        );
        assert!(parsed.pcp().is_none());
        assert!(parsed.udp_hints.contains(&UdpAppHint::NatPmp));

        let map_udp = [0, 1, 0, 0, 0xa2, 0xa9, 0, 0, 0, 0, 0x1c, 0x20];
        let frame = build_ethernet_ipv4_udp_frame(49_152, 5351, &map_udp);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert_eq!(
            parsed.nat_pmp(),
            Some(&NatPmpMessage {
                version: 0,
                opcode: 1,
            })
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::NatPmp));
    }

    #[test]
    fn parses_pcp_announce_over_udp_before_nat_pmp() {
        let payload = [
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0xa8, 0x32,
            0x05,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49_152, 5351, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.pcp(),
            Some(&PcpHeader {
                version: 2,
                is_response: false,
                opcode: 0,
                lifetime: 0,
            })
        );
        assert!(parsed.nat_pmp().is_none());
        assert!(parsed.udp_hints.contains(&UdpAppHint::Pcp));
    }

    #[test]
    fn parses_radius_access_request() {
        let payload = [
            0x01, 0x67, 0x00, 0x57, 0x40, 0xb6, 0x64, 0xdb, 0xf5, 0xd6, 0x81, 0xb2, 0xad, 0xbd,
            0x17, 0x69, 0x51, 0x51, 0x18, 0xc8, 0x01, 0x07, 0x73, 0x74, 0x65, 0x76, 0x65, 0x02,
            0x12, 0xdb, 0xc6, 0xc4, 0xb7, 0x58, 0xbe, 0x14, 0xf0, 0x05, 0xb3, 0x87, 0x7c, 0x9e,
            0x2f, 0xb6, 0x01, 0x04, 0x06, 0xc0, 0xa8, 0x00, 0x1c, 0x05, 0x06, 0x00, 0x00, 0x00,
            0x7b, 0x50, 0x12, 0x5f, 0x0f, 0x86, 0x47, 0xe8, 0xc8, 0x9b, 0xd8, 0x81, 0x36, 0x42,
            0x68, 0xfc, 0xd0, 0x45, 0x32, 0x4f, 0x0c, 0x02, 0x66, 0x00, 0x0a, 0x01, 0x73, 0x74,
            0x65, 0x76, 0x65,
        ];

        let frame = build_ethernet_ipv4_udp_frame(49_152, 1812, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let radius = parsed.radius().expect("RADIUS should be present");
        assert_eq!(radius.code, 1);
        assert_eq!(radius.identifier, 103);
        assert!(parsed.udp_hints.contains(&UdpAppHint::Radius));
    }

    #[test]
    fn parses_snmp_v3_get_request() {
        let payload = [
            0x30, 0x4b, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x30, 0xf6, 0xf3, 0xd4, 0x02,
            0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e,
            0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00,
            0x30, 0x21, 0x04, 0x0d, 0x80, 0x00, 0x1f, 0x88, 0x80, 0x59, 0xdc, 0x48, 0x61, 0x45,
            0xa2, 0x63, 0x22, 0x04, 0x00, 0xa0, 0x0e, 0x02, 0x04, 0x7d, 0x0e, 0x08, 0x2e, 0x02,
            0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];

        let frame = build_ethernet_ipv4_udp_frame(49_152, 161, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(matches!(
            parsed.snmp(),
            Some(SnmpMessage::V3 {
                msg_id: 821_490_644,
                msg_max_size: 65_507,
                msg_flags: 0x04,
                pdu_type: Some(SnmpPduType::GetRequest),
                request_id: Some(2_098_071_598),
                ..
            })
        ));
        assert!(parsed.udp_hints.contains(&UdpAppHint::Snmp));
    }

    #[test]
    fn parses_tftp_read_request_only_on_well_known_port() {
        let payload = b"\0\x01rfc1350.txt\0octet\0";
        let frame = build_ethernet_ipv4_udp_frame(49152, 69, payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert_eq!(
            parsed.tftp(),
            Some(&TftpMessage::ReadRequest {
                filename: "rfc1350.txt".to_owned(),
                mode: "octet".to_owned(),
            })
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::Tftp));

        let non_tftp_frame = build_ethernet_ipv4_udp_frame(49152, 1069, payload);
        let non_tftp = BuiltinPacketParser::parse(&non_tftp_frame).expect("parse should succeed");
        assert!(non_tftp.tftp().is_none());
        assert!(!non_tftp.udp_hints.contains(&UdpAppHint::Tftp));
    }

    #[test]
    fn parses_ntp_client() {
        let mut payload = vec![0u8; 48];
        payload[0] = 0x23;
        payload[1] = 2;
        payload[16..24].copy_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        payload[40..48].copy_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());

        let frame = build_ethernet_ipv4_udp_frame(123, 123, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Ntp));
        let ntp = parsed.ntp().expect("ntp");
        assert_eq!(ntp.version, 4);
        assert_eq!(ntp.mode, 3);
        assert_eq!(ntp.reference_ts, 0x0102_0304_0506_0708);
        assert_eq!(ntp.transmit_ts, 0x1112_1314_1516_1718);
    }

    #[test]
    fn parses_l2tp_over_udp() {
        let l2tp = [
            0x42, 0x02, 0x00, 0x0c, 0x12, 0x34, 0x56, 0x78, 0x00, 0x01, 0x00, 0x02,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 1701, &l2tp);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let l2tp = parsed.l2tp.as_ref().expect("L2TP metadata");
        assert_eq!(l2tp.flags, 0x4202);
        assert_eq!(l2tp.version, 2);
        assert_eq!(l2tp.tunnel_id, Some(0x1234));
        assert_eq!(l2tp.session_id, Some(0x5678));
        assert!(parsed.udp_hints.contains(&UdpAppHint::L2tp));
    }

    #[test]
    fn detects_mdns_udp_probe() {
        let payload = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let frame = build_ethernet_ipv4_udp_frame(5353, 5353, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.udp_hints.contains(&UdpAppHint::Mdns));
        assert!(parsed.dns().is_some());
    }

    #[test]
    fn test_stun_udp_hint() {
        let payload = [
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 3478, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Stun));
        assert!(parsed.stun().is_some());
    }

    #[test]
    fn test_llmnr_udp_hint() {
        let payload = [
            0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 5355, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Llmnr));
        assert!(parsed.dns().is_none());
    }

    #[test]
    fn test_nbns_udp_hint() {
        let payload = [
            0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let frame = build_ethernet_ipv4_udp_frame(49152, 137, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        assert!(parsed.udp_hints.contains(&UdpAppHint::Nbns));
        assert!(parsed.dns().is_none());
    }

    #[test]
    fn parses_tcp_options_mss_and_window_scale() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x70, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x07, 0x01, 0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let opts = parsed.tcp_options.as_ref().expect("tcp_options");
        assert_eq!(opts.mss, Some(1460));
        assert_eq!(opts.window_scale, Some(7));
    }

    #[test]
    fn parses_ipv4_gre() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x2c, 0x00, 0x01,
            0x40, 0x00, 64, 47, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 64, 0, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(parsed.gre.is_some());
        assert_eq!(parsed.gre.as_ref().unwrap().protocol_type, 0x0800);
        assert!(
            parsed
                .inner
                .as_ref()
                .is_some_and(|inner| inner.ipv4.is_some())
        );
        assert!(
            !parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::GreInner))
        );
    }

    #[test]
    fn gre_minimal_parsed_with_warning() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x24, 0x00, 0x01,
            0x40, 0x00, 64, 47, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.gre.is_some());
        assert_eq!(parsed.gre.as_ref().unwrap().protocol_type, 0x0800);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::GreInner))
        );
    }

    #[test]
    fn gre_key_and_sequence_extend_header() {
        let gre_header = [
            0x30, 0x00, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let frame = build_ethernet_ipv4_l4_frame(47, &gre_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let gre = parsed.gre.as_ref().expect("gre");
        assert!(!gre.checksum_present);
        assert!(gre.key_present);
        assert!(gre.sequence_present);
        assert_eq!(gre.key, Some(0x0102_0304));
        assert_eq!(gre.sequence, Some(0x0506_0708));
        assert_eq!(gre.header_len, 12);
    }

    /// A truncated GRE header is a transport header that did not survive the
    /// capture. Strict still refuses it; permissive keeps the addresses it did
    /// read and says why there is no transport, which is what permissive means
    /// everywhere else.
    #[test]
    fn gre_truncated_checksum_header_is_strict_only() {
        use crate::engine::builtin::types::{ParseConfig, ParseMode, ParseWarningCode};

        let frame = build_ethernet_ipv4_l4_frame(47, &[0x80, 0x00, 0x08, 0x00]);

        let strict = ParseConfig {
            mode: ParseMode::Strict,
            ..ParseConfig::default()
        };
        assert!(BuiltinPacketParser::parse_with_config(&frame, strict).is_err());

        let parsed = BuiltinPacketParser::parse(&frame).expect("permissive keeps what it read");
        assert!(parsed.ipv4.is_some(), "the addresses are still valid");
        assert!(
            parsed.gre.is_none(),
            "the header that did not survive is absent"
        );
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.code == ParseWarningCode::TransportTruncated),
            "and the reason is recorded"
        );
    }

    #[test]
    fn tcp_options_mss_and_window_scale_parsed() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x06, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.tcp_options.is_some());
        let opts = parsed.tcp_options.as_ref().unwrap();
        assert_eq!(opts.mss, Some(0x05b4));
        assert_eq!(opts.window_scale, Some(6));
    }

    #[test]
    fn vxlan_minimal_parsed_with_warning() {
        let vxlan_header: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 100, 0];
        let frame = build_ethernet_ipv4_udp_frame(4789, 4789, &vxlan_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.vxlan.is_some());
        assert_eq!(parsed.vxlan.as_ref().unwrap().vni, 100);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::VxlanInner))
        );
    }

    #[test]
    fn vxlan_decodes_inner_ethernet_ipv4_udp() {
        let inner = build_ethernet_ipv4_udp_frame(1234, 4321, &[]);
        let mut payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 100, 0];
        payload.extend_from_slice(&inner);
        let frame = build_ethernet_ipv4_udp_frame(4789, 4789, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.vxlan.is_some());
        let inner = parsed.inner.as_ref().expect("inner packet");
        assert!(inner.ethernet.is_some());
        assert!(inner.ipv4.is_some());
        assert!(matches!(inner.transport, Some(TransportSegment::Udp(_))));
    }

    #[test]
    fn vxlan_flow_key_uses_inner_ipv4_tcp_tuple_in_transport_mode() {
        let inner = build_ethernet_ipv4_tcp_frame(23456, 8443, &[]);
        let mut payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 100, 0];
        payload.extend_from_slice(&inner);
        let frame = build_ethernet_ipv4_udp_frame(4789, 4789, &payload);
        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                stop_after: StopLayer::Transport,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");

        assert!(parsed.vxlan.is_some());
        assert!(parsed.inner.is_some());
        assert_eq!(
            parsed.flow_key(),
            Some(FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                src_port: 23456,
                dst_port: 8443,
                protocol: 6,
            })
        );
    }

    #[test]
    fn vxlan_outer_and_innermost_flow_keys_differ() {
        let inner = build_ethernet_ipv4_tcp_frame(23456, 8443, &[]);
        let mut payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 100, 0];
        payload.extend_from_slice(&inner);
        let frame = build_ethernet_ipv4_udp_frame(4789, 4789, &payload);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");

        let outer = parsed
            .outer_flow_key()
            .expect("VXLAN tunnel's own outer flow should resolve");
        let innermost = parsed
            .innermost_flow_key()
            .expect("encapsulated TCP flow should resolve");
        assert_ne!(outer, innermost);
        assert_eq!(outer.protocol, 17); // UDP, the VXLAN tunnel itself
        assert_eq!(innermost.protocol, 6); // TCP, the encapsulated traffic
        assert_eq!(parsed.flow_key(), Some(innermost));

        let path: Vec<_> = parsed.flow_path().collect();
        assert_eq!(path, vec![outer, innermost]);
    }

    #[test]
    fn ipv4_in_ipv4_decodes_inner_packet() {
        let inner_frame = build_ethernet_ipv4_l4_frame(1, &[8, 0, 0, 0, 0, 1, 0, 1]);
        let frame = build_ethernet_ipv4_l4_frame(4, &inner_frame[14..]);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ipv4.is_some());
        assert!(
            parsed
                .inner
                .as_ref()
                .is_some_and(|inner| inner.ipv4.is_some())
        );
    }

    #[test]
    fn zero_tunnel_depth_disables_recursion() {
        let inner_frame = build_ethernet_ipv4_l4_frame(1, &[8, 0, 0, 0, 0, 1, 0, 1]);
        let mut gre = vec![0x00, 0x00, 0x08, 0x00];
        gre.extend_from_slice(&inner_frame[14..]);
        let frame = build_ethernet_ipv4_l4_frame(47, &gre);

        let parsed = BuiltinPacketParser::parse_with_config(
            &frame,
            ParseConfig {
                max_tunnel_depth: 0,
                ..ParseConfig::default()
            },
        )
        .expect("parse should succeed");
        assert!(parsed.inner.is_none());
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::TunnelDepthLimit))
        );
    }

    #[test]
    fn geneve_minimal_parsed_with_warning() {
        let geneve_header: [u8; 8] = [0x00, 0x00, 0x65, 0x58, 0x00, 0x00, 101, 0];
        let frame = build_ethernet_ipv4_udp_frame(6081, 6081, &geneve_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.geneve.is_some());
        assert_eq!(parsed.geneve.as_ref().unwrap().version, 0);
        assert_eq!(parsed.geneve.as_ref().unwrap().protocol_type, 0x6558);
        assert_eq!(parsed.geneve.as_ref().unwrap().vni, 101);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::GeneveInner))
        );
    }

    #[test]
    fn geneve_options_extend_header() {
        let geneve_header: [u8; 12] = [
            0x01, 0x00, 0x65, 0x58, 0x00, 0x00, 101, 0, 0x01, 0x02, 0x03, 0x04,
        ];
        let frame = build_ethernet_ipv4_udp_frame(6081, 6081, &geneve_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let geneve = parsed.geneve.as_ref().expect("geneve");
        assert_eq!(geneve.opt_len, 1);
        assert_eq!(geneve.header_len, 12);
    }

    #[test]
    fn geneve_truncated_options_are_not_parsed() {
        let geneve_header: [u8; 8] = [0x01, 0x00, 0x65, 0x58, 0x00, 0x00, 101, 0];
        let frame = build_ethernet_ipv4_udp_frame(6081, 6081, &geneve_header);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.geneve.is_none());
    }

    #[test]
    fn classifies_wireguard_handshake_initiation() {
        let wg = wireguard_payload(1, 148);
        let frame = build_ethernet_ipv4_udp_frame(51820, 51820, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.wireguard.is_some());
        assert_eq!(
            parsed.wireguard.as_ref().unwrap().message_type,
            WireGuardMessageType::HandshakeInitiation
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn classifies_wireguard_handshake_response() {
        let wg = wireguard_payload(2, 92);
        let frame = build_ethernet_ipv4_udp_frame(51821, 51821, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert_eq!(
            parsed.wireguard.as_ref().unwrap().message_type,
            WireGuardMessageType::HandshakeResponse
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn classifies_wireguard_cookie_reply() {
        let wg = wireguard_payload(3, 64);
        let frame = build_ethernet_ipv4_udp_frame(51820, 9999, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert_eq!(
            parsed.wireguard.as_ref().unwrap().message_type,
            WireGuardMessageType::CookieReply
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn classifies_wireguard_transport_data() {
        let wg = wireguard_payload(4, 32);
        let frame = build_ethernet_ipv4_udp_frame(9999, 51820, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert_eq!(
            parsed.wireguard.as_ref().unwrap().message_type,
            WireGuardMessageType::TransportData
        );
        assert!(parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn does_not_classify_wireguard_when_payload_too_short() {
        let mut wg = vec![0u8; 40];
        wg[0] = 1;
        let frame = build_ethernet_ipv4_udp_frame(51820, 51820, &wg);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.wireguard.is_none());
        assert!(!parsed.udp_hints.contains(&UdpAppHint::WireGuard));
    }

    #[test]
    fn classifies_openvpn_udp_control_packet() {
        let session_id = 0x8138_1462_1d67_462d_u64;
        let mut payload = vec![0x38];
        payload.extend_from_slice(&session_id.to_be_bytes());
        payload.extend_from_slice(&[0xaa, 0xbb]);
        let frame = build_ethernet_ipv4_udp_frame(49152, 1194, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, OpenVpnOpcode::ControlHardResetClientV2);
        assert_eq!(openvpn.key_id, 0);
        assert_eq!(openvpn.session_id, Some(session_id));
        assert_eq!(openvpn.peer_id, None);
        assert!(parsed.udp_hints.contains(&UdpAppHint::OpenVpn));
    }

    #[test]
    fn classifies_openvpn_udp_data_v1_without_session_id() {
        let payload = [0x30, 0xd7, 0xb2, 0x33];
        let frame = build_ethernet_ipv4_udp_frame(1194, 49152, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, OpenVpnOpcode::DataV1);
        assert_eq!(openvpn.session_id, None);
        assert_eq!(openvpn.peer_id, None);
    }

    #[test]
    fn classifies_openvpn_udp_data_v2_with_peer_id() {
        let payload = [0x48, 0x12, 0x34, 0x56, 0xde, 0xad];
        let frame = build_ethernet_ipv4_udp_frame(49152, 1194, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, OpenVpnOpcode::DataV2);
        assert_eq!(openvpn.session_id, None);
        assert_eq!(openvpn.peer_id, Some(0x12_3456));
    }

    #[test]
    fn classifies_length_prefixed_openvpn_tcp_packet() {
        let session_id = 0x8138_1462_1d67_462d_u64;
        let mut payload = vec![0x00, 0x09, 0x38];
        payload.extend_from_slice(&session_id.to_be_bytes());
        let frame = build_ethernet_ipv4_tcp_frame(49152, 1194, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let openvpn = parsed.openvpn.as_ref().expect("openvpn should be present");
        assert_eq!(openvpn.opcode, OpenVpnOpcode::ControlHardResetClientV2);
        assert_eq!(openvpn.session_id, Some(session_id));
    }

    #[test]
    fn does_not_classify_openvpn_on_non_default_port() {
        let payload = [0x38, 0x81, 0x38, 0x14, 0x62, 0x1d, 0x67, 0x46, 0x2d];
        let frame = build_ethernet_ipv4_udp_frame(49152, 443, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.openvpn.is_none());
        assert!(!parsed.udp_hints.contains(&UdpAppHint::OpenVpn));
    }

    #[test]
    fn does_not_classify_invalid_openvpn_opcode() {
        let payload = [0x78, 0x81, 0x38, 0x14, 0x62, 0x1d, 0x67, 0x46, 0x2d];
        let frame = build_ethernet_ipv4_udp_frame(49152, 1194, &payload);

        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.openvpn.is_none());
        assert!(!parsed.udp_hints.contains(&UdpAppHint::OpenVpn));
    }

    #[test]
    fn ah_minimal_parsed_with_warning() {
        let ah = [58, 1, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x09];
        let frame = build_ethernet_ipv4_l4_frame(51, &ah);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.ah.is_some());
        assert_eq!(parsed.ah.as_ref().unwrap().next_header, 58);
        assert_eq!(parsed.ah.as_ref().unwrap().spi, 0x1122_3344);
        assert_eq!(parsed.ah.as_ref().unwrap().sequence, 9);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::AhInner))
        );
    }

    #[test]
    fn esp_minimal_parsed_with_warning() {
        let esp = [0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x02];
        let frame = build_ethernet_ipv4_l4_frame(50, &esp);
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        assert!(parsed.esp.is_some());
        assert_eq!(parsed.esp.as_ref().unwrap().spi, 0xaabb_ccdd);
        assert_eq!(parsed.esp.as_ref().unwrap().sequence, 2);
        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| matches!(w.code, ParseWarningCode::EspInner))
        );
    }

    #[test]
    fn tcp_options_timestamp_and_sack_permitted() {
        let frame = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x3a, 0x00, 0x01,
            0x40, 0x00, 64, 6, 0, 0, 192, 168, 1, 1, 192, 168, 1, 2, 0x00, 0x50, 0x01, 0xbb, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x90, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x04, 0x02, 0x08, 0x0a, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x01,
            0x01, 0x01, 0x01,
        ];
        let parsed = BuiltinPacketParser::parse(&frame).expect("parse should succeed");
        let opts = parsed.tcp_options.as_ref().expect("tcp_options");
        assert!(opts.sack_permitted);
        assert_eq!(opts.ts_val, Some(0x1111_1111));
        assert_eq!(opts.ts_ecr, Some(0x2222_2222));
    }
}
