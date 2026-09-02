use super::udp::UDP_PORT_SIP;
use super::*;

pub(super) const DNP3_PORT: u16 = 20_000;
const TCP_PORT_FTP: u16 = 21;
const TCP_PORT_SMTP: u16 = 25;
const TCP_PORT_TELNET: u16 = 23;
const TCP_PORT_IMAP: u16 = 143;
const TCP_PORT_BGP: u16 = 179;
const TCP_PORT_LDAP: u16 = 389;
const TCP_PORT_LDAPS: u16 = 636;
const TCP_PORT_NNTP: u16 = 119;
const TCP_PORT_NNTPS: u16 = 563;
const TCP_PORT_MQTT: u16 = 1883;
const TCP_PORT_MODBUS: u16 = 502;
const TCP_PORT_SUBMISSION: u16 = 587;
const TCP_PORT_SMB2: u16 = 445;

pub(super) fn classify_tcp_application(
    parsed: &mut ParsedPacket,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) {
    let is_tls_handshake_record = payload.len() >= 5 && payload[0] == 22;
    parsed.tls = is_tls_handshake_record
        .then(|| probe_tls_client_hello(payload).ok())
        .flatten();
    if parsed.tls.is_none() && is_tls_handshake_record {
        parsed.tls_server_hello = parse_tls_server_hello(payload).ok();
    }
    if parsed.tls.is_none() && parsed.tls_server_hello.is_none() {
        parsed.http = probe_http(payload).ok();
        if parsed.http.is_none()
            && (source_port == UDP_PORT_SIP || destination_port == UDP_PORT_SIP)
        {
            parsed.sip = parse_sip(payload).ok();
        }
        if parsed.http.is_none() && parsed.sip.is_none() {
            if !payload.is_empty() {
                parsed.ssh = probe_ssh_banner(payload).ok();
            }
            if parsed.ssh.is_none() {
                parsed.ssh_kex_init = parse_ssh_kex_init(payload).ok();
            }
            if parsed.ssh.is_none() && parsed.ssh_kex_init.is_none() {
                classify_tcp_app_by_port(source_port, destination_port, payload, parsed);
            }
        }
    }
}

fn classify_tcp_app_by_port(
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    parsed: &mut ParsedPacket,
) {
    if source_port == TCP_PORT_FTP || destination_port == TCP_PORT_FTP {
        parsed.ftp = probe_ftp(payload).ok();
        return;
    }
    if source_port == TCP_PORT_SMB2 || destination_port == TCP_PORT_SMB2 {
        classify_smb(payload, parsed);
        return;
    }
    if source_port == TCP_PORT_SMTP
        || destination_port == TCP_PORT_SMTP
        || source_port == TCP_PORT_SUBMISSION
        || destination_port == TCP_PORT_SUBMISSION
    {
        parsed.smtp = probe_smtp(payload).ok();
        return;
    }
    if source_port == TCP_PORT_TELNET || destination_port == TCP_PORT_TELNET {
        parsed.telnet = parse_telnet_command(payload).ok();
        return;
    }
    if source_port == TCP_PORT_IMAP || destination_port == TCP_PORT_IMAP {
        parsed.imap = probe_imap(payload).ok();
        return;
    }
    if source_port == TCP_PORT_BGP || destination_port == TCP_PORT_BGP {
        parsed.bgp = probe_bgp(payload).ok();
    }
    if parsed.bgp.is_none()
        && (source_port == TCP_PORT_LDAP
            || destination_port == TCP_PORT_LDAP
            || source_port == TCP_PORT_LDAPS
            || destination_port == TCP_PORT_LDAPS)
    {
        parsed.ldap = probe_ldap(payload).ok();
    }
    if parsed.bgp.is_none()
        && parsed.ldap.is_none()
        && (source_port == TCP_PORT_NNTP
            || destination_port == TCP_PORT_NNTP
            || source_port == TCP_PORT_NNTPS
            || destination_port == TCP_PORT_NNTPS)
    {
        parsed.nntp = probe_nntp(payload).ok();
    }
    if parsed.bgp.is_none()
        && parsed.ldap.is_none()
        && parsed.nntp.is_none()
        && (source_port == TCP_PORT_MQTT || destination_port == TCP_PORT_MQTT)
    {
        parsed.mqtt = probe_mqtt(payload).ok();
    }
    if parsed.bgp.is_none()
        && parsed.ldap.is_none()
        && parsed.nntp.is_none()
        && parsed.mqtt.is_none()
        && (source_port == TCP_PORT_MODBUS || destination_port == TCP_PORT_MODBUS)
    {
        parsed.modbus = probe_modbus(payload).ok();
    }
    if parsed.bgp.is_none()
        && parsed.ldap.is_none()
        && parsed.nntp.is_none()
        && parsed.mqtt.is_none()
        && parsed.modbus.is_none()
        && (source_port == PORT_KERBEROS || destination_port == PORT_KERBEROS)
    {
        parsed.kerberos = parse_kerberos_tcp(payload).ok();
    }
}

fn classify_smb(payload: &[u8], parsed: &mut ParsedPacket) {
    parsed.smb2 = probe_smb2(payload).ok();
    if parsed.smb2.is_none() {
        parsed.smb1 = probe_smb1(payload).ok();
    }
}

pub(super) fn parse_tcp_options(blob: &[u8]) -> TcpOptionsParsed {
    let mut out = TcpOptionsParsed::default();
    let mut i = 0;
    while i < blob.len() {
        let kind = blob[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        if i + 2 > blob.len() {
            break;
        }
        let len = blob[i + 1] as usize;
        if len < 2 || i + len > blob.len() {
            break;
        }
        parse_tcp_option(kind, &blob[i..i + len], &mut out);
        i += len;
    }
    out
}

fn parse_tcp_option(kind: u8, option: &[u8], out: &mut TcpOptionsParsed) {
    match kind {
        2 if option.len() >= 4 => {
            out.mss = Some(u16::from_be_bytes([option[2], option[3]]));
        }
        3 if option.len() >= 3 => {
            out.window_scale = Some(option[2]);
        }
        4 => {
            out.sack_permitted = true;
        }
        8 if option.len() >= 10 => {
            out.ts_val = Some(u32::from_be_bytes([
                option[2], option[3], option[4], option[5],
            ]));
            out.ts_ecr = Some(u32::from_be_bytes([
                option[6], option[7], option[8], option[9],
            ]));
        }
        _ => {}
    }
}

pub(super) fn parse_tcp_header(
    l4_bytes: &[u8],
    parse_options: bool,
) -> Result<TcpHeader, LayerError> {
    if l4_bytes.len() < 20 {
        return Err(LayerError::InvalidLength);
    }

    let source_port = u16::from_be_bytes([l4_bytes[0], l4_bytes[1]]);
    let destination_port = u16::from_be_bytes([l4_bytes[2], l4_bytes[3]]);
    let sequence_number = u32::from_be_bytes([l4_bytes[4], l4_bytes[5], l4_bytes[6], l4_bytes[7]]);
    let acknowledgment_number =
        u32::from_be_bytes([l4_bytes[8], l4_bytes[9], l4_bytes[10], l4_bytes[11]]);

    let data_offset = (l4_bytes[12] >> 4) & 0x0f;
    if data_offset < 5 {
        return Err(LayerError::InvalidHeader);
    }

    let header_length = (data_offset as usize) * 4;
    if l4_bytes.len() < header_length {
        return Err(LayerError::InvalidLength);
    }

    let flags = TcpFlags {
        fin: (l4_bytes[13] & 0x01) != 0,
        syn: (l4_bytes[13] & 0x02) != 0,
        rst: (l4_bytes[13] & 0x04) != 0,
        psh: (l4_bytes[13] & 0x08) != 0,
        ack: (l4_bytes[13] & 0x10) != 0,
        urg: (l4_bytes[13] & 0x20) != 0,
        ece: (l4_bytes[13] & 0x40) != 0,
        cwr: (l4_bytes[13] & 0x80) != 0,
        ns: (l4_bytes[12] & 0x01) != 0,
    };

    let window_size = u16::from_be_bytes([l4_bytes[14], l4_bytes[15]]);
    let checksum = u16::from_be_bytes([l4_bytes[16], l4_bytes[17]]);
    let urgent_pointer = u16::from_be_bytes([l4_bytes[18], l4_bytes[19]]);
    let options = if parse_options && header_length > 20 {
        Some(l4_bytes[20..header_length].to_vec())
    } else {
        None
    };

    Ok(TcpHeader {
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        data_offset,
        flags,
        window_size,
        checksum,
        urgent_pointer,
        options,
    })
}
