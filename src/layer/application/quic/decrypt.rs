use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::layer::LayerError;
use crate::layer::application::tls::{TlsClientHello, parse_tls_client_hello};

use super::{QuicLongHeader, QuicPacketType, decode_packet_number, is_v1_or_v2_family};

// RFC 9001 sec 5.2.
const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
// RFC 9369 sec 3.3.1.
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

const SAMPLE_LEN: usize = 16;
const AEAD_TAG_LEN: usize = 16;

fn initial_salt(version: u32) -> [u8; 20] {
    if version == 0x6b33_43cf || version == 0x709a_50c4 {
        V2_SALT
    } else {
        V1_SALT
    }
}

// RFC 9369 sec 3.3.2 renames "quic key"/"quic iv"/"quic hp" to
// "quicv2 key"/"quicv2 iv"/"quicv2 hp" for v2; "client in"/"server in" are unchanged.
fn label_for(version: u32, base: &str) -> String {
    if version == 0x6b33_43cf || version == 0x709a_50c4 {
        format!("quicv2 {base}")
    } else {
        format!("quic {base}")
    }
}

/// RFC 8446 sec 7.1 HkdfLabel, as used by RFC 9001 sec 5 (empty Context in all QUIC uses here).
fn hkdf_expand_label(
    hk: &Hkdf<Sha256>,
    label: &str,
    out_len: usize,
) -> Result<Vec<u8>, LayerError> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1);
    info.extend_from_slice(
        &u16::try_from(out_len)
            .map_err(|_| LayerError::InvalidHeader)?
            .to_be_bytes(),
    );
    info.push(u8::try_from(full_label.len()).map_err(|_| LayerError::InvalidHeader)?);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0); // empty Context

    let mut out = vec![0u8; out_len];
    hk.expand(&info, &mut out)
        .map_err(|_| LayerError::InvalidHeader)?;
    Ok(out)
}

struct PacketProtectionKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn derive_client_initial_keys(
    version: u32,
    dcid: &[u8],
) -> Result<PacketProtectionKeys, LayerError> {
    let salt = initial_salt(version);
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&salt), dcid);
    let initial_secret_hk = Hkdf::<Sha256>::from_prk(initial_secret.as_slice())
        .map_err(|_| LayerError::InvalidHeader)?;

    let client_initial_secret = hkdf_expand_label(&initial_secret_hk, "client in", 32)?;
    let client_hk =
        Hkdf::<Sha256>::from_prk(&client_initial_secret).map_err(|_| LayerError::InvalidHeader)?;

    let key_vec = hkdf_expand_label(&client_hk, &label_for(version, "key"), 16)?;
    let iv_vec = hkdf_expand_label(&client_hk, &label_for(version, "iv"), 12)?;
    let hp_vec = hkdf_expand_label(&client_hk, &label_for(version, "hp"), 16)?;

    let mut key = [0u8; 16];
    key.copy_from_slice(&key_vec);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec);
    let mut hp = [0u8; 16];
    hp.copy_from_slice(&hp_vec);

    Ok(PacketProtectionKeys { key, iv, hp })
}

/// RFC 9001 sec 5.4.1-5.4.2: AES-ECB(hp_key, sample) over one 16-byte block;
/// only the low bits of mask[0] and mask[1..] (per actual PN length) are used.
fn header_protection_mask(hp: &[u8; 16], sample: &[u8; SAMPLE_LEN]) -> [u8; SAMPLE_LEN] {
    let cipher = Aes128::new(&Array::from(*hp));
    let mut block = Array::from(*sample);
    cipher.encrypt_block(&mut block);
    let mut mask = [0u8; SAMPLE_LEN];
    mask.copy_from_slice(&block);
    mask
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedInitial {
    pub packet_number: u32,
    pub payload: Vec<u8>,
}

/// Decrypts a client-sent Initial packet using only publicly derivable keys
/// (RFC 9001 sec 5.2 - the whole point of Initial protection is that DCID
/// alone is sufficient, by design, not a secret). Server-sent Initial packets
/// and every other encryption level need real key material and are out of
/// scope here.
pub fn decrypt_initial_packet(
    header: &QuicLongHeader,
    raw_packet: &[u8],
) -> Result<DecryptedInitial, LayerError> {
    if header.kind != QuicPacketType::Initial || !is_v1_or_v2_family(header.version) {
        return Err(LayerError::InvalidHeader);
    }
    let pn_offset = header
        .packet_number_offset
        .ok_or(LayerError::InvalidHeader)?;
    let declared_length = header.length.ok_or(LayerError::InvalidHeader)?;
    let declared_length =
        usize::try_from(declared_length).map_err(|_| LayerError::InvalidLength)?;

    let keys = derive_client_initial_keys(header.version, &header.dcid)?;

    let sample_start = pn_offset.checked_add(4).ok_or(LayerError::InvalidLength)?;
    let sample_bytes = raw_packet
        .get(sample_start..sample_start + SAMPLE_LEN)
        .ok_or(LayerError::InvalidLength)?;
    let mut sample = [0u8; SAMPLE_LEN];
    sample.copy_from_slice(sample_bytes);
    let mask = header_protection_mask(&keys.hp, &sample);

    let mut first_byte = *raw_packet.first().ok_or(LayerError::InvalidLength)?;
    first_byte ^= mask[0] & 0x0f;
    let pn_len = usize::from(first_byte & 0x03) + 1;

    let protected_pn = raw_packet
        .get(pn_offset..pn_offset + pn_len)
        .ok_or(LayerError::InvalidLength)?;
    let mut pn_bytes = [0u8; 4];
    for (index, byte) in protected_pn.iter().enumerate() {
        pn_bytes[4 - pn_len + index] = byte ^ mask[1 + index];
    }
    // This single-packet helper has no connection state, so `None` reconstructs
    // the packet number using RFC 9000 Appendix A.3 as if the largest packet
    // number were -1. Stateful callers can use `QuicConnectionTracker` across
    // multiple packets. `pn_bytes` already holds the decoded low-order bytes.
    let packet_number = u32::try_from(decode_packet_number(
        None,
        u32::from_be_bytes(pn_bytes),
        pn_len,
    ))
    .unwrap_or(u32::MAX);

    let mut associated_data = raw_packet
        .get(..pn_offset)
        .ok_or(LayerError::InvalidLength)?
        .to_vec();
    associated_data[0] = first_byte;
    associated_data.extend_from_slice(&pn_bytes[4 - pn_len..]);

    let ciphertext_start = pn_offset + pn_len;
    let ciphertext_end = pn_offset
        .checked_add(declared_length)
        .ok_or(LayerError::InvalidLength)?;
    if declared_length < pn_len + AEAD_TAG_LEN {
        return Err(LayerError::InvalidLength);
    }
    let ciphertext = raw_packet
        .get(ciphertext_start..ciphertext_end)
        .ok_or(LayerError::InvalidLength)?;

    let mut nonce_bytes = keys.iv;
    let pn_full = u64::from(packet_number).to_be_bytes();
    for (index, byte) in pn_full.iter().enumerate() {
        nonce_bytes[4 + index] ^= byte;
    }

    let cipher = Aes128Gcm::new(&Array::from(keys.key));
    let nonce = Nonce::from(nonce_bytes);
    let payload = cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad: &associated_data,
            },
        )
        .map_err(|_| LayerError::InvalidHeader)?;

    Ok(DecryptedInitial {
        packet_number,
        payload,
    })
}

/// Walks the decrypted plaintext of an Initial packet and reassembles the
/// CRYPTO stream carried in it. RFC 9000 sec 12.4 permits only PADDING(0x00),
/// PING(0x01), ACK(0x02/0x03), CRYPTO(0x06), and CONNECTION_CLOSE(0x1c) in
/// Initial packets; walking stops at any other frame type (defensive, not
/// expected in practice) and returns whatever CRYPTO data was assembled so far.
pub fn extract_crypto_stream(plaintext: &[u8]) -> Vec<u8> {
    use std::collections::BTreeMap;

    let mut chunks: BTreeMap<u64, &[u8]> = BTreeMap::new();
    let mut offset = 0usize;

    while offset < plaintext.len() {
        let Some((frame_type, type_size)) = super::decode_varint(&plaintext[offset..]) else {
            break;
        };
        offset += type_size;

        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                let Some(rest) = skip_ack_frame(&plaintext[offset..]) else {
                    break;
                };
                offset += rest;
            }
            0x06 => {
                let Some((data_offset, off_size)) = super::decode_varint(&plaintext[offset..])
                else {
                    break;
                };
                offset += off_size;
                let Some((data_len, len_size)) = super::decode_varint(&plaintext[offset..]) else {
                    break;
                };
                offset += len_size;
                let Ok(data_len) = usize::try_from(data_len) else {
                    break;
                };
                let Some(data) = plaintext.get(offset..offset + data_len) else {
                    break;
                };
                chunks.insert(data_offset, data);
                offset += data_len;
            }
            _ => break,
        }
    }

    let mut stream = Vec::new();
    for (data_offset, data) in chunks {
        let Ok(data_offset) = usize::try_from(data_offset) else {
            continue;
        };
        if data_offset < stream.len() {
            let overlap = stream.len() - data_offset;
            if overlap < data.len() {
                stream.extend_from_slice(&data[overlap..]);
            }
        } else {
            stream.resize(data_offset, 0);
            stream.extend_from_slice(data);
        }
    }
    stream
}

/// Decrypts a client Initial packet, reassembles its CRYPTO stream, and
/// parses the ClientHello inside it. QUIC's CRYPTO stream carries raw TLS
/// Handshake messages with no TLS record layer (RFC 9001 sec 4); a synthetic
/// record header is prepended since `parse_tls_client_hello` expects one and
/// does not otherwise validate `record_version`.
pub fn decrypt_initial_client_hello(
    header: &QuicLongHeader,
    raw_packet: &[u8],
) -> Result<TlsClientHello, LayerError> {
    let decrypted = decrypt_initial_packet(header, raw_packet)?;
    let crypto_stream = extract_crypto_stream(&decrypted.payload);

    let mut wrapped = Vec::with_capacity(5 + crypto_stream.len());
    wrapped.extend_from_slice(&[0x16, 0x03, 0x03]);
    let record_len = u16::try_from(crypto_stream.len()).map_err(|_| LayerError::InvalidLength)?;
    wrapped.extend_from_slice(&record_len.to_be_bytes());
    wrapped.extend_from_slice(&crypto_stream);

    parse_tls_client_hello(&wrapped)
}

/// Returns bytes consumed by one ACK frame body (after the type byte), or
/// `None` if the frame is truncated.
fn skip_ack_frame(payload: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    let (_largest_acked, size) = super::decode_varint(&payload[offset..])?;
    offset += size;
    let (_delay, size) = super::decode_varint(&payload[offset..])?;
    offset += size;
    let (range_count, size) = super::decode_varint(&payload[offset..])?;
    offset += size;
    let (_first_range, size) = super::decode_varint(&payload[offset..])?;
    offset += size;
    for _ in 0..range_count {
        let (_gap, size) = super::decode_varint(&payload[offset..])?;
        offset += size;
        let (_len, size) = super::decode_varint(&payload[offset..])?;
        offset += size;
    }
    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::application::quic::parse_quic_long_header;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // RFC 9001 Appendix A: the canonical published conformance vector for
    // Initial packet protection. DCID 8394c8f03e515708.
    const PROTECTED_PACKET_HEX: &str = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";

    #[test]
    fn decrypts_rfc9001_appendix_a2_client_initial() {
        let packet = from_hex(PROTECTED_PACKET_HEX);
        let header = parse_quic_long_header(&packet).expect("header should parse");
        assert_eq!(header.dcid, from_hex("8394c8f03e515708"));

        let decrypted = decrypt_initial_packet(&header, &packet).expect("should decrypt");
        assert_eq!(decrypted.packet_number, 2);

        let crypto_frame_hex = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113020100\
00c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005\
04616c706e00050005010000000000330026002\
4001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff08011001048000753009011\
00f088394c8f03e51570806048000ffff";
        let crypto_frame = from_hex(crypto_frame_hex);
        assert_eq!(decrypted.payload.len(), 1162);
        assert_eq!(&decrypted.payload[..crypto_frame.len()], &crypto_frame[..]);
        assert!(
            decrypted.payload[crypto_frame.len()..]
                .iter()
                .all(|&b| b == 0)
        );
    }

    #[test]
    fn decrypt_initial_client_hello_recovers_sni_from_real_capture() {
        use crate::engine::{BuiltinPacketParser, iter_capture_frames};

        let bytes = include_bytes!("../../../../tests/pcaps/protocol-gaps/quic_tls_upgrade.pcapng");
        let frame = iter_capture_frames(bytes)
            .expect("pcap should parse")
            .nth(46)
            .expect("capture should contain frame 47")
            .expect("capture frame should parse");
        let parsed = BuiltinPacketParser::parse_with_linktype(frame.data, frame.linktype)
            .expect("packet should parse");
        let quic = parsed.quic.expect("QUIC should be present");
        assert_eq!(quic.version, 1);
        assert_eq!(quic.kind, QuicPacketType::Initial);
        assert!(
            parsed.ipv6.is_some(),
            "fixture is plain IPv6, no ext headers"
        );

        // Ethernet(14) + fixed IPv6 header(40) + UDP header(8), verified against
        // this fixture's own already-passing frame-47 test elsewhere in this crate.
        const ETH_IPV6_UDP_HEADERS_LEN: usize = 14 + 40 + 8;
        let raw_quic_packet = &frame.data[ETH_IPV6_UDP_HEADERS_LEN..];

        let client_hello = decrypt_initial_client_hello(&quic, raw_quic_packet)
            .expect("CRYPTO stream should be a ClientHello");

        assert_eq!(
            client_hello.server_name,
            Some("cloudflare-quic.com".to_string())
        );
    }
}
