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

    Ok(packet_protection_keys(&key_vec, &iv_vec, &hp_vec))
}

fn derive_keys_from_secret(
    version: u32,
    secret: &[u8],
) -> Result<PacketProtectionKeys, LayerError> {
    let secret_hk = Hkdf::<Sha256>::from_prk(secret).map_err(|_| LayerError::InvalidHeader)?;
    let key_vec = hkdf_expand_label(&secret_hk, &label_for(version, "key"), 16)?;
    let iv_vec = hkdf_expand_label(&secret_hk, &label_for(version, "iv"), 12)?;
    let hp_vec = hkdf_expand_label(&secret_hk, &label_for(version, "hp"), 16)?;

    Ok(packet_protection_keys(&key_vec, &iv_vec, &hp_vec))
}

fn packet_protection_keys(key_vec: &[u8], iv_vec: &[u8], hp_vec: &[u8]) -> PacketProtectionKeys {
    let mut key = [0u8; 16];
    key.copy_from_slice(key_vec);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(iv_vec);
    let mut hp = [0u8; 16];
    hp.copy_from_slice(hp_vec);

    PacketProtectionKeys { key, iv, hp }
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
/// alone is sufficient, by design, not a secret). This entry point supports
/// client-sent Initial packets; other encryption levels need real key material.
pub fn decrypt_initial_packet(
    header: &QuicLongHeader,
    raw_packet: &[u8],
) -> Result<DecryptedInitial, LayerError> {
    if header.kind != QuicPacketType::Initial || !is_v1_or_v2_family(header.version) {
        return Err(LayerError::InvalidHeader);
    }
    let keys = derive_client_initial_keys(header.version, &header.dcid)?;
    decrypt_with_keys(&keys, header, raw_packet)
}

/// Decrypts a QUIC Handshake or 1-RTT packet using a traffic secret supplied
/// externally (e.g. from a `QuicKeyLog`, matching how Wireshark/curl/browsers
/// expose this - Handshake/1-RTT keys derive from a live TLS 1.3 ECDHE
/// exchange and cannot be recovered from a passive capture alone, unlike
/// Initial packets).
pub fn decrypt_packet_with_secret(
    header: &QuicLongHeader,
    raw_packet: &[u8],
    secret: &[u8],
) -> Result<DecryptedInitial, LayerError> {
    if !matches!(
        header.kind,
        QuicPacketType::Handshake | QuicPacketType::ZeroRtt
    ) || !is_v1_or_v2_family(header.version)
    {
        return Err(LayerError::InvalidHeader);
    }
    let keys = derive_keys_from_secret(header.version, secret)?;
    decrypt_with_keys(&keys, header, raw_packet)
}

fn decrypt_with_keys(
    keys: &PacketProtectionKeys,
    header: &QuicLongHeader,
    raw_packet: &[u8],
) -> Result<DecryptedInitial, LayerError> {
    let pn_offset = header
        .packet_number_offset
        .ok_or(LayerError::InvalidHeader)?;
    let declared_length = header.length.ok_or(LayerError::InvalidHeader)?;
    let declared_length =
        usize::try_from(declared_length).map_err(|_| LayerError::InvalidLength)?;

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
            break;
        };
        if data_offset < stream.len() {
            let overlap = stream.len() - data_offset;
            if overlap < data.len() {
                stream.extend_from_slice(&data[overlap..]);
            }
        } else if data_offset == stream.len() {
            stream.extend_from_slice(data);
        } else {
            break;
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
pub(crate) use tests::{PROTECTED_PACKET_HEX, from_hex};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::application::quic::parse_quic_long_header;

    pub(crate) fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // RFC 9001 Appendix A: the canonical published conformance vector for
    // Initial packet protection. DCID 8394c8f03e515708.
    pub(crate) const PROTECTED_PACKET_HEX: &str = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";

    const HANDSHAKE_PACKET_HEX: &str = "ea0000000104aabbccdd05112233445532be8efef96fc8190e83e58c6fb096d74e9eaf3177a70f65b223dbdcf17ba830d4ef1d80be29f87003064a2409052deda7027b";
    const HANDSHAKE_SECRET_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    const SYNTHETIC_INITIAL_HEX: &str = "c10000000108a1b2c3d4e5f607180000449e465f93f6fe01a10fdd248ff58a7eb9888d4f9eb99c5027cdc4112ba6246e9431ea279954012891844e8770659dcbdf7bdb19e184e270df75071e28d383e82af141edac3027b2dc32c34897e418dd8e7a844b89eb4bc5414e0125caedd84ca68a18ec32c85a73d507f10e5d8d294f105bc9cf8cad065e721a9ccc9a9882b8b3fc0b1647e28bb4d44e963a1b6280065cef74a0088e2eea2488b1f3edf892267a8c020ffd1ea49d39e33bedf2b8c122405e9345e3141a774bc23ed826099fde2f0bc70178524cc303114e60a651df4c080280b64f3d4aea5899d1d2064183bc489c9479c1aab3c29ff83eea9afb2fc0c087fc50b06c9d32c63ff28e5d2c77de46c7eb0ae7c97cc02587a74c45f804842734168ebae1ae96d51a39653916188fdcb91bf2dde6fc32557ea567e25674b4c817344b7ed517dc8b68c31b5011dd1899d69f9e1e85bc72dabfabb6b74bd44196fc4705c070681ed55bbe81f909768c3c502492f7c89fd4653acbf2a5cd62a2594ea3dd195751b232eae00ead908e84b367cc58c3dfe61fac0bc68026f7747099613aa4ccfc2ef3e2cb5b6f8aca2eb9f6ef32304374ff42b35241f5c60139465f9e1d0ab2acc4df53814db1005bb35394a1e7831ccb87b91f6d6613be7afb7b76a46dcb2c7dd7fb593e512ced621555268bbe7ad716186f5ba31fc04d985de491322d00319d104ebf9b361a2c463dfdc08ca4e902719c866b2b8016041d3c97378163d053b19dfb6b32b690d21aaed0c37f83639f1e3c6f70ec8c2c8f439097dc1649084a64b79f318ee720bc408cf6482bd2cd93b55aea025ded6c24a806b6106f0e746e1b1a47ac6b3194f80e95ab930cc763814168aa005068cce58a19066e3d37d0d060c032aef787227636ca96a3c88575c2293c0912b418b62dd4016e9ab104c04d8dd087f0d590c524d13ecafafadeb673e7d31eae3ac9e2c5a4e6345bcbde0d524e3d040598b0a0b9832ff33f2092cd7d4677603220c1e8c15afae4bcac6bcc4ab7f1eecf5557ae635fdfa9b9a06a081fddf304903efca5d889a6c49fe0cc3077e292838d6a5dad1cf45f5af9bf72af8f688e4dd2eb3b755bdb63b500785a7f2b55edbc960761f802508251ed0a8d2e11ec180a47d9bbcfb35ed732cf060c5a1d3df14e72b64d0b5b57a8c3862c9bba83fbfa72dcdc4c9727fd8a604fd96109a06de061b143c870c87f44e27a5fdb29f5eaf1cd0b9e359548c3ade91656804ca43b113bf78f4df85cd7f8106d6d62a4abaeef6eeacb2e5ee0b0b154056f740a600f8ea10bfcd219f15d2219768b8465253f1c1cea24e4908b4649b1f6c440b71f179d8e158f1037c9c81fae15e9d214de718c1c6761fca06182fa86a9e1ec1d62759ed3862bffe18d18734d93b1982f6595f88dd45cc166f62217ec3b181ae21bb9df5ea00dd3324accfbbdf9b3395dfe4f672ead42b93b2d7fbadf97cf50e7255cef2d8e3b7bc10d46351847bf8850fda0e3f7b5fc45d6adbc8597ff95764c36c79eb9a76c4a45c1337403d1231e55c053d47629e218b24c5482200e630b648d5db976b3776522e57106d0031e6be9086eafca558e89175b796cd639af14a3a10b0b6c9fe8b387a6077dde8b6c351576de4f0ac373958d9d5b186680ead9bb4e765ed21c469e7eeed9ae35";

    #[test]
    fn crypto_stream_stops_at_gap() {
        let plaintext = [
            0x06, 0x00, 0x0a, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x06, 0x14, 0x03, 20, 21, 22,
        ];

        assert_eq!(
            extract_crypto_stream(&plaintext),
            (0..10).collect::<Vec<_>>()
        );
    }

    #[test]
    fn crypto_stream_reassembles_contiguous_frames() {
        let plaintext = [
            0x06, 0x00, 0x0a, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x06, 0x0a, 0x03, 10, 11, 12,
        ];

        assert_eq!(
            extract_crypto_stream(&plaintext),
            (0..13).collect::<Vec<_>>()
        );
    }

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
    fn decrypts_v1_handshake_packet_with_external_secret() {
        let packet = from_hex(HANDSHAKE_PACKET_HEX);
        let secret = from_hex(HANDSHAKE_SECRET_HEX);
        let header = parse_quic_long_header(&packet).expect("header should parse");

        assert_eq!(header.kind, QuicPacketType::Handshake);
        assert_eq!(header.length, Some(50));
        assert_eq!(header.packet_number_offset, Some(17));

        let decrypted = decrypt_packet_with_secret(&header, &packet, &secret)
            .expect("Handshake packet should decrypt");
        assert_eq!(decrypted.packet_number, 5);
        assert_eq!(decrypted.payload, b"THIS-IS-HANDSHAKE-PLAINTEXT-DATA");
    }

    #[test]
    fn decrypt_initial_client_hello_recovers_sni_from_synthetic_packet() {
        // A fully valid, self-generated QUIC v1 Initial packet (DCID
        // a1b2c3d4e5f60718, PN 2, padded to the real 1200-byte minimum
        // Initial datagram size) carrying a TLS ClientHello with SNI
        // "paccel-test.example". Built and independently encrypted via
        // Python's `cryptography` library (a separate implementation from
        // this crate's Rust crypto stack) using the same RFC 9001 sec 5.2
        // Initial-secret derivation this module implements, then verified
        // to decrypt back to the expected plaintext before being embedded
        // here - not derived from any captured traffic.
        let packet = from_hex(SYNTHETIC_INITIAL_HEX);
        let header = parse_quic_long_header(&packet).expect("header should parse");
        assert_eq!(header.version, 1);
        assert_eq!(header.kind, QuicPacketType::Initial);
        assert_eq!(header.dcid, from_hex("a1b2c3d4e5f60718"));

        let client_hello = decrypt_initial_client_hello(&header, &packet)
            .expect("CRYPTO stream should be a ClientHello");

        assert_eq!(
            client_hello.server_name,
            Some("paccel-test.example".to_string())
        );
    }
}
