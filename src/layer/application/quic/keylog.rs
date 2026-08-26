use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicKeyLogLabel {
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientTrafficSecret0,
    ServerTrafficSecret0,
}

impl QuicKeyLogLabel {
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => Some(Self::ClientHandshakeTrafficSecret),
            "SERVER_HANDSHAKE_TRAFFIC_SECRET" => Some(Self::ServerHandshakeTrafficSecret),
            "CLIENT_TRAFFIC_SECRET_0" => Some(Self::ClientTrafficSecret0),
            "SERVER_TRAFFIC_SECRET_0" => Some(Self::ServerTrafficSecret0),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct QuicKeyLog {
    secrets: HashMap<([u8; 32], QuicKeyLogLabel), Vec<u8>>,
}

impl QuicKeyLog {
    #[must_use]
    pub fn parse(contents: &str) -> Self {
        let mut keylog = Self::default();

        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut fields = line.split_ascii_whitespace();
            let (Some(label), Some(client_random_hex), Some(secret_hex), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let Some(label) = QuicKeyLogLabel::from_token(label) else {
                continue;
            };
            let Some(client_random_bytes) = decode_hex(client_random_hex) else {
                continue;
            };
            if client_random_bytes.len() != 32 {
                continue;
            }
            let Some(secret) = decode_hex(secret_hex) else {
                continue;
            };

            let mut client_random = [0u8; 32];
            client_random.copy_from_slice(&client_random_bytes);
            keylog.secrets.insert((client_random, label), secret);
        }

        keylog
    }

    /// Looks up a secret for a given ClientHello Random and label.
    #[must_use]
    pub fn secret(&self, client_random: &[u8; 32], label: QuicKeyLogLabel) -> Option<&[u8]> {
        self.secrets
            .get(&(*client_random, label))
            .map(Vec::as_slice)
    }
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }

    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| {
            let high = hex_digit(high)?;
            let low = hex_digit(low)?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_recognized_secrets_and_skips_irrelevant_or_malformed_lines() {
        let first_random = [0x11; 32];
        let second_random = [0x22; 32];
        let contents = "\
# generated test keylog

CLIENT_HANDSHAKE_TRAFFIC_SECRET 1111111111111111111111111111111111111111111111111111111111111111 aabbcc
SERVER_HANDSHAKE_TRAFFIC_SECRET 1111111111111111111111111111111111111111111111111111111111111111 ddeeff
CLIENT_TRAFFIC_SECRET_0 2222222222222222222222222222222222222222222222222222222222222222 abcd
SERVER_TRAFFIC_SECRET_0 2222222222222222222222222222222222222222222222222222222222222222 01020304
EXPORTER_SECRET 1111111111111111111111111111111111111111111111111111111111111111 deadbeef
CLIENT_TRAFFIC_SECRET_0 missing-secret
SERVER_TRAFFIC_SECRET_0 too many fields in this line
";

        let keylog = QuicKeyLog::parse(contents);

        assert_eq!(
            keylog.secret(&first_random, QuicKeyLogLabel::ClientHandshakeTrafficSecret),
            Some(&[0xaa, 0xbb, 0xcc][..])
        );
        assert_eq!(
            keylog.secret(&first_random, QuicKeyLogLabel::ServerHandshakeTrafficSecret),
            Some(&[0xdd, 0xee, 0xff][..])
        );
        assert_eq!(
            keylog.secret(&second_random, QuicKeyLogLabel::ClientTrafficSecret0),
            Some(&[0xab, 0xcd][..])
        );
        assert_eq!(
            keylog.secret(&second_random, QuicKeyLogLabel::ServerTrafficSecret0),
            Some(&[1, 2, 3, 4][..])
        );
        assert_eq!(
            keylog.secret(&first_random, QuicKeyLogLabel::ClientTrafficSecret0),
            None
        );
        assert_eq!(
            keylog.secret(&first_random, QuicKeyLogLabel::ServerTrafficSecret0),
            None
        );
    }
}
