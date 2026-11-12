//! The one's-complement sum RFC 1071 defines, for IPv4, ICMP, UDP and TCP.

/// Sums bytes and pseudo-header fields without building a buffer for them.
///
/// A transport checksum covers a pseudo-header that is never transmitted, so
/// feeding the fields straight in is both faster and the only way to avoid a
/// temporary.
#[derive(Debug, Default, Clone, Copy)]
pub struct ChecksumAccumulator {
    /// Wide enough that no message length can overflow it before the fold.
    sum: u64,
    /// A byte held back because the run that delivered it ended on an odd
    /// length. The pairing is over the whole message, not per call.
    odd: Option<u8>,
}

impl ChecksumAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_u16(&mut self, value: u16) {
        debug_assert!(self.odd.is_none(), "a field after an odd-length run");
        self.sum += u64::from(value);
    }

    pub fn add_u32(&mut self, value: u32) {
        let [a, b, c, d] = value.to_be_bytes();
        self.add_u16(u16::from_be_bytes([a, b]));
        self.add_u16(u16::from_be_bytes([c, d]));
    }

    pub fn add_bytes(&mut self, bytes: &[u8]) {
        // A run of no bytes adds nothing and, more to the point, must not
        // disturb a byte held back from the run before it.
        let Some((first, rest)) = bytes.split_first() else {
            return;
        };

        let mut bytes = bytes;
        if let Some(held) = self.odd.take() {
            self.sum += u64::from(u16::from_be_bytes([held, *first]));
            bytes = rest;
        }

        let (pairs, remainder) = bytes.as_chunks::<2>();
        for pair in pairs {
            self.sum += u64::from(u16::from_be_bytes(*pair));
        }
        // Held rather than padded: more bytes may follow, and RFC 1071 pairs
        // across the whole message.
        self.odd = remainder.first().copied();
    }

    /// The value to put in the header.
    pub fn finish(&self) -> u16 {
        let mut sum = self.sum;
        if let Some(held) = self.odd {
            sum += u64::from(u16::from_be_bytes([held, 0]));
        }
        !fold(sum)
    }
}

/// Carries the high half back into the low until sixteen bits are left.
fn fold(mut sum: u64) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    debug_assert!(sum <= u64::from(u16::MAX));
    u16::try_from(sum).unwrap_or(u16::MAX)
}

/// Moves a checksum to account for one changed 16-bit field, by RFC 1624 eq 3.
///
/// Rewriting an address in a captured packet is exactly this: the rest of the
/// header is untouched, so summing it again would be wasted work.
pub fn update_u16(checksum: u16, old: u16, new: u16) -> u16 {
    !fold(u64::from(!checksum) + u64::from(!old) + u64::from(new))
}

#[cfg(test)]
mod tests {
    use super::{ChecksumAccumulator, update_u16};

    /// The header from RFC 1071's worked example, with the checksum field
    /// zeroed; summing it has to give back the value it carries.
    const HEADER: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];

    #[test]
    fn the_sum_matches_the_checksum_the_header_carries() {
        let mut sum = ChecksumAccumulator::new();
        sum.add_bytes(&HEADER);
        assert_eq!(sum.finish(), 0xb861);
    }

    /// Bytes arriving in odd-length runs must pair across the joins, not pad
    /// at each one.
    #[test]
    fn splitting_the_bytes_does_not_change_the_sum() {
        for split in 0..HEADER.len() {
            let mut sum = ChecksumAccumulator::new();
            sum.add_bytes(&HEADER[..split]);
            sum.add_bytes(&HEADER[split..]);
            assert_eq!(sum.finish(), 0xb861, "split at {split}");
        }
    }

    /// A run that delivers no bytes must not swallow the byte held back from
    /// the one before it, and a message long enough to overflow a 32-bit
    /// accumulator must still fold to the right value.
    #[test]
    fn an_empty_run_and_a_long_message_still_sum() {
        let mut split = ChecksumAccumulator::new();
        split.add_bytes(&[0x12]);
        split.add_bytes(&[]);
        let mut whole = ChecksumAccumulator::new();
        whole.add_bytes(&[0x12]);
        assert_eq!(split.finish(), whole.finish());
        assert_eq!(split.finish(), 0xedff);

        // 65_538 words of 0xffff, which overflows a u32 sum.
        let mut long = ChecksumAccumulator::new();
        long.add_bytes(&vec![0xff; 131_076]);
        assert_eq!(long.finish(), 0);
    }

    /// The whole point of the incremental form: it has to agree with summing
    /// the changed header from scratch, for every field and value.
    #[test]
    fn an_incremental_update_agrees_with_a_fresh_sum() {
        let mut state = 0x1234_5678u32;
        for field in (0..HEADER.len()).step_by(2) {
            for _ in 0..64 {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let new = (state >> 16) as u16;

                let mut before = ChecksumAccumulator::new();
                before.add_bytes(&HEADER);
                let old = u16::from_be_bytes([HEADER[field], HEADER[field + 1]]);

                let mut changed = HEADER;
                changed[field..field + 2].copy_from_slice(&new.to_be_bytes());
                let mut after = ChecksumAccumulator::new();
                after.add_bytes(&changed);

                assert_eq!(
                    update_u16(before.finish(), old, new),
                    after.finish(),
                    "field {field} to {new:#06x}"
                );
            }
        }
    }
}
