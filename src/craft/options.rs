use super::EncodeError;

/// The forty bytes of options IPv4 and TCP each cap out at.
pub const MAX_OPTIONS: usize = 40;

/// Header options, stored inline so a builder never allocates.
///
/// Both IPv4 and TCP bound their option space at forty bytes and require it to
/// be a multiple of four, so one type serves both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    bytes: [u8; MAX_OPTIONS],
    len: u8,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_OPTIONS],
            len: 0,
        }
    }
}

impl Options {
    pub fn new(bytes: &[u8]) -> Result<Self, EncodeError> {
        if bytes.len() > MAX_OPTIONS {
            return Err(EncodeError::OptionsTooLong {
                max: MAX_OPTIONS,
                got: bytes.len(),
            });
        }
        if !bytes.len().is_multiple_of(4) {
            return Err(EncodeError::OptionsNotAligned { got: bytes.len() });
        }
        let mut stored = Self::default();
        stored.bytes[..bytes.len()].copy_from_slice(bytes);
        // Bounded just above, so this cannot fail.
        stored.len = u8::try_from(bytes.len()).unwrap_or(0);
        Ok(stored)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodeError, MAX_OPTIONS, Options};

    #[test]
    fn options_are_bounded_and_aligned() {
        assert_eq!(Options::default().as_slice(), &[] as &[u8]);
        assert_eq!(Options::new(&[1, 2, 3, 4]).expect("aligned").len(), 4);
        assert_eq!(
            Options::new(&[0; 44]),
            Err(EncodeError::OptionsTooLong {
                max: MAX_OPTIONS,
                got: 44
            })
        );
        assert_eq!(
            Options::new(&[1, 2, 3]),
            Err(EncodeError::OptionsNotAligned { got: 3 })
        );
    }
}
