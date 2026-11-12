use super::EncodeError;

/// Writes a header or frame into a caller's buffer.
///
/// `encoded_len` is exact, so a caller can size one buffer and reuse it.
/// `encode_into` returns how many bytes it wrote, which is always
/// `encoded_len` when it succeeds.
pub trait Encode {
    fn encoded_len(&self) -> usize;

    fn encode_into(&self, buffer: &mut [u8]) -> Result<usize, EncodeError>;

    /// Allocates a buffer of the right size and encodes into it. The
    /// convenience form; the hot path uses `encode_into`.
    fn build(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buffer = vec![0; self.encoded_len()];
        let written = self.encode_into(&mut buffer)?;
        buffer.truncate(written);
        Ok(buffer)
    }
}
