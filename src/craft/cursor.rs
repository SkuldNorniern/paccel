use super::EncodeError;

/// Writes big-endian fields into a caller's buffer, refusing to run past it.
///
/// Every write is checked, so an encoder can be written as a straight run of
/// writes without tracking the remaining room itself.
pub(crate) struct WriteCursor<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> WriteCursor<'a> {
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }

    pub(crate) fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let end = self.position + bytes.len();
        let given = self.buffer.len();
        let room = self
            .buffer
            .get_mut(self.position..end)
            .ok_or(EncodeError::BufferTooSmall { needed: end, given })?;
        room.copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    pub(crate) fn write_u8(&mut self, value: u8) -> Result<(), EncodeError> {
        self.write_bytes(&[value])
    }

    pub(crate) fn write_u16_be(&mut self, value: u16) -> Result<(), EncodeError> {
        self.write_bytes(&value.to_be_bytes())
    }

    pub(crate) fn write_u32_be(&mut self, value: u32) -> Result<(), EncodeError> {
        self.write_bytes(&value.to_be_bytes())
    }

    /// Overwrites two bytes already written, for a checksum that could not be
    /// known until the rest of the header was in place.
    pub(crate) fn patch_u16_be(&mut self, at: usize, value: u16) -> Result<(), EncodeError> {
        let given = self.buffer.len();
        let room = self
            .buffer
            .get_mut(at..at + 2)
            .ok_or(EncodeError::BufferTooSmall {
                needed: at + 2,
                given,
            })?;
        room.copy_from_slice(&value.to_be_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{EncodeError, WriteCursor};

    #[test]
    fn a_cursor_writes_fields_and_stops_at_the_end() {
        let mut buffer = [0u8; 7];
        let mut cursor = WriteCursor::new(&mut buffer);
        cursor.write_u8(0x01).expect("room for a byte");
        cursor.write_u16_be(0x0203).expect("room for two");
        cursor.write_u32_be(0x0405_0607).expect("room for four");
        assert_eq!(cursor.position(), 7);
        assert_eq!(
            cursor.write_u8(0x08),
            Err(EncodeError::BufferTooSmall {
                needed: 8,
                given: 7
            })
        );
        assert_eq!(buffer, [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn a_patch_rewrites_bytes_already_written() {
        let mut buffer = [0u8; 4];
        let mut cursor = WriteCursor::new(&mut buffer);
        cursor.write_u32_be(0).expect("room");
        cursor.patch_u16_be(1, 0xbeef).expect("in the buffer");
        assert!(cursor.patch_u16_be(3, 0).is_err(), "past the end");
        assert_eq!(buffer, [0x00, 0xbe, 0xef, 0x00]);
    }
}
