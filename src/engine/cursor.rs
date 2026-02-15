#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn with_pos(data: &'a [u8], pos: usize) -> Option<Self> {
        if pos > data.len() {
            return None;
        }
        Some(Self { data, pos })
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn advance(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining() {
            return false;
        }
        self.pos += bytes;
        true
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    pub fn read_u16_be(&mut self) -> Option<u16> {
        let bytes = self.read_exact(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_exact(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    pub fn peek_u8_at(&self, offset: usize) -> Option<u8> {
        self.data.get(self.pos.checked_add(offset)?).copied()
    }
}
