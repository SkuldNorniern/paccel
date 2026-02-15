use super::metadata::PacketMetadata;

#[derive(Debug, Clone, Copy)]
pub struct PacketView<'a> {
    data: &'a [u8],
    cursor: usize,
    pub metadata: Option<&'a PacketMetadata>,
}

impl<'a> PacketView<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            cursor: 0,
            metadata: None,
        }
    }

    pub fn with_metadata(data: &'a [u8], metadata: &'a PacketMetadata) -> Self {
        Self {
            data,
            cursor: 0,
            metadata: Some(metadata),
        }
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.cursor)
    }

    pub fn advance(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining() {
            return false;
        }

        self.cursor += bytes;
        true
    }

    pub fn slice(&self, start: usize, len: usize) -> Option<&'a [u8]> {
        let end = start.checked_add(len)?;
        self.data.get(start..end)
    }

    pub fn tail(&self) -> &'a [u8] {
        &self.data[self.cursor..]
    }
}
