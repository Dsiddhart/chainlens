#[derive(Debug)]
pub enum ReadError {
    /// Returned when attempting to read beyond available data
    UnexpectedEndOfData,
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::UnexpectedEndOfData => write!(f, "Unexpected end of data"),
        }
    }
}

/// Simple byte cursor over a Vec<u8>
/// Used for sequential parsing of block / transaction data.
pub struct ByteReader {
    data: Vec<u8>,
    pos: usize,
}

impl ByteReader {
    /// Create a new reader from raw bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    /// Manually move the internal cursor
    /// Used when peeking ahead (e.g., SegWit marker detection)
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Bytes left to read
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Current cursor position
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Read exactly `n` bytes
    pub fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, ReadError> {
        if self.pos + n > self.data.len() {
            return Err(ReadError::UnexpectedEndOfData);
        }

        let slice = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(slice)
    }

    /// Read a single byte
    pub fn read_u8(&mut self) -> Result<u8, ReadError> {
        if self.pos >= self.data.len() {
            return Err(ReadError::UnexpectedEndOfData);
        }

        let byte = self.data[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    /// Read 2 bytes (little-endian)
    pub fn read_u16_le(&mut self) -> Result<u16, ReadError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read 4 bytes (little-endian)
    pub fn read_u32_le(&mut self) -> Result<u32, ReadError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read 8 bytes (little-endian)
    pub fn read_u64_le(&mut self) -> Result<u64, ReadError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read Bitcoin CompactSize (used in block & transaction format)
    ///
    /// Encoding:
    /// 0x00..=0xFC  → value directly
    /// 0xFD         → next 2 bytes (u16)
    /// 0xFE         → next 4 bytes (u32)
    /// 0xFF         → next 8 bytes (u64)
    pub fn read_varint(&mut self) -> Result<u64, ReadError> {
        let first = self.read_u8()?;

        match first {
            0x00..=0xFC => Ok(first as u64),
            0xFD => Ok(self.read_u16_le()? as u64),
            0xFE => Ok(self.read_u32_le()? as u64),
            0xFF => self.read_u64_le(),
        }
    }

    /// Read Bitcoin Core base-128 VARINT (used in undo data)
    ///
    /// This is NOT CompactSize.
    /// Each byte:
    /// - Lower 7 bits = data
    /// - Highest bit = continuation flag
    ///
    /// Encoding rule:
    /// Every continuation byte implies a +1 carry to the accumulated value.
    pub fn read_varint128(&mut self) -> Result<u64, ReadError> {
        let mut result: u64 = 0;

        loop {
            let byte = self.read_u8()?;

            result = (result << 7) | (byte & 0x7F) as u64;

            if (byte & 0x80) == 0 {
                return Ok(result);
            }

            // Continuation adjustment (Bitcoin Core behavior)
            result += 1;
        }
    }
}