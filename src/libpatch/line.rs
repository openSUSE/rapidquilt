

/// ID that is given to every unique line
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct LineId(u64);

const IS_OFFSET_BIT: u64 = 0x8000_0000_00000000;

impl LineId {
    pub fn is_line_id(&self) -> bool {
        self.0 & IS_OFFSET_BIT == 0
    }

    pub fn is_offset_and_length(&self) -> bool {
        self.0 & IS_OFFSET_BIT != 0
    }

    pub fn from_offset_and_length(offset: u32, length: u32) -> Self {
        let value = (length as u64) << 32 | offset as u64;

        assert!(value & IS_OFFSET_BIT == 0); // Otherwise we are over tour max!

        LineId(value | IS_OFFSET_BIT)
    }

    pub fn from_line_id(line_id: u64) -> Self {
        assert!(line_id & IS_OFFSET_BIT == 0); // Otherwise we are over our max!

        LineId(line_id)
    }

    pub fn as_offset_and_length(&self) -> (u32, u32) {
        debug_assert!(self.is_offset_and_length());
        let value = self.0 & !IS_OFFSET_BIT;
        ((value & 0xffff_fffff) as u32, (value >> 32) as u32)
    }

    pub fn as_line_id(&self) -> u64 {
        debug_assert!(self.is_line_id());
        self.0
    }
}
