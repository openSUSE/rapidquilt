use std::fmt;


/// ID that is given to every unique line
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct LineId(u64);

const IS_OFFSET_BIT: u64 = 0x8000_0000_00000000;

impl LineId {
    pub fn is_line_id(&self) -> bool {
        self.0 & IS_OFFSET_BIT == 0
    }

    pub fn is_offset(&self) -> bool {
        self.0 & IS_OFFSET_BIT != 0
    }

    pub fn from_offset(offset: u64) -> Self {
        assert!(offset & IS_OFFSET_BIT == 0); // Otherwise we are over tour max!

        LineId(offset | IS_OFFSET_BIT)
    }

    pub fn from_line_id(line_id: u64) -> Self {
        assert!(line_id & IS_OFFSET_BIT == 0); // Otherwise we are over our max!

        LineId(line_id)
    }

    pub fn as_offset(&self) -> u64 {
        debug_assert!(self.is_offset());
        self.0 & !IS_OFFSET_BIT
    }

    pub fn as_line_id(&self) -> u64 {
        debug_assert!(self.is_line_id());
        self.0
    }

}

/*
#[derive(Clone, Copy, Eq, Debug, Hash, PartialEq)]
#[repr(transparent)]
pub struct LineOffset(u64);

impl LineOffset {
    pub fn from_usize(v: usize) -> Self {
        LineOffset(v as u64)
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Copy, Eq, Debug, Hash, PartialEq)]
#[repr(transparent)]
pub struct LineIdOrOffset(u64);

const DISTINGUISHING_BIT: u64 = 0x8000_0000_00000000;

impl LineIdOrOffset {
    pub fn is_line_id(&self) -> bool {
        self.0 & DISTINGUISHING_BIT == 0
    }

    pub fn is_offset(&self) -> bool {
        self.0 & DISTINGUISHING_BIT != 0
    }

    pub fn as_line_id(&self) -> LineId {
        debug_assert!(self.is_line_id());

        LineId(self.0)
    }

    pub fn as_offset(&self) -> LineOffset {
        debug_assert!(self.is_offset());

        LineOffset(self.0 & !DISTINGUISHING_BIT)
    }
}

impl From<LineOffset> for LineIdOrOffset {
    fn from(v: LineOffset) -> Self {
        assert!(v.0 & DISTINGUISHING_BIT != 0);

        LineIdOrOffset(v.0 | DISTINGUISHING_BIT)
    }
}

impl From<LineId> for LineIdOrOffset {
    fn from(v: LineId) -> Self {
        assert!(v.0 & DISTINGUISHING_BIT != 0);

        LineIdOrOffset(v.0)
    }
}

impl<'a> fmt::Debug for LineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
*/