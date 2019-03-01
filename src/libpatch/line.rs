use std::fmt;


/// ID that is given to every unique line
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct LineId(u64);

impl LineId {
    pub fn from_usize(v: usize) -> Self {
        assert!(v <= std::u64::MAX); // This is noop for <= 64-bit systems

        LineId(v as u64)
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct LineOffset(u64);

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
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
}

impl From<LineOffset> for LineIdOrOffset {
    fn from(v: LineOffset) -> Self {
        assert!(v.0 & DISTINGUISHING_BIT != 0); // Make sure it is no bigger than 2^31

        LineIdOrOffset(v.0 | DISTINGUISHING_BIT)
    }
}

impl From<LineId> for LineIdOrOffset {
    fn from(v: LineId) -> Self {
        assert!(v.0 & DISTINGUISHING_BIT != 0); // Make sure it is no bigger than 2^31

        LineIdOrOffset(v.0 | DISTINGUISHING_BIT)
    }
}

impl<'a> fmt::Debug for LineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
