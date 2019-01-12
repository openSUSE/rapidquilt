// Licensed under the MIT license. See LICENSE.md

use std::fmt;
use std::hash::BuildHasherDefault;

use indexmap::IndexSet;


pub struct Stats {
    lines: usize,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LineInterner Statistics (lines: {})", self.lines)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct LineId(u32); // 4G interned slices ought to be enough for everybody...

impl<'a> fmt::Debug for LineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

pub struct LineInterner<'a> {
    set: IndexSet<&'a [u8], BuildHasherDefault<seahash::SeaHasher>>,
}

impl<'a> LineInterner<'a> {
    pub fn new() -> Self {
        Self {
            set: IndexSet::default(),
        }
    }

    pub fn add(&mut self, bytes: &'a [u8]) -> LineId {
        // There is nothing like empty line. Each line has at least '\n'. If the
        // last line in file is not terminated by '\n', it still has some characters,
        // otherwise it would not exist.
        debug_assert!(!bytes.is_empty());

        LineId(self.set.insert_full(bytes).0 as u32)
    }

    pub fn get(&self, id: LineId) -> Option<&'a [u8]> {
        self.set.get_index(id.0 as usize).cloned() // Cloned for Option<&&[u8]> -> Option<&[u8]>
    }

    pub fn stats(&self) -> Stats {
        Stats {
            lines: self.set.len(),
        }
    }
}

impl<'a> fmt::Debug for LineInterner<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "LineInterner {{ set:")?;
        for (i, item) in self.set.iter().enumerate() {
            writeln!(f, "{}:\t\"{}\"", i, String::from_utf8_lossy(item))?;
        }
        write!(f, " }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_test() {
        let mut interner = LineInterner::new();
        let id1 = interner.add(b"aaa");
        let id2 = interner.add(b"bbb");
        let id3 = interner.add(&b"-aaa-"[1..=3]);
        assert_eq!(id1, id3);
        assert_ne!(id1, id2);

        assert!(interner.get(id1) == Some(b"aaa"));
        assert!(interner.get(id2) == Some(b"bbb"));
    }
}
