// Licensed under the MIT license. See LICENSE.md

use std::collections::HashMap;
use std::fmt;
use std::hash::BuildHasherDefault;
use std::vec::Vec;

use seahash;


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
    vec: Vec<&'a [u8]>,
    map: HashMap<&'a [u8], LineId, BuildHasherDefault<seahash::SeaHasher>>,
}

impl<'a> LineInterner<'a> {
    pub fn new() -> Self {
        Self {
            vec: Vec::new(),
            map: HashMap::default(),
        }
    }

    pub fn add(&mut self, bytes: &'a [u8]) -> LineId {
        // There is nothing like empty line. Each line has at least '\n'. If the
        // last line in file is not terminated by '\n', it still has some characters,
        // otherwise it would not exist.
        assert!(!bytes.is_empty());

        // This is written strangely because of borrow checker limitation
        // It could be done nicely with entry and or_insert_with if we had NLL
        let id = self.map.entry(bytes).or_insert(LineId(self.vec.len() as u32));
        if id.0 as usize == self.vec.len() {
            self.vec.push(bytes);
        }
        *id
    }

    pub fn get(&self, id: LineId) -> Option<&'a [u8]> {
        self.vec.get(id.0 as usize).cloned() // Cloned for Option<&&[u8]> -> Option<&[u8]>
    }

    pub fn stats(&self) -> Stats {
        Stats {
            lines: self.vec.len(),
        }
    }
}

impl<'a> fmt::Debug for LineInterner<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "LineInterner {{ vec:")?;
        for (i, item) in self.vec.iter().enumerate() {
            writeln!(f, "{}:\t\"{}\"", i, String::from_utf8_lossy(item))?;
        }
        write!(f, ", map: {:?} }}", self.map)
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
