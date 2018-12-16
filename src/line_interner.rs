use std::collections::HashMap;
use std::fmt;
use std::hash::BuildHasherDefault;
use std::str;
use std::vec::Vec;

use seahash;


#[derive(Clone, Copy, PartialEq)]
pub struct LineId(u32); // 4G interned slices ought to be enough for everybody...

pub const EMPTY_LINE_ID: LineId = LineId(0);
pub const EMPTY_LINE_SLICE: [u8; 0] = [];

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
        let vec = vec!(&EMPTY_LINE_SLICE as &[u8]);
        let mut map = HashMap::default();
        map.insert(&EMPTY_LINE_SLICE as &[u8], EMPTY_LINE_ID);

        Self {
            vec,
            map,
        }
    }

    pub fn add(&mut self, bytes: &'a [u8]) -> LineId {
        // This is written strangely because of borrow checker limitation
        // It could be done nicely with entry and or_insert_with if we had NLL
        let id = self.map.entry(bytes).or_insert(LineId(self.vec.len() as u32));
        if id.0 as usize == self.vec.len() {
            self.vec.push(bytes);
        }
        *id
    }

    pub fn get(&self, id: LineId) -> Option<&'a [u8]> {
        self.vec.get(id.0 as usize).map(|bytes| *bytes)
    }
}

impl<'a> fmt::Debug for LineInterner<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LineInterner {{ vec:\n")?;
        for (i, item) in self.vec.iter().enumerate() {
            write!(f, "{}:\t", i)?;
            match str::from_utf8(item) {
                Ok(string) => write!(f, "\"{}\"", string)?,
                Err(error) => write!(f, "<{}>", error)?,
            }
            write!(f, "\n")?
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
