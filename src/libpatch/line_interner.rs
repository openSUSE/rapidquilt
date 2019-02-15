// Licensed under the MIT license. See LICENSE.md

use std::fmt;
use std::hash::BuildHasherDefault;

use indexmap::IndexSet;
use std::hash::Hash;
use std::hash::Hasher;


pub struct Stats {
    lines: usize,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LineInterner Statistics (lines: {})", self.lines)
    }
}

/// ID that is given to every unique line
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LineId(u32); // 4G interned slices ought to be enough for everybody...

impl<'a> fmt::Debug for LineId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// A newtype around `&[u8]` that makes lines ending with "\r\n" act like if they ended with "\n"
/// when hashing and comparing. Note that lines with no newline marker are still distinct from lines
/// with marker.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq)]
struct EOLIgnoringLine<'a>(&'a [u8]);

impl<'a> Hash for EOLIgnoringLine<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        if self.0.ends_with(b"\r\n") {
            self.0[0..self.0.len() - 2].hash(state);
        } else {
            self.0[0..self.0.len() - 1].hash(state);
        }
    }
}

impl<'a> PartialEq<Self> for EOLIgnoringLine<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (self.0.ends_with(b"\r\n"), other.0.ends_with(b"\r\n")) {
            (true, true) => self.0[0..self.0.len() - 2] == other.0[0..other.0.len() - 2],
            (true, false) => self.0[0..self.0.len() - 2] == other.0[0..other.0.len() - 1] && other.0[other.0.len() - 1] == b'\n',
            (false, true) => self.0[0..self.0.len() - 1] == other.0[0..other.0.len() - 2] && self.0[self.0.len() - 1] == b'\n',
            (false, false) => self.0 == other.0,
        }
    }
}

/// A tool that interns lines and assigns them `LineId`s.
///
/// A line is a non-empty sequence of bytes that may end with b'\n' (but
/// doesn't have to, e.g. if it was the last line of a file that did not
/// end with b'\n')
pub struct LineInterner<'a> {
    set: IndexSet<EOLIgnoringLine<'a>, BuildHasherDefault<seahash::SeaHasher>>,
}

impl<'a> LineInterner<'a> {
    pub fn new() -> Self {
        Self {
            set: IndexSet::default(),
        }
    }

    /// Add this line to the interner.
    ///
    /// If the same line was added before, its `LineId` is returned. Otherwise
    /// new one is assigned to it.
    pub fn add(&mut self, bytes: &'a [u8]) -> LineId {
        // There is nothing like empty line. Each line has at least '\n'. If the
        // last line in file is not terminated by '\n', it still has some characters,
        // otherwise it would not exist.
        debug_assert!(!bytes.is_empty());

        LineId(self.set.insert_full(EOLIgnoringLine(bytes)).0 as u32)
    }

    /// Get the line for given `LineId`. Returns `None` if that id isn't known.
    pub fn get(&self, id: LineId) -> Option<&'a [u8]> {
        self.set.get_index(id.0 as usize).cloned().map(|f| f.0) // Cloned for Option<&&[u8]> -> Option<&[u8]>
    }

    /// Get statistics
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
            writeln!(f, "{}:\t\"{}\"", i, String::from_utf8_lossy(item.0))?;
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

    #[test]
    fn eol_ignoring_line() {
        let line_linux = EOLIgnoringLine(b"test\n");
        let line_windows = EOLIgnoringLine(b"test\r\n");
        let line_no_nl = EOLIgnoringLine(b"test");

        fn get_hash<T: Hash>(t: &T) -> u64 {
            let mut hasher = seahash::SeaHasher::default();
            t.hash(&mut hasher);
            hasher.finish()
        }

        assert_eq!(get_hash(&line_linux), get_hash(&line_linux));
        assert_eq!(get_hash(&line_windows), get_hash(&line_windows));
        assert_eq!(get_hash(&line_no_nl), get_hash(&line_no_nl));
        assert_eq!(get_hash(&line_linux), get_hash(&line_windows));

        // Technically the following two tests are not correct. It could happen that the two hashes
        // will end up the same. If this test ever start failing, first just try to change the sample
        // string to something else. If it is still failing, then we are probably generating hashes
        // that are too prone to collision.
        assert_ne!(get_hash(&line_linux), get_hash(&line_no_nl));
        assert_ne!(get_hash(&line_windows), get_hash(&line_no_nl));

        assert_eq!(line_linux, line_linux);
        assert_eq!(line_windows, line_windows);
        assert_eq!(line_no_nl, line_no_nl);
        assert_eq!(line_linux, line_windows);
        assert_ne!(line_linux, line_no_nl);
        assert_ne!(line_windows, line_no_nl);
    }

    #[test]
    fn eol_test() {
        let mut interner = LineInterner::new();
        let line_linux = interner.add(b"test\n");
        let line_windows = interner.add(b"test\r\n");
        let line_no_nl = interner.add(b"test");

        assert_eq!(line_linux, line_windows);
        assert_ne!(line_linux, line_no_nl);
        assert_ne!(line_windows, line_no_nl);

        assert_eq!(interner.get(line_linux), Some(&b"test\n"[..]));
        assert_eq!(interner.get(line_windows), Some(&b"test\n"[..])); // We should get back the linux one, because that's the first that went in
        assert_eq!(interner.get(line_no_nl), Some(&b"test"[..]));
    }
}
