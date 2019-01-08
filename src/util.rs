// Licensed under the MIT license. See LICENSE.md

use memchr::{memchr_iter, Memchr};


struct LinesWithEndings<'a> {
    input: &'a [u8],
    previous_offset: usize,
    iter: Memchr<'a>,
}

impl<'a> LinesWithEndings<'a> {
    fn new(input: &'a [u8]) -> LinesWithEndings<'a> {
        LinesWithEndings {
            input,
            previous_offset: 0,
            iter: memchr_iter(b'\n', input),
        }
    }
}

impl<'a> Iterator for LinesWithEndings<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<&'a [u8]> {
        if let Some(offset) = self.iter.next() {
            let previous_offset = self.previous_offset;
            self.previous_offset = offset + 1;

            Some(&self.input[previous_offset..=offset])
        } else {
            if self.previous_offset >= self.input.len() {
                return None;
            }

            let previous_offset = self.previous_offset;
            self.previous_offset = self.input.len();

            Some(&self.input[previous_offset..])
        }
    }
}

/// This splits the byte slice into subslices by newline character and keeps
/// the newline character in the subslice. The only possible expection is the
/// last subslice in case there was no newline character at the end.
pub fn split_lines_with_endings(input: &[u8]) -> impl Iterator<Item = &[u8]> {
    LinesWithEndings::new(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let mut l = split_lines_with_endings(b"aaa\nbbb\nccc\n");

        assert!(l.next() == Some(b"aaa\n"));
        assert!(l.next() == Some(b"bbb\n"));
        assert!(l.next() == Some(b"ccc\n"));
        assert!(l.next() == None);
    }

    #[test]
    fn single_line() {
        let mut l = split_lines_with_endings(b"aaa\n");

        assert!(l.next() == Some(b"aaa\n"));
        assert!(l.next() == None);
    }

    #[test]
    fn empty() {
        let mut l = split_lines_with_endings(b"\n");

        assert!(l.next() == Some(b"\n"));
        assert!(l.next() == None);
    }

    #[test]
    fn basic_no_trailing_newline() {
        let mut l = split_lines_with_endings(b"aaa\nbbb\nccc");

        assert!(l.next() == Some(b"aaa\n"));
        assert!(l.next() == Some(b"bbb\n"));
        assert!(l.next() == Some(b"ccc"));
        assert!(l.next() == None);
    }

    #[test]
    fn single_line_no_trailing_newline() {
        let mut l = split_lines_with_endings(b"aaa");

        assert!(l.next() == Some(b"aaa"));
        assert!(l.next() == None);
    }

    #[test]
    fn empty_no_trailing_newline() {
        let mut l = split_lines_with_endings(b"");

        assert!(l.next() == None);
    }
}
