// Licensed under the MIT license. See LICENSE.md

use std::ops::{Index, Range, RangeInclusive};
use std::vec::Vec;


pub struct EditBuffer<'a, T: Copy> {
    parts: Vec<&'a [T]>,
    size_in_parts: usize,
    remaining: &'a [T],
}

impl<'a, T: Copy> EditBuffer<'a, T> {
    pub fn new(slice: &'a [T]) -> Self {
        EditBuffer {
            parts: Vec::new(),
            size_in_parts: 0,
            remaining: slice.as_ref(),
        }
    }

    pub fn remaining(&self) -> &[T] {
        self.remaining
    }

    pub fn push_slice(&mut self, slice: &'a [T]) {
        let slice = slice.as_ref();
        self.size_in_parts += slice.len();
        self.parts.push(slice);
    }

    pub fn push_own(&mut self, count: usize) {
        let (a, b) = self.remaining.split_at(count);

        self.push_slice(a);
        self.remaining = b;
    }

    pub fn skip_own(&mut self, count: usize) {
        self.remaining = &self.remaining[count..];
    }

    pub fn frozen_len(&self) -> usize {
        self.size_in_parts
    }

    pub fn len(&self) -> usize {
        self.size_in_parts + self.remaining.len()
    }

    pub fn to_vec(mut self) -> Vec<T> {
        if !self.remaining.is_empty() {
            self.push_own(self.remaining.len());
        }

        debug_assert!(self.remaining.is_empty());

        let mut result = Vec::<T>::with_capacity(self.size_in_parts);
        for part in self.parts {
            result.extend(part);
        }

        result
    }
}

impl<'a, T: Copy> Index<usize> for EditBuffer<'a, T> {
    type Output = T;

    fn index(&self, i: usize) -> &T {
        if i < self.size_in_parts {
            panic!();
        }

        &self.remaining[i - self.size_in_parts]
    }
}

impl<'a, T: Copy> Index<Range<usize>> for EditBuffer<'a, T> {
    type Output = [T];

    fn index(&self, range: Range<usize>) -> &[T] {
        if range.start < self.size_in_parts {
            panic!();
        }

        &self.remaining[(range.start - self.size_in_parts)..(range.end - self.size_in_parts)]
    }
}

impl<'a, T: Copy> Index<RangeInclusive<usize>> for EditBuffer<'a, T> {
    type Output = [T];

    fn index(&self, range: RangeInclusive<usize>) -> &[T] {
        if *range.start() < self.size_in_parts {
            panic!();
        }

        &self.remaining[(range.start() - self.size_in_parts)..=(range.end() - self.size_in_parts)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let mut edit_buffer = EditBuffer::new(b"abcdefghi");
        edit_buffer.push_own(3);
        edit_buffer.push_slice(b"123");
        edit_buffer.push_own(3);
        edit_buffer.push_slice(b"456");
        let result = edit_buffer.to_vec();
        assert_eq!(&result, b"abc123def456ghi");
    }

    #[test]
    fn indexing() {
        let mut edit_buffer = EditBuffer::new(b"abcdef");

        assert_eq!(edit_buffer[0], b'a');
        assert_eq!(edit_buffer[1], b'b');
        assert_eq!(edit_buffer[2], b'c');
        assert_eq!(edit_buffer[3], b'd');
        assert_eq!(edit_buffer[4], b'e');
        assert_eq!(edit_buffer[5], b'f');

        edit_buffer.push_own(3);
        assert_eq!(edit_buffer[3], b'd');
        assert_eq!(edit_buffer[4], b'e');
        assert_eq!(edit_buffer[5], b'f');

        edit_buffer.push_slice(b"xxx");
        assert_eq!(edit_buffer[6], b'd');
        assert_eq!(edit_buffer[7], b'e');
        assert_eq!(edit_buffer[8], b'f');
    }

    #[test]
    fn slicing() {
        let mut edit_buffer = EditBuffer::new(b"abcdef");

        assert_eq!(&edit_buffer[0..=1], &b"ab"[..]);
        assert_eq!(&edit_buffer[0..=5], &b"abcdef"[..]);
        assert_eq!(&edit_buffer[2..=4], &b"cde"[..]);

        edit_buffer.push_own(3);
        assert_eq!(&edit_buffer[3..=4], &b"de"[..]);
        assert_eq!(&edit_buffer[4..=5], &b"ef"[..]);

        edit_buffer.push_slice(b"xxx");
        assert_eq!(&edit_buffer[6..=7], &b"de"[..]);
        assert_eq!(&edit_buffer[7..=8], &b"ef"[..]);
    }
}
