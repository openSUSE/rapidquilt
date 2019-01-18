// Licensed under the MIT license. See LICENSE.md

// use std::slice::SliceIndex;
use std::ops::{Index, Range, RangeInclusive};
use std::vec::Vec;


enum Part<'a, T> {
    Mine { src: Range<usize>, dst: usize },
    Foreign { slice: &'a [T], dst: usize },
}

pub struct EditBuffer<'a, T: Copy + Default> {
    parts: Vec<Part<'a, T>>,
    size_in_parts: usize,

    vec: &'a mut Vec<T>,
    used_from_vec: usize,
}

impl<'a, T: Copy + Default> EditBuffer<'a, T> {
    pub fn new(vec: &'a mut Vec<T>) -> Self {
        EditBuffer {
            parts: Vec::new(),
            size_in_parts: 0,

            vec: vec,
            used_from_vec: 0,
        }
    }

//     pub fn remaining(&self) -> &[T] {
//         self.remaining
//     }

    pub fn push_slice(&mut self, slice: &'a [T]) {
        self.parts.push(Part::Foreign { slice, dst: self.size_in_parts });

        self.size_in_parts += slice.len();
    }

    pub fn push_own(&mut self, count: usize) {
        if self.used_from_vec + count > self.vec.len() {
            panic!("Trying to push_own({}), but there is not enough left.", count);
        }

        self.parts.push(Part::Mine { src: self.used_from_vec..(self.used_from_vec + count), dst: self.size_in_parts });

        self.size_in_parts += count;
        self.used_from_vec += count;
    }

    pub fn skip_own(&mut self, count: usize) {
        if self.used_from_vec + count > self.vec.len() {
            panic!("Trying to skip_own({}), but there is not enough left.", count);
        }

        self.used_from_vec += count;
    }

    pub fn written_len(&self) -> usize {
        self.size_in_parts
    }

    pub fn len(&self) -> usize {
        self.vec.len() - self.used_from_vec + self.size_in_parts
    }

//     pub fn to_vec(mut self) -> Vec<T> {
//         if !self.remaining.is_empty() {
//             self.push_own(self.remaining.len());
//         }
//
//         debug_assert!(self.remaining.is_empty());
//
//         let mut result = Vec::<T>::with_capacity(self.size_in_parts);
//         for part in self.parts {
//             result.extend(part);
//         }
//
//         result
//     }

    pub fn commit(mut self) {
        // If there is anything left, push it in
        if self.vec.len() > self.used_from_vec {
            self.push_own(self.vec.len() - self.used_from_vec);
        }

        // Ensure enough capacity
        if self.len() > self.vec.len() {
//             self.vec.reserve(self.len() - self.vec.len());

            self.vec.resize(self.len(), Default::default()); // XXX: This will construct all remaining elements with Defaults. We may want to try unsafe unitialized too.. (set_len?)
        }

        // Copy the pieces, one by one from that end to beginning
        let buf = self.vec.as_mut_slice();

        for part in self.parts.iter().rev() {
            match part {
                Part::Mine { src, dst } => {
//                     buf.copy_within(src, dst); // XXX: unstable

                    unsafe {
                        std::ptr::copy(
                            buf.get_unchecked(src.start),
                            buf.get_unchecked_mut(*dst),
                            src.len(),
                        );
                    }
                }

                Part::Foreign { slice, dst } => {
                    let buf_dst = &mut buf[*dst..(*dst + slice.len())];
                    buf_dst.copy_from_slice(slice);
                }
            }
        }
    }
}

impl<'a, T: Copy + Default> Index<usize> for EditBuffer<'a, T> {
    type Output = T;

    fn index(&self, i: usize) -> &T {
        if i < self.size_in_parts {
            panic!();
        }

        &self.vec[i - self.size_in_parts + self.used_from_vec]
    }
}

impl<'a, T: Copy + Default> Index<Range<usize>> for EditBuffer<'a, T> {
    type Output = [T];

    fn index(&self, range: Range<usize>) -> &[T] {
        if range.start < self.size_in_parts {
            panic!();
        }

        &self.vec[(range.start - self.size_in_parts + self.used_from_vec)..(range.end - self.size_in_parts + self.used_from_vec)]
    }
}

impl<'a, T: Copy + Default> Index<RangeInclusive<usize>> for EditBuffer<'a, T> {
    type Output = [T];

    fn index(&self, range: RangeInclusive<usize>) -> &[T] {
        if *range.start() < self.size_in_parts {
            panic!();
        }

        &self.vec[(range.start() - self.size_in_parts + self.used_from_vec)..=(range.end() - self.size_in_parts + self.used_from_vec)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let mut buf = b"abcdefghi".to_vec();
        let mut edit_buffer = EditBuffer::new(&mut buf);
        edit_buffer.push_own(3);
        edit_buffer.push_slice(b"123");
        edit_buffer.push_own(3);
        edit_buffer.push_slice(b"456");
        edit_buffer.commit();
        assert_eq!(&buf, b"abc123def456ghi");
    }

    #[test]
    fn indexing() {
        let mut buf = b"abcdef".to_vec();
        let mut edit_buffer = EditBuffer::new(&mut buf);

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
        let mut buf = b"abcdef".to_vec();
        let mut edit_buffer = EditBuffer::new(&mut buf);

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
