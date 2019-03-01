use std::cmp::min;
use std::collections::HashSet;
use std::hash::Hash;
use std::hash::BuildHasherDefault;
use std::ops::{Index, Range, RangeFull};
use std::cell::Ref;


// TODO: Any standard trait to use instead of this?
pub trait HayStack<T> /*: Index<usize, Output = T> +
                        Index<Range<usize>, Output = [T]> +
                        Index<RangeFull, Output = [T]>*/
{
    fn len(&self) -> usize;

    fn get(&self, index: usize) -> Ref<T>;
    fn slice(&self, range: Range<usize>) -> Ref<[T]>;
    fn full_slice(&self) -> Ref<[T]>;
}

//impl<T, A> HayStack<T> for A
//    where A: AsRef<[T]> + Index<usize, Output = T> +
//    Index<Range<usize>, Output = [T]> +
//    Index<RangeFull, Output = [T]>
//{
//    fn len(&self) -> usize {
//        self.as_ref().len()
//    }
//}

//impl<T, A> HayStack<T> for A
//    where A: AsRef<[T]> + Index<usize, Output = T> +
//    Index<Range<usize>, Output = [T]> +
//    Index<RangeFull, Output = [T]>
//{
//    fn len(&self) -> usize {
//        self.as_ref().len()
//    }
//
//    fn get(&self, index: usize) -> Ref<&T> {
//        &self[index]
//    }
//
//    fn slice(&self, range: Range<usize>) -> &[T] {
//        &self[range]
//    }
//
//    fn full_slice(&self) -> &[T] {
//        &self[..]
//    }
//}

/*
pub trait HayStack<T> {
    fn get(&self, idx: usize) -> Option<&T>;

    /// Panics if the range is out-of-range! If sometihng is in range can be deremined only by the
    /// `get` function.
    fn slice(&self, range: Range<usize>) -> &[T];
}

impl<T, A> HayStack<T> for A where A: AsRef<[T]> + Index<usize, Output = T> + Index<Range<usize>, Output = [T]> {
    fn get(&self, idx: usize) -> Option<&T> {
        if idx < self.as_ref().len() {
            Some(&self[idx])
        } else {
            None
        }
    }

    fn slice(&self, range: Range<usize>) -> &[T] {
        &self[range]
    }
}*/




/// Horspool-like algorithm optimized for searching with huge alphabets where
/// letters are rarely repeated. I.e. useful for searching arrays of `LineId`s
/// representing interned files.
pub struct Searcher<'needle, T>
where T: Clone + Eq + Hash + PartialEq {
    needle: &'needle [T],
    filter: HashSet<T, BuildHasherDefault<seahash::SeaHasher>>, // Note: This turned out to be faster than any of the filters from probabilistic-collections
}

impl<'needle, T> Searcher<'needle, T>
where T: Clone + Eq + Hash + PartialEq {
    pub fn new(needle: &'needle [T]) -> Self {
        let mut filter = HashSet::default();

        for item in needle {
            filter.insert(item.clone());
        }

        Searcher {
            needle,
            filter
        }
    }

    pub fn search_in<'haystack: 'searcher, 'searcher, H: HayStack<T> + 'searcher>(&'searcher self, haystack: &'haystack H) -> impl Iterator<Item = usize> + 'searcher {
        SearcherIterator {
            searcher: self,
            position: 0,
            haystack,
        }
    }
}

struct SearcherIterator<'needle, 'haystack, 'searcher, T, H>
where T: Clone + Eq + Hash + PartialEq,
      H: HayStack<T>
{
    searcher: &'searcher Searcher<'needle, T>,
    position: usize,
    haystack: &'haystack H,
}

impl<'needle, 'haystack, 'searcher, T, H> Iterator for SearcherIterator<'needle, 'haystack, 'searcher, T, H>
where T: Clone + Eq + Hash + PartialEq,
      H: HayStack<T>
{
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        // If the needle is zero-length, we'll just find nothing. TODO: Would there be other appropriate behavior?
        if self.searcher.needle.is_empty() {
            return None;
        }

        loop {
            // If we are so close to the end that the needle can not be there, search is over.
            if self.position + self.searcher.needle.len() > self.haystack.len() {
                return None;
            }

            // Check if the last element in the current window is one of the needle's characters...
            let last_item = self.haystack.get(self.position + self.searcher.needle.len() - 1);
            if self.searcher.filter.contains(&*last_item) {
                // ... it is one of them, manually explore the current window.
                for pos in self.position..min(self.position + self.searcher.needle.len(), self.haystack.len() + 1 - self.searcher.needle.len()) {
                    if &*self.haystack.slice(pos..(pos + self.searcher.needle.len())) == self.searcher.needle {
                        // We found one! Move position behind it and return it.
                        self.position = pos + 1;
                        return Some(self.position - 1);
                    }
                }
            }

            // The filter said it isn't there. Skip ahead the whole needle length ...
            self.position += self.searcher.needle.len();
            // ... and try again.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /*
    #[test]
    fn basic1() {
        let searcher = Searcher::new(b"abc");
        let mut iter = searcher.search_in(bla(b"xabcx"));

        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn basic2() {
        let searcher = Searcher::new(b"abc");
        let mut iter = searcher.search_in(b"xxabcxx");

        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn basic3() {
        let searcher = Searcher::new(b"abc");
        let mut iter = searcher.search_in(b"xxxabcxxx");

        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn match_full() {
        let searcher = Searcher::new(b"abc");
        let mut iter = searcher.search_in(b"abc");

        assert_eq!(iter.next(), Some(0));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn no_match_other_letters() {
        let searcher = Searcher::new(b"xyzqwerty");
        let mut iter = searcher.search_in(b"abc");

        assert_eq!(iter.next(), None);
    }

    #[test]
    fn no_match_same_letters() {
        let searcher = Searcher::new(b"bacbacabbacb");
        let mut iter = searcher.search_in(b"abc");

        assert_eq!(iter.next(), None);
    }

    #[test]
    fn no_match_too_short() {
        let searcher = Searcher::new(b"bb");
        let mut iter = searcher.search_in(b"abc");

        assert_eq!(iter.next(), None);
    }

    #[test]
    fn multiple_matches1() {
        let searcher = Searcher::new(b"abc");
        let mut iter = searcher.search_in(b"abcabcabcabc");

        assert_eq!(iter.next(), Some(0));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(6));
        assert_eq!(iter.next(), Some(9));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn multiple_matches2() {
        let searcher = Searcher::new(b"abc");
        let mut iter = searcher.search_in(b"abcopopabcqeqeqabc");

        assert_eq!(iter.next(), Some(0));
        assert_eq!(iter.next(), Some(7));
        assert_eq!(iter.next(), Some(15));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn multiple_matches_overlapping() {
        let searcher = Searcher::new(b"aaa");
        let mut iter = searcher.search_in(b"aaaaaaaaa");

        assert_eq!(iter.next(), Some(0));
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), Some(4));
        assert_eq!(iter.next(), Some(5));
        assert_eq!(iter.next(), Some(6));
        assert_eq!(iter.next(), None);
    }
    */
}

#[cfg(test)]
#[cfg(feature = "bencher")]
mod benchmarks {
    use super::*;
    use test::{Bencher, black_box};

    fn prepare_big_big() -> (Vec<u32>, Vec<u32>) {
        let haystack = (0..10000).map(|i| i % 500).collect();
        let needle = (100..140).collect();

        (haystack, needle)
    }

    fn prepare_big_small() -> (Vec<u32>, Vec<u32>) {
        let haystack = (0..10000).map(|i| i % 500).collect();
        let needle = (100..107).collect();

        (haystack, needle)
    }

    fn prepare_small_big() -> (Vec<u32>, Vec<u32>) {
        let haystack = (0..500).map(|i| i % 150).collect();
        let needle = (100..140).collect();

        (haystack, needle)
    }

    fn prepare_small_small() -> (Vec<u32>, Vec<u32>) {
        let haystack = (0..500).map(|i| i % 150).collect();
        let needle = (100..107).collect();

        (haystack, needle)
    }

    #[bench]
    fn bench_searcher_big_big(b: &mut Bencher) {
        let (haystack, needle) = prepare_big_big();

        b.iter(|| {
            for i in Searcher::new(&needle).search_in(&haystack) { black_box(i); }
        });
    }

    #[bench]
    fn bench_naive_big_big(b: &mut Bencher) {
        let (haystack, needle) = prepare_big_big();

        b.iter(|| {
            for pos in 0..(haystack.len() - needle.len() + 1) {
                if &haystack[pos..(pos + needle.len())] == &needle[..] {
                    black_box(pos);
                }
            }
        });
    }

    #[bench]
    fn bench_searcher_big_small(b: &mut Bencher) {
        let (haystack, needle) = prepare_big_small();

        b.iter(|| {
            for i in Searcher::new(&needle).search_in(&haystack) { black_box(i); }
        });
    }

    #[bench]
    fn bench_naive_big_small(b: &mut Bencher) {
        let (haystack, needle) = prepare_big_small();

        b.iter(|| {
            for pos in 0..(haystack.len() - needle.len() + 1) {
                if &haystack[pos..(pos + needle.len())] == &needle[..] {
                    black_box(pos);
                }
            }
        });
    }

    #[bench]
    fn bench_searcher_small_big(b: &mut Bencher) {
        let (haystack, needle) = prepare_small_big();

        b.iter(|| {
            for i in Searcher::new(&needle).search_in(&haystack) { black_box(i); }
        });
    }

    #[bench]
    fn bench_naive_small_big(b: &mut Bencher) {
        let (haystack, needle) = prepare_small_big();

        b.iter(|| {
            for pos in 0..(haystack.len() - needle.len() + 1) {
                if &haystack[pos..(pos + needle.len())] == &needle[..] {
                    black_box(pos);
                }
            }
        });
    }

    #[bench]
    fn bench_searcher_small_small(b: &mut Bencher) {
        let (haystack, needle) = prepare_small_small();

        b.iter(|| {
            for i in Searcher::new(&needle).search_in(&haystack) { black_box(i); }
        });
    }

    #[bench]
    fn bench_naive_small_small(b: &mut Bencher) {
        let (haystack, needle) = prepare_small_small();

        b.iter(|| {
            for pos in 0..(haystack.len() - needle.len() + 1) {
                if &haystack[pos..(pos + needle.len())] == &needle[..] {
                    black_box(pos);
                }
            }
        });
    }
}
