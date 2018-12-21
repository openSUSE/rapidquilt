use std::path::{Path, PathBuf};

use crate::apply::parallel::FilenameDistributor;


#[test]
fn test_empty() {
    let f = FilenameDistributor::<String>::new(1);
    let h = f.build();
    assert_eq!(h.len(), 0);
}

#[test]
fn test_basic() {
    let thread_count = 4;

    let mut f = FilenameDistributor::new(thread_count);

    f.add("aaa", None);
    f.add("bbb", None);
    f.add("ccc", None);
    f.add("ddd", None);
    f.add("eee", None);
    f.add("fff", None);
    f.add("ggg", None);
    f.add("hhh", None);

    let h = f.build();

    // Files should be distributed among the threads.
    // We can not make any assumption about the actual distribution.
    assert_eq!(h.len(), 8);

    assert!(*h.get(&"aaa").unwrap() < thread_count);
    assert!(*h.get(&"bbb").unwrap() < thread_count);
    assert!(*h.get(&"ccc").unwrap() < thread_count);
    assert!(*h.get(&"ddd").unwrap() < thread_count);
    assert!(*h.get(&"eee").unwrap() < thread_count);
    assert!(*h.get(&"fff").unwrap() < thread_count);
    assert!(*h.get(&"ggg").unwrap() < thread_count);
    assert!(*h.get(&"hhh").unwrap() < thread_count);
}

#[test]
fn test_equal_distribution() {
    let thread_count = 4096;

    let mut f = FilenameDistributor::new(thread_count);

    f.add("aaa", None);
    f.add("bbb", None);
    f.add("ccc", None);
    f.add("ddd", None);

    let h = f.build();

    assert_eq!(h.len(), 4);

    // This may not be true if we change FilenameDistributor, but now it
    // should give each filename its own thread if there is enough threads.

    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"bbb").unwrap());
    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"ccc").unwrap());
    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"ddd").unwrap());

    assert_ne!(*h.get(&"bbb").unwrap(), *h.get(&"ccc").unwrap());
    assert_ne!(*h.get(&"bbb").unwrap(), *h.get(&"ddd").unwrap());

    assert_ne!(*h.get(&"ccc").unwrap(), *h.get(&"ddd").unwrap());
}

#[test]
fn test_rename_1() {
    let thread_count = 4096;

    let mut f = FilenameDistributor::new(thread_count);

    f.add("aaa", None);
    f.add("bbb", None);
    f.add("ccc", None);
    f.add("ddd", None);
    f.add("eee", None);
    f.add("fff", None);
    f.add("ggg", None);
    f.add("hhh", None);

    f.add("aaa", Some("bbb"));
    f.add("ggg", Some("hhh"));

    let h = f.build();

    // Files renamed to each other should be given to the same thread, but
    // separate groups should be in different threads.
    assert_eq!(*h.get(&"aaa").unwrap(), *h.get(&"bbb").unwrap());
    assert_eq!(*h.get(&"ggg").unwrap(), *h.get(&"hhh").unwrap());
    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"ggg").unwrap());
}

#[test]
fn test_rename_2() {
    let thread_count = 4096;

    let mut f = FilenameDistributor::new(thread_count);

    f.add("aaa", None);
    f.add("bbb", None);
    f.add("ccc", None);
    f.add("ddd", None);
    f.add("eee", None);
    f.add("fff", None);
    f.add("ggg", None);
    f.add("hhh", None);

    f.add("aaa", Some("bbb"));
    f.add("ggg", Some("hhh"));

    f.add("aaa", Some("ggg"));

    let h = f.build();

    // Files renamed to each other should be given to the same thread.
    assert_eq!(*h.get(&"aaa").unwrap(), *h.get(&"bbb").unwrap());
    assert_eq!(*h.get(&"ggg").unwrap(), *h.get(&"hhh").unwrap());
    assert_eq!(*h.get(&"aaa").unwrap(), *h.get(&"ggg").unwrap());
}

#[test]
fn test_rename_3() {
    let thread_count = 4096;

    let mut f = FilenameDistributor::new(thread_count);

    f.add("aaa", Some("bbb"));
    f.add("bbb", Some("ccc"));
    f.add("ccc", Some("ddd"));
    f.add("ddd", Some("eee"));
    f.add("eee", Some("fff"));
    f.add("fff", Some("ggg"));
    f.add("ggg", Some("hhh"));

    let h = f.build();

    // Files renamed to each other should be given to the same thread.
    assert_eq!(*h.get(&"aaa").unwrap(), *h.get(&"bbb").unwrap());
    assert_eq!(*h.get(&"bbb").unwrap(), *h.get(&"ccc").unwrap());
    assert_eq!(*h.get(&"ccc").unwrap(), *h.get(&"ddd").unwrap());
    assert_eq!(*h.get(&"ddd").unwrap(), *h.get(&"eee").unwrap());
    assert_eq!(*h.get(&"eee").unwrap(), *h.get(&"fff").unwrap());
    assert_eq!(*h.get(&"fff").unwrap(), *h.get(&"ggg").unwrap());
    assert_eq!(*h.get(&"ggg").unwrap(), *h.get(&"hhh").unwrap());
}

#[test]
fn test_rename_4() {
    let thread_count = 4096;

    let mut f = FilenameDistributor::new(thread_count);

    f.add("hhh", Some("ggg"));
    f.add("ggg", Some("fff"));
    f.add("fff", Some("eee"));
    f.add("eee", Some("ddd"));
    f.add("ddd", Some("ccc"));
    f.add("ccc", Some("bbb"));
    f.add("bbb", Some("aaa"));

    let h = f.build();

    // Files renamed to each other should be given to the same thread.
    assert_eq!(*h.get(&"aaa").unwrap(), *h.get(&"bbb").unwrap());
    assert_eq!(*h.get(&"bbb").unwrap(), *h.get(&"ccc").unwrap());
    assert_eq!(*h.get(&"ccc").unwrap(), *h.get(&"ddd").unwrap());
    assert_eq!(*h.get(&"ddd").unwrap(), *h.get(&"eee").unwrap());
    assert_eq!(*h.get(&"eee").unwrap(), *h.get(&"fff").unwrap());
    assert_eq!(*h.get(&"fff").unwrap(), *h.get(&"ggg").unwrap());
    assert_eq!(*h.get(&"ggg").unwrap(), *h.get(&"hhh").unwrap());
}

#[test]
fn test_rename_5() {
    let thread_count = 4096;

    let mut f = FilenameDistributor::new(thread_count);

    f.add("aaa", None);
    f.add("bbb", None);
    f.add("ccc", None);
    f.add("ddd", None);
    f.add("eee", None);
    f.add("fff", None);
    f.add("ggg", None);
    f.add("hhh", None);

    f.add("aaa", Some("bbb"));
    f.add("ggg", Some("hhh"));
    f.add("bbb", Some("ccc"));
    f.add("eee", Some("fff"));
    f.add("fff", Some("aaa"));

    let h = f.build();

    // Files renamed to each other should be given to the same thread, but
    // separate groups should be in different threads.
    assert_eq!(*h.get(&"aaa").unwrap(), *h.get(&"bbb").unwrap());
    assert_eq!(*h.get(&"ggg").unwrap(), *h.get(&"hhh").unwrap());
    assert_eq!(*h.get(&"ccc").unwrap(), *h.get(&"bbb").unwrap());
    assert_eq!(*h.get(&"eee").unwrap(), *h.get(&"fff").unwrap());
    assert_eq!(*h.get(&"fff").unwrap(), *h.get(&"aaa").unwrap());

    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"ggg").unwrap());
}

#[test]
fn test_rename_6() {
    let thread_count = 4096;

    let mut f = FilenameDistributor::new(thread_count);

    f.add("aaa", None);
    f.add("aaa", Some("bbb"));
    f.add("ccc", None);
    f.add("ddd", None);
    f.add("eee", None);
    f.add("ccc", Some("bbb"));
    f.add("fff", None);
    f.add("ggg", None);
    f.add("hhh", None);

    let h = f.build();

    // Files renamed to each other should be given to the same thread, but
    // separate groups should be in different threads.
    assert_eq!(*h.get(&"aaa").unwrap(), *h.get(&"bbb").unwrap());
    assert_eq!(*h.get(&"bbb").unwrap(), *h.get(&"ccc").unwrap());

    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"ddd").unwrap());
    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"eee").unwrap());
    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"fff").unwrap());
    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"ggg").unwrap());
    assert_ne!(*h.get(&"aaa").unwrap(), *h.get(&"hhh").unwrap());
}
