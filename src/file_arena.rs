// Licensed under the MIT license. See LICENSE.md

use std::marker::PhantomData;
use std::vec::Vec;
use std::io;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::mem::transmute;


pub struct Stats {
    loaded_files: usize,
    total_size: usize,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FileArena Statistics (loaded files: {}, total size: {} B)", self.loaded_files, self.total_size)
    }
}

/// Utility that reads files and keeps them loaded in immovable place in memory
/// for its lifetime. So the returned byte slices can be used as long as the
/// object of this struct is alive.
pub struct FileArena<'a> {
    files: Mutex<Vec<Box<[u8]>>>,
    _phantom: PhantomData<&'a [u8]>,
}

impl<'a> FileArena<'a> {
    pub fn new() -> Self {
        Self {
            files: Mutex::new(Vec::new()),
            _phantom: PhantomData,
        }
    }

    pub fn load_file<P: AsRef<Path>>(&self, path: P) -> Result<&'a [u8], io::Error> {
        let data = fs::read(path.as_ref())?.into_boxed_slice();

        let slice = unsafe {
            // We guarantee to the compiler that we will hold the content of the
            // Box for as long as we are alive. We will place the Box into the
            // `files` Vec and we never delete items from there. Reallocating the
            // `files` backing storage doesn't affect the content of the Boxes.
            transmute::<&[u8], &'a [u8]>(&data)
        };

        self.files.lock().unwrap().push(data); // NOTE(unwrap): If the lock is poisoned, some other thread panicked. We may as well.

        Ok(slice)
    }

    pub fn stats(&self) -> Stats {
        let files = self.files.lock().unwrap(); // NOTE(unwrap): If the lock is poisoned, some other thread panicked. We may as well.

        Stats {
            loaded_files: files.len(),
            total_size: files.iter().map(|f| f.len()).sum(),
        }
    }
}
