// Licensed under the MIT license. See LICENSE.md

use std::fs;
use std::io;
use std::marker::PhantomData;
use std::mem::transmute;
use std::path::Path;
use std::sync::Mutex;
use std::vec::Vec;

use super::{Arena, Stats};

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
}

impl<'a> Arena for FileArena<'a> {
    /// Load the file and return byte slice of its complete content. The slice
    /// is valid as long as this object is alive. (Same lifetimes.)
    fn load_file(&self, path: &Path) -> Result<&[u8], io::Error> {
        let data = fs::read(path)?.into_boxed_slice();

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

    /// Get statistics
    fn stats(&self) -> Stats {
        let files = self.files.lock().unwrap(); // NOTE(unwrap): If the lock is poisoned, some other thread panicked. We may as well.

        Stats {
            loaded_files: files.len(),
            total_size: files.iter().map(|f| f.len()).sum(),
        }
    }
}
