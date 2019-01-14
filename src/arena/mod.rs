use std::io;
use std::fmt;
use std::path::Path;

mod file_arena;
mod mmap_arena;

pub use self::file_arena::FileArena;
pub use self::mmap_arena::MmapArena;


pub trait Arena: Sync {
    /// Load the file and return byte slice of its complete content. The slice
    /// is valid as long as this object is alive. (Same lifetimes.)
    fn load_file(&self, path: &Path) -> Result<&[u8], io::Error>;

    /// Get statistics
    fn stats(&self) -> Stats;
}

pub struct Stats {
    loaded_files: usize,
    total_size: usize,
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Arena Statistics (loaded files: {}, total size: {} B)", self.loaded_files, self.total_size)
    }
}
