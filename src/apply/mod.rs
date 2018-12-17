use std::ffi::OsStr;
use std::path::{Path, PathBuf};

mod sequential;
mod parallel;

pub use self::sequential::apply_patches;
pub use self::parallel::apply_patches as apply_patches_parallel;


pub fn make_rej_filename<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();

    match path.extension() {
        Some(extension) => path.with_extension((extension.to_string_lossy().into_owned() + ".rej")),
        None => path.with_extension("rej")
    }
}
