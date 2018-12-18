use std::fs::{self, File};
use std::path::{Path, PathBuf};

use failure::Error;

use crate::interned_file::InternedFile;
use crate::line_interner::LineInterner;


pub struct ApplyResult<'a> {
    pub applied_patches: &'a [PathBuf],
    pub skipped_patches: &'a [PathBuf],
}

pub fn make_rej_filename<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();

    match path.extension() {
        Some(extension) => path.with_extension(extension.to_string_lossy().into_owned() + ".rej"),
        None => path.with_extension("rej")
    }
}

pub fn save_modified_file<P: AsRef<Path>>(filename: P, file: &InternedFile, interner: &LineInterner) -> Result<(), Error> {
    let filename = filename.as_ref();

//     println!("Saving modified file: {:?}", filename);

    // First we delete it, no matter what. The fie may be a hard link and
    // we must replace it with new one, not edit the shared content.
    // We ignore the result, because it is ok if it is not there.
    // TODO: Do not ignore other errors, e.g. permissions.
    let _ = fs::remove_file(filename);

    // If the file is not tracked as deleted, re-create it with the next content.
    if !file.deleted {
        if let Some(parent) = filename.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = File::create(filename)?;
        file.write_to(&interner, &mut output)?;
    }

    Ok(())
}

pub fn save_backup_file(patch_filename: &Path, filename: &Path, original_file: &InternedFile, interner: &LineInterner) -> Result<(), Error> {
    let mut path = PathBuf::from(".pc");
    path.push(patch_filename);
    path.push(&filename);

//     println!("Saving backup file {:?}", path);

    fs::create_dir_all(&path.parent().unwrap())?;
    original_file.write_to(interner, &mut File::create(path)?)?;

    Ok(())
}
