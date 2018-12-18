// Licensed under the MIT license. See LICENSE.md

use std::collections::HashMap;
use std::fs::{self, File};
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};

use failure::Error;

use crate::interned_file::InternedFile;
use crate::line_interner::LineInterner;
use crate::patch::{self, FilePatchApplyReport, InternedFilePatch, PatchDirection, TextFilePatch};


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

    if file.existed {
        // If the file file existed, delete it. Whether we want to overwrite it
        // or really delete it - the file may be a hard link and we must replace
        // it with a new one, not edit the shared content.
        // We ignore the result, because it is ok if it wasn't there.
        // TODO: Do not ignore other errors, e.g. from permissions.
        let _ = fs::remove_file(filename);
    }

    // If the file is not tracked as deleted, re-create it with the next content.
    if !file.deleted {
        if !file.existed {
            // If the file is new, the directory may be new as well. Let's
            // create it now.
            if let Some(parent) = filename.parent() {
                fs::create_dir_all(parent)?;
            }
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

pub struct PatchStatus<'a, 'b> {
    pub index: usize,
    pub file_patch: InternedFilePatch<'a>,
    pub report: FilePatchApplyReport,
    pub patch_filename: &'b Path,
}

pub fn rollback_and_save_rej_files<H: BuildHasher>(
    applied_patches: &mut Vec<PatchStatus>,
    modified_files: &mut HashMap<PathBuf, InternedFile, H>,
    rejected_patch_index: usize,
    interner: &LineInterner)
    -> Result<(), Error>
{
    while let Some(applied_patch) = applied_patches.last() {
        assert!(applied_patch.index <= rejected_patch_index);
        if applied_patch.index < rejected_patch_index {
            break;
        }

        let mut file = modified_files.get_mut(&applied_patch.file_patch.filename).unwrap(); // It must be there, we must have loaded it when applying the patch.
        applied_patch.file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

        if applied_patch.report.failed() {
            let rej_filename = make_rej_filename(&applied_patch.file_patch.filename);
            println!("Saving rejects to {:?}", rej_filename);
            let mut output = File::create(rej_filename)?;
            applied_patch.file_patch.write_rej_to(&interner, &mut output, &applied_patch.report)?;
        }

        applied_patches.pop();
    }

    Ok(())
}

pub fn rollback_and_save_backup_files<H: BuildHasher>(
    applied_patches: &mut Vec<PatchStatus>,
    modified_files: &mut HashMap<PathBuf, InternedFile, H>,
    interner: &LineInterner)
    -> Result<(), Error>
{
    for applied_patch in applied_patches.iter().rev() {
        let mut file = modified_files.get_mut(&applied_patch.file_patch.filename).unwrap(); // It must be there, we must have loaded it when applying the patch.
        applied_patch.file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

        save_backup_file(applied_patch.patch_filename, &applied_patch.file_patch.filename, &file, &interner)?;
    }

    Ok(())
}
