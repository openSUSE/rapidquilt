// Licensed under the MIT license. See LICENSE.md

use std::collections::HashMap;
use std::fs::{self, File};
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};

use failure::Error;

use crate::apply::*;
use crate::interned_file::InternedFile;
use crate::file_arena::FileArena;
use crate::line_interner::LineInterner;
use crate::patch::{FilePatchApplyReport, InternedFilePatch, HunkApplyReport, PatchDirection, TextFilePatch};
use crate::patch_unified::{UnifiedPatchRejWriter};


pub fn make_rej_filename<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();

    match path.extension() {
        Some(extension) => path.with_extension(extension.to_string_lossy().into_owned() + ".rej"),
        None => path.with_extension("rej")
    }
}

fn clean_empty_parent_directories<P: AsRef<Path>>(path: P) -> Result<(), Error> {
    let mut path = path.as_ref();

    while let Some(parent) = path.parent() {
        if fs::read_dir(parent)?.next().is_some() {
            // Not empty, we are done.
            return Ok(());
        }

        fs::remove_dir(parent)?;

        path = parent;
    }

    Ok(())
}

pub fn save_modified_file<P: AsRef<Path>>(filename: P, file: &InternedFile, interner: &LineInterner) -> Result<(), Error> {
    let filename = filename.as_ref();

//     println!("Saving modified file: {:?}: exited: {:?} deleted: {:?} len: {}", filename, file.existed, file.deleted, file.content.len());

    if file.existed {
        // If the file file existed, delete it. Whether we want to overwrite it
        // or really delete it - the file may be a hard link and we must replace
        // it with a new one, not edit the shared content.
        // We ignore the result, because it is ok if it wasn't there.
        // TODO: Do not ignore other errors, e.g. from permissions.
        let _ = fs::remove_file(filename);
    }

    if file.deleted {
        // If the file was deleted and existed before, clean empty parent directories
        if file.existed {
            clean_empty_parent_directories(filename)?;
        }
    } else {
        // If the file is not tracked as deleted, re-create it with the next content.
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

pub fn get_interned_file<
    'arena: 'interner,
    'interner,
    'modified_files,
    H: BuildHasher>
(
    filename: &PathBuf,
    modified_files: &'modified_files mut HashMap<PathBuf, InternedFile, H>,
    arena: &'arena FileArena,
    interner: &'interner mut LineInterner<'arena>)
    -> &'modified_files mut InternedFile
{
    // Load the file or create it empty
    modified_files.entry(filename.clone() /* <-TODO: Avoid clone */).or_insert_with(|| {
        match arena.load_file(filename) {
            Ok(data) => InternedFile::new(interner, &data, true),
            Err(_) => InternedFile::new_non_existent(), // If the file doesn't exist, make empty one. TODO: Differentiate between "doesn't exist" and other errors!
        }
    })
}

pub fn apply_one_file_patch<
    'arena: 'interner,
    'interner,
    'config: 'applied_patches,
    'applied_patches,
    H: BuildHasher>
(
    config: &'config ApplyConfig,
    index: usize,
    text_file_patch: TextFilePatch<'arena>,
    applied_patches: &'applied_patches mut Vec<PatchStatus<'arena, 'config>>,
    modified_files: &mut HashMap<PathBuf, InternedFile, H>,
    arena: &'arena FileArena,
    interner: &'interner mut LineInterner<'arena>)
    -> bool
{
    let file_patch = text_file_patch.intern(interner);

    let file = get_interned_file(file_patch.filename(), modified_files, arena, interner);

    // If the patch renames the file...
    let mut file = if let Some(new_filename) = file_patch.new_filename() {
        // Move out its content, but keep it among modified_files - we need a record on what
        // to do later - unless something else changes it, we will need to delete it from disk.
        let mut tmp_file = file.move_out();
        drop(file); // We can't hold mutable references to two items from modified_files...

        let new_file = get_interned_file(new_filename, modified_files, arena, interner);

        if !new_file.move_in(&mut tmp_file) {
            // Regular patch will just happily overwrite existing file if there is any...
            // We can not do that, because we would have no way to rollback.

            // TODO: Proper reporting!
            println!("Patch {} is renaming file {} to {}, which overwrites existing file!",
                config.patch_filenames[index].display(),
                file_patch.filename().display(),
                new_filename.display());

            // Put the content back to the old file.
            drop(new_file); // We can't hold mutable references to two items from modified_files...
            let file = get_interned_file(file_patch.filename(), modified_files, arena, interner);
            file.move_in(&mut tmp_file);

            // Note that we don't place anything into applied_patches - the patch
            // was not applied at all.
            return false;
        }

//         println!("Patch {} is renaming file {} to {}!",
//                 config.patch_filenames[index].display(),
//                 file_patch.filename().display(),
//                 new_filename.display());

        new_file
    } else {
        file
    };

    let report = file_patch.apply(&mut file, PatchDirection::Forward, config.fuzz);

    let report_ok = report.ok();
    if !report_ok {
        // TODO: Proper reporting, instead of just printing it here...
        println!("Patch {} failed on file {} hunks {:?}.",
            config.patch_filenames[index].display(),
            file_patch.filename().display(),
            report.hunk_reports().iter().enumerate().filter(|r| *r.1 == HunkApplyReport::Failed).map(|r| r.0 + 1).collect::<Vec<_>>());
    }

    applied_patches.push(PatchStatus {
        index,
        file_patch,
        report,
        patch_filename: &config.patch_filenames[index],
    });

    report_ok
}

pub fn rollback_applied_patch<'a: 'b, 'b, H: BuildHasher>(
    applied_patch: &PatchStatus,
    modified_files: &'a mut HashMap<PathBuf, InternedFile, H>)
    -> &'b InternedFile
{
    let filename = match applied_patch.file_patch.new_filename() {
        Some(new_filename) => new_filename,
        None => applied_patch.file_patch.filename(),
    };

    {
        let mut file = modified_files.get_mut(filename).unwrap(); // It must be there, we must have loaded it when applying the patch.

        applied_patch.file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

        // XXX: `file` is here dropped and later got again. I would prefer to just keep it, but
        // can't get it to pass borrowcheck
    }

    if let Some(new_filename) = applied_patch.file_patch.new_filename() {
        // Now we have to do the rename backwards
        let file = modified_files.get_mut(new_filename).unwrap();
        let mut tmp_file = file.move_out();
        drop(file);

        let old_file = modified_files.get_mut(applied_patch.file_patch.filename()).unwrap();
        let ok = old_file.move_in(&mut tmp_file);
        assert!(ok); // It must be ok during rollback, otherwise we made mistake during applying

        old_file
    } else {
        modified_files.get(filename).unwrap()
    }
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

        rollback_applied_patch(applied_patch, modified_files);

        if applied_patch.report.failed() {
            let rej_filename = make_rej_filename(
                applied_patch.file_patch.new_filename().unwrap_or(applied_patch.file_patch.filename())
            );
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
    interner: &LineInterner,
    down_to_index: usize)
    -> Result<(), Error>
{
    for applied_patch in applied_patches.iter().rev() {
        if applied_patch.index < down_to_index {
            break;
        }

        let file = rollback_applied_patch(applied_patch, modified_files);

        save_backup_file(applied_patch.patch_filename, applied_patch.file_patch.filename(), &file, &interner)?;

        if let Some(new_filename) = applied_patch.file_patch.new_filename() {
            // If it was a rename, we also have to backup the new file (it will be empty file).
            let new_file = modified_files.get(new_filename).unwrap();
            save_backup_file(applied_patch.patch_filename, new_filename, &new_file, &interner)?;
        }
    }

    Ok(())
}
