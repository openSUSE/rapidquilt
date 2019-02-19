// Licensed under the MIT license. See LICENSE.md

//! This module contains functions shared between the `parallel` and
//! `sequential` modules.

use std::collections::{HashMap, hash_map::Entry};
use std::fs::{self, File};
use std::io::{self, BufWriter};
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};

use failure::{Error, ResultExt};

use libpatch::analysis::{AnalysisSet, Note};
use libpatch::interned_file::InternedFile;
use libpatch::line_interner::LineInterner;
use libpatch::patch::{FilePatchApplyReport, InternedFilePatch, PatchDirection, TextFilePatch};
use libpatch::patch::unified::writer::UnifiedPatchRejWriter;

use crate::apply::*;
use crate::arena::Arena;


/// Build a ".rej" filename for given path.
pub fn make_rej_filename<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();

    match path.extension() {
        Some(extension) => path.with_extension(extension.to_string_lossy().into_owned() + ".rej"),
        None => path.with_extension("rej")
    }
}

/// Delete the directory containing the `path` and every parent directory as
/// long as they are empty.
fn clean_empty_parent_directories<P: AsRef<Path>>(path: P) -> Result<(), io::Error> {
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

/// Save the `file` to disk. It also takes care of creating/deleting the file
/// and containing directories.
pub fn save_modified_file<P: AsRef<Path>>(filename: P, file: &InternedFile, interner: &LineInterner, verbosity: Verbosity) -> Result<(), io::Error> {
    let filename = filename.as_ref();

    if verbosity >= Verbosity::ExtraVerbose {
        println!("Saving modified file: {:?}: existed: {:?} deleted: {:?} len: {}", filename, file.existed, file.deleted, file.content.len());
    }

    if file.existed {
        // If the file file existed, delete it. Whether we want to overwrite it
        // or really delete it - the file may be a hard link and we must replace
        // it with a new one, not edit the shared content.
        match fs::remove_file(filename) {
            Ok(_) => {
                // All is good.
            },
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                // It wasn't there since beginning, that is fine.
            },
            Err(err) => {
                // Some other error, report it
                return Err(err);
            }
        }
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

        // If any patch set non-default permission, set them now
        if let Some(ref permissions) = file.permissions {
            output.set_permissions(permissions.clone())?;
        }

        file.write_to(&interner, &mut output)?;
    }

    Ok(())
}

/// Save all `modified_files` to disk. It also takes care of creating/deleting
/// the files and containing directories.
pub fn save_modified_files<
    'arena: 'interner,
    'interner,
    H: BuildHasher>
(
    modified_files: &HashMap<PathBuf, InternedFile, H>,
    interner: &'interner LineInterner<'arena>,
    verbosity: Verbosity)
    -> Result<(), Error>
{
    for (filename, file) in modified_files {
        save_modified_file(filename, file, &interner, verbosity)
            .with_context(|_| ApplyError::SaveModifiedFile { filename: filename.clone() })?;
    }

    Ok(())
}

/// Write the `original_file` as a quilt backup file.
pub fn save_backup_file(patch_filename: &Path,
                        filename: &Path,
                        original_file: &InternedFile,
                        interner: &LineInterner,
                        verbosity: Verbosity)
                        -> Result<(), Error>
{
    let mut path = PathBuf::from(".pc");
    path.push(patch_filename);
    path.push(filename); // Note that this may add multiple directories plus filename

    if verbosity >= Verbosity::ExtraVerbose {
        println!("Saving backup file {:?}", path);
    }

    (|| -> Result<(), io::Error> { // TODO: Replace me with try-block when stable.
        let path_parent = path.parent().unwrap(); // NOTE(unwrap): We know that there is a parent, we just built it ourselves.

        fs::create_dir_all(path_parent)?;
        original_file.write_to(interner, &mut File::create(&path)?)
    })().with_context(|_| ApplyError::SaveQuiltBackupFile { filename: path })?;

    Ok(())
}

#[derive(Debug)]
pub struct PatchStatus<'a, 'b> {
    /// The index of this `FilePatch` in the original list of **patches**. Note
    /// that there can be multiple `FilePatch`es with the same index if they
    /// came from the same patch.
    pub index: usize,

    /// The interned `FilePatch`
    pub file_patch: InternedFilePatch<'a>,

    /// Which filename was actually patched. Because patch has to choose between
    /// `old_filename` and `new_filename` (in some cases even more) based on
    /// which files exist on the disk.
    /// Note that the file may have been renamed by the same `FilePatch`. The
    /// final form with be in `final_filename`.
    pub target_filename: PathBuf,

    /// The final filename of the file when this patch was done with it. Typically
    /// it will be the same as `target_filename`, unless the file was renamed.
    pub final_filename: PathBuf,

    /// Report from `FilePatch::apply`
    pub report: FilePatchApplyReport,

    /// The filename of the patch file, e.g. "blabla.patch"
    pub patch_filename: &'b Path,
}

/// Decides which filename to use, old or new, depending on which
/// files exist. This should mimic behavior of patch when used **without**
/// the --posix option.
///
/// # panics
///
/// Panics if both `old_filename` and `new_filename` are `None`.
pub fn choose_filename_to_patch<'a, H: BuildHasher>(
    old_filename: Option<&'a PathBuf>,
    new_filename: Option<&'a PathBuf>,
    modified_files: &HashMap<PathBuf, InternedFile, H>)
    -> &'a PathBuf
{
    match (old_filename, new_filename) {
        // If there is only one of them, that's the one we'll return
        (Some(old_filename), None) => old_filename,
        (None, Some(new_filename)) => new_filename,

        // If there are both...
        (Some(old_filename), Some(new_filename)) => {
            // If the old one exists (loaded or on disk), return that
            if modified_files.get(old_filename).map(|f| !f.deleted).unwrap_or(false) ||
                old_filename.exists()
            {
                return old_filename;
            }

            // If the new one exists (loaded or on disk), return that
            if modified_files.get(new_filename).map(|f| !f.deleted).unwrap_or(false) ||
                new_filename.exists()
            {
                return new_filename;
            }

            // This matches behavior of patch in my tests, but it may not match every time. Patch actually
            // uses strange logic of figuring the "best" of the two filenames by comparing amount of
            // components in path, length of basename and length of the full path. The comparison code may
            // not actually do what it is described to do. So at this point we can not really replicate
            // the behavior exactly.

            // Otherwise return the new one.
            new_filename
        }

        (None, None) => {
            // Called without any??? Bug -> panic.
            panic!();
        }
    }
}

/// Gets an `InternedFile` from `modified_files` if it was already there,
/// or loads it from disk if it exists, or creates new one.
pub fn get_interned_file<
    'arena: 'interner,
    'interner,
    'modified_files,
    H: BuildHasher>
(
    filename: &PathBuf,
    modified_files: &'modified_files mut HashMap<PathBuf, InternedFile, H>,
    arena: &'arena dyn Arena,
    interner: &'interner mut LineInterner<'arena>)
    -> Result<&'modified_files mut InternedFile, io::Error>
{
    // Load the file or create it empty
    let item = match modified_files.entry(filename.clone() /* <-TODO: Avoid clone */) {
        Entry::Occupied(entry) => entry.into_mut(),

        Entry::Vacant(entry) => {
            match arena.load_file(filename) {
                Ok(data) => entry.insert(InternedFile::new(interner, &data, true)),

                // If the file doesn't exist, make empty one.
                Err(ref error) if error.kind() == io::ErrorKind::NotFound =>
                    entry.insert(InternedFile::new_non_existent()),

                Err(error) => return Err(error),
            }
        }
    };

    Ok(item)
}

/// Applies single `FilePatch` to the appropriate file.
///
/// `config`: The configuration of the task.
/// `index`: Index of the **patch** in the configuration.
/// `text_file_patch`: A `FilePatch` before interning.
/// `applied_patches`: Vector of `PatchStatus`es with reports of previously applied patches. Report for this one will be appended in.
/// `modified_files`: HashMap of modified files so far. The currently patched file will be taken from or added to here.
/// `arena`: For loading files.
/// `interner`: For interning patches and files.
///
/// Returns whether the patch applied successfully, or Err in case some other error happened.
pub fn apply_one_file_patch<
    'arena: 'interner,
    'interner,
    'config: 'applied_patches,
    'applied_patches,
    'analyses,
    'fn_analysis_note,
    H: BuildHasher>
(
    config: &'config ApplyConfig,
    index: usize,
    text_file_patch: TextFilePatch<'arena>,
    reverse: bool,
    applied_patches: &'applied_patches mut Vec<PatchStatus<'arena, 'config>>,
    modified_files: &mut HashMap<PathBuf, InternedFile, H>,
    arena: &'arena dyn Arena,
    interner: &'interner mut LineInterner<'arena>,
    analyses: &'analyses AnalysisSet,
    fn_analysis_note: &'fn_analysis_note Fn(&dyn Note, &InternedFilePatch))
    -> Result<bool, Error>
{
    // Intern the `FilePatch`
    let file_patch = text_file_patch.intern(interner);

    // Get the file to patch
    let target_filename = choose_filename_to_patch(file_patch.old_filename(), file_patch.new_filename(), modified_files).clone();
    let file = get_interned_file(&target_filename, modified_files, arena, interner)
        .with_context(|_| ApplyError::LoadFileToPatch { filename: target_filename.clone() })?;

    // If the patch renames the file. do it now...
    let (mut file, final_filename) = if file_patch.is_rename() {
        let new_filename = file_patch.new_filename().unwrap(); // NOTE(unwrap): It must be there for renaming patches.

        if *new_filename == target_filename {
            // TODO: Proper reporting!
            println!("Patch {} would rename file {} to {}, but it already has the name.",
                     config.series_patches[index].filename.display(),
                     target_filename.display(),
                     new_filename.display());
        }

        // Move out its content, but keep it among modified_files - we need a record on what
        // to do later - unless something else changes it, we will need to delete it from disk.
        let mut tmp_file = file.move_out();

        let new_file = get_interned_file(new_filename, modified_files, arena, interner)
            .with_context(|_| ApplyError::LoadFileToPatch { filename: new_filename.clone() })?;

        if !new_file.move_in(&mut tmp_file) {
            // Regular patch will just happily overwrite existing file if there is any...
            // We can not do that, because we would have no way to rollback.

            // TODO: Proper reporting!
            println!("Patch {} is renaming file {} to {}, which overwrites existing file!",
                     config.series_patches[index].filename.display(),
                     target_filename.display(),
                     new_filename.display());

            // Put the content back to the old file.
            let file = get_interned_file(&target_filename, modified_files, arena, interner)
                .with_context(|_| ApplyError::LoadFileToPatch { filename: target_filename.clone() })?;
            file.move_in(&mut tmp_file);

            // Note that we don't place anything into applied_patches - the patch
            // was not applied at all.
            return Ok(false);
        }

//         println!("Patch {} is renaming file {} to {}!",
//                 config.series_patches[index].filename.display(),
//                 file_patch.filename().display(),
//                 new_filename.display());

        (new_file, new_filename.clone())
    } else {
        (file, target_filename.clone())
    };

    let direction = if reverse {
        PatchDirection::Revert
    } else {
        PatchDirection::Forward
    };

    // Apply the `FilePatch` on it.
    let report = file_patch.apply(&mut file, direction, config.fuzz, analyses, fn_analysis_note);

    let report_ok = report.ok();

    applied_patches.push(PatchStatus {
        index,
        file_patch,
        target_filename,
        final_filename,
        report,
        patch_filename: &config.series_patches[index].filename,
    });

    Ok(report_ok)
}

/// Rolls back single applied `FilePatch`
pub fn rollback_applied_patch<'a: 'b, 'b, H: BuildHasher>(
    applied_patch: &PatchStatus,
    modified_files: &'a mut HashMap<PathBuf, InternedFile, H>)
    -> &'b InternedFile
{
    {
        let mut file = modified_files.get_mut(&applied_patch.final_filename).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.

        applied_patch.file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

        // XXX: `file` is here dropped and later got again. I would prefer to just keep it, but
        // can't get it to pass borrowcheck
    }

    if applied_patch.file_patch.is_rename() {
        // Now we have to do the rename backwards
        let file = modified_files.get_mut(&applied_patch.final_filename).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
        let mut tmp_file = file.move_out();

        let old_file = modified_files.get_mut(&applied_patch.target_filename).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
        let ok = old_file.move_in(&mut tmp_file);
        assert!(ok); // It must be ok during rollback, otherwise we made mistake during applying

        old_file
    } else {
        modified_files.get(&applied_patch.final_filename).unwrap() // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
    }
}

/// Rolls back all `FilePatch`es belonging to the `rejected_patch_index` and save
/// ".rej" files for each `FilePatch` that failed applying
pub fn rollback_and_save_rej_files<H: BuildHasher>(
    applied_patches: &mut Vec<PatchStatus>,
    modified_files: &mut HashMap<PathBuf, InternedFile, H>,
    rejected_patch_index: usize,
    interner: &LineInterner,
    verbosity: Verbosity)
    -> Result<(), Error>
{
    while let Some(applied_patch) = applied_patches.last() {
        assert!(applied_patch.index <= rejected_patch_index);
        if applied_patch.index < rejected_patch_index {
            break;
        }

        rollback_applied_patch(applied_patch, modified_files);

        if applied_patch.report.failed() {
            let rej_filename = make_rej_filename(&applied_patch.target_filename);

            if verbosity >= Verbosity::Normal {
                println!("Saving rejects to {:?}", rej_filename);
            }

            File::create(&rej_filename).and_then(|output| {
                let mut writer = BufWriter::new(output);
                applied_patch.file_patch.write_rej_to(&interner, &mut writer, &applied_patch.report)
            }).with_context(|_| ApplyError::SaveRejectFile { filename: rej_filename.clone() })?;
        }

        applied_patches.pop();
    }

    Ok(())
}

/// Rolls back all `FilePatch`es up to the one belonging to patch with
/// `down_to_index` index and generates quilt backup files for all of them.
pub fn rollback_and_save_backup_files<H: BuildHasher>(
    applied_patches: &mut Vec<PatchStatus>,
    modified_files: &mut HashMap<PathBuf, InternedFile, H>,
    interner: &LineInterner,
    down_to_index: usize,
    verbosity: Verbosity)
    -> Result<(), Error>
{
    for applied_patch in applied_patches.iter().rev() {
        if applied_patch.index < down_to_index {
            break;
        }

        let file = rollback_applied_patch(applied_patch, modified_files);

        save_backup_file(&applied_patch.patch_filename, &applied_patch.target_filename, &file, &interner, verbosity)?;

        if let Some(new_filename) = applied_patch.file_patch.new_filename() {
            // If it was a rename, we also have to backup the new file (it will be empty file).
            let new_file = modified_files.get(new_filename).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
            save_backup_file(applied_patch.patch_filename, new_filename, &new_file, &interner, verbosity)?;
        }
    }

    Ok(())
}
