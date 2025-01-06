// Licensed under the MIT license. See LICENSE.md

//! This module contains functions shared between the `parallel` and
//! `sequential` modules.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::fs::{self, File};
use std::hash::BuildHasherDefault;
use std::io::{self, BufWriter};
use std::hash::BuildHasher;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use failure::{Error, ResultExt};
use seahash;

use libpatch::analysis::{AnalysisSet, Note};
use libpatch::modified_file::ModifiedFile;
use libpatch::patch::{FilePatchApplyReport, PatchDirection, TextFilePatch};
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

/// Delete all directories and their parents if they are empty.
pub fn clean_empty_directories<P, I>(base_dir: P, directories_for_cleaning: I) -> Result<(), io::Error>
where P: AsRef<Path>,
      I: IntoIterator,
      I::Item: AsRef<Path>
{
    // Warning: This function can be called by multiple threads at the same time for the same
    //          directories (or nested directories), so things may disappear under its hands, it
    //          must be able to deal with it.

    // Go over every directory from the list...
    for directory in directories_for_cleaning {
        // ... and climb from the directory up until we find non-empty directory or there are no
        // more parents (the paths are relative to our working directory, so that means we reached
        // the working directory)
        let mut directory = directory.as_ref();
        loop {
            let dir_path = base_dir.as_ref().join(&directory);
            // Check if there is at least one file in the directory
            match fs::read_dir(&dir_path).map(|mut d| d.next()) {
                Err(ref error) if error.kind() == io::ErrorKind::NotFound => {
                    // Directory itself does not exist, we are done.
                    // This may happen if we already deleted it when cleaning after another file.
                    // For example if there were "dir1/file1" and "dir1/dir2/file2" and both
                    // "file1" and "file2" got deleted, then cleanup for "file2" would delete
                    // everything and then the cleanup for "file1" has nothing to do.
                    break;
                }

                Err(error) => {
                    // Other error, report
                    return Err(error);
                }

                Ok(Some(_)) => {
                    // Directory is not empty, we are done.
                    break;
                }

                Ok(None) => {
                    // Directory is empty, we will delete it and then proceed with its parent...
                }
            }

            match fs::remove_dir(dir_path) {
                Err(error) => {
                    if error.kind() != io::ErrorKind::NotFound {
                        return Err(error);
                    }
                }
                _ => {}
            }

            if let Some(parent) = directory.parent() {
                directory = parent;
            } else {
                break;
            }
        }
    }

    Ok(())
}

/// Save the `file` to disk. It also takes care of creating/deleting the file
/// and containing directories.
pub fn save_modified_file<'arena, H: BuildHasher>(
    config: &ApplyConfig,
    filename: &Cow<'arena, Path>,
    file: &ModifiedFile,
    directories_for_cleaning: &mut HashSet<Cow<'arena, Path>, H>)
    -> Result<(), io::Error>
{
    if config.verbosity >= Verbosity::ExtraVerbose {
        println!("Saving modified file: {:?}: existed: {:?} deleted: {:?} len: {}", filename.as_ref(), file.existed, file.deleted, file.content.len());
    }

    let file_path = config.base_dir.join(&filename);
    if file.existed {
        // If the file file existed, delete it. Whether we want to overwrite it
        // or really delete it - the file may be a hard link and we must replace
        // it with a new one, not edit the shared content.
        match fs::remove_file(&file_path) {
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
        // If the file was deleted and existed before, its parent directory may be empty and so
        // needs to be checked for cleaning.
        if file.existed {
            // The filename may be owned or be a reference into the arena. If it is reference, we can
            // keep the parent as reference with the same lifetime. But if it is owned, we must make
            // a copy.
            let parent = match filename {
                Cow::Borrowed(path_ref) => path_ref.parent().map(Cow::Borrowed),
                Cow::Owned(path_buf) => path_buf.parent().map(|parent| Cow::Owned(parent.to_path_buf())),
            };

            if let Some(parent) = parent {
                directories_for_cleaning.insert(parent);
            }
        }
    } else {
        // If the file is not tracked as deleted, re-create it with the next content.
        if !file.existed {
            // If the file is new, the directory may be new as well. Let's
            // create it now.
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut output = File::create(file_path)?;

        // If any patch set non-default permission, set them now
        if let Some(ref permissions) = file.permissions {
            output.set_permissions(permissions.clone())?;
        }

        file.write_to(&mut output)?;
    }

    Ok(())
}

#[derive(Debug)]
pub struct ModifiedFiles<'arena, 'config> {
    config: &'config ApplyConfig<'config>,
    inner: HashMap<Cow<'arena, Path>, ModifiedFile<'arena>, BuildHasherDefault<seahash::SeaHasher>>,
}

impl<'arena, 'config> Deref for ModifiedFiles<'arena, 'config> {
    type Target = HashMap<Cow<'arena, Path>, ModifiedFile<'arena>, BuildHasherDefault<seahash::SeaHasher>>;
    #[inline]
    fn deref(&self) -> &Self::Target { &self.inner }
}

impl<'arena, 'config> DerefMut for ModifiedFiles<'arena, 'config> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

impl<'arena, 'config> ModifiedFiles<'arena, 'config> {
    /// Constructs a new `AppliedState` with the specified capacity.
    pub fn new(config: &'config ApplyConfig) -> Self {
        Self {
            config,
            inner: HashMap::default(),
        }
    }

    /// Save all `modified_files` to disk. It also takes care of
    /// creating/deleting the files and containing directories.
    pub fn save<H: BuildHasher>(
        &self,
        directories_for_cleaning: &mut HashSet<Cow<'arena, Path>, H>)
        -> Result<(), Error>
    {
        for (filename, file) in self.iter() {
            save_modified_file(self.config, filename, file, directories_for_cleaning)
                .with_context(|_| ApplyError::SaveModifiedFile { filename: filename.to_path_buf() })?;
        }

        Ok(())
    }

    /// Gets an `ModifiedFile` from `modified_files` if it was already there,
    /// or loads it from disk if it exists, or creates new one.
    pub fn get_or_load(
        &mut self,
        filename: &Cow<'arena, Path>,
        arena: &'arena dyn Arena)
        -> Result<&mut ModifiedFile<'arena>, io::Error>
    {
        let config = self.config;
        // Load the file or create it empty
        let item = match self.entry(filename.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),

            Entry::Vacant(entry) => {
                let real_path = config.base_dir.join(filename);
                match arena.load_file(&real_path) {
                    Ok(data) => {
                        let meta = std::fs::metadata(real_path)?;
                        entry.insert(ModifiedFile::new(&data, true, Some(meta.permissions())))
                    }

                    // If the file doesn't exist, make empty one.
                    Err(ref error) if error.kind() == io::ErrorKind::NotFound =>
                        entry.insert(ModifiedFile::new_non_existent()),

                    Err(error) => return Err(error),
                }
            }
        };

        Ok(item)
    }

    /// Rolls back single applied `FilePatch`
    pub fn rollback(
        &mut self,
        applied_patch: &PatchStatus<'arena, '_>)
        -> &ModifiedFile<'arena>
    {
        // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
        let mut file = self.get_mut(&applied_patch.final_filename).unwrap();

        applied_patch.file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);


        if applied_patch.file_patch.is_rename() {
            // Now we have to rename backwards
            let mut tmp_file = file.move_out();

            // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
            let old_file = self.get_mut(&applied_patch.target_filename).unwrap();
            let ok = old_file.move_in(&mut tmp_file);
            // It must be ok during rollback, otherwise we have bug in the applying code
            assert!(ok);

            old_file
        } else {
            // TODO: Here we just search for `file` again. It would be nicer to just return `file`, but borrow checker does not like that.
            // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
            self.get(&applied_patch.final_filename).unwrap()
        }
    }
}

/// Create a file with given permissions, removing existing file if necessary
pub fn create_file(filename: &PathBuf, permissions: &Option<fs::Permissions>)
		   -> Result<File, io::Error>
{
    let f = match File::create(filename) {
	Ok(file) => file,
	Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
	    fs::remove_file(filename)?;
	    File::create(filename)?
	}
        Err(error) => return Err(error),
    };
    if let Some(ref permissions) = permissions {
	f.set_permissions(permissions.clone())?;
    }
    Ok(f)
}

/// Write the `original_file` as a quilt backup file.
pub fn save_backup_file(config: &ApplyConfig,
                        patch_filename: &Path,
                        filename: &Path,
                        original_file: &ModifiedFile)
                        -> Result<(), Error>
{
    let mut path = PathBuf::from(".pc");
    path.push(patch_filename);
    path.push(filename); // Note that this may add multiple directories plus filename

    if config.verbosity >= Verbosity::ExtraVerbose {
        println!("Saving backup file {:?}", path);
    }

     let real_path = config.base_dir.join(&path);
    // NOTE(unwrap): We know that there is a parent; we built it ourselves.
    let path_parent = real_path.parent().unwrap();
    fs::create_dir_all(path_parent)
        .and_then(|_| create_file(&real_path, &original_file.permissions))
        .and_then(|mut f| original_file.write_to(&mut f))
        .with_context(|_| ApplyError::SaveQuiltBackupFile { filename: path })?;

    Ok(())
}

#[derive(Debug)]
pub struct PatchStatus<'arena, 'config> {
    /// The index of this `FilePatch` in the original list of **patches**. Note
    /// that there can be multiple `FilePatch`es with the same index if they
    /// came from the same patch.
    pub index: usize,

    /// The applied `FilePatch`
    pub file_patch: TextFilePatch<'arena>,

    /// Which filename was actually patched. Because patch has to choose between
    /// `old_filename` and `new_filename` (in some cases even more) based on
    /// which files exist on the disk.
    /// Note that the file may have been renamed by the same `FilePatch`. The
    /// final form with be in `final_filename`.
    pub target_filename: Cow<'arena, Path>,

    /// The final filename of the file when this patch was done with it. Typically
    /// it will be the same as `target_filename`, unless the file was renamed.
    pub final_filename: Cow<'arena, Path>,

    /// Report from `FilePatch::apply`
    pub report: FilePatchApplyReport,

    /// The filename of the patch file, e.g. "blabla.patch"
    pub patch_filename: &'config Path,
}

/// Decides which filename to use, old or new, depending on which
/// files exist. This should mimic behavior of patch when used **without**
/// the --posix option.
///
/// # panics
///
/// Panics if both `old_filename` and `new_filename` are `None`.
pub fn choose_filename_to_patch<'arena, 'filename>(
    config: &ApplyConfig,
    old_filename: Option<&'filename Cow<'arena, Path>>,
    new_filename: Option<&'filename Cow<'arena, Path>>,
    modified_files: &ModifiedFiles)
    -> &'filename Cow<'arena, Path>
{
    match (old_filename, new_filename) {
        // If there is only one of them, that's the one we'll return
        (Some(old_filename), None) => old_filename,
        (None, Some(new_filename)) => new_filename,

        // If there are both and are the same, there is nothing to decide
        (Some(old_filename), Some(new_filename))
            if old_filename == new_filename => old_filename,

        // If there are both...
        (Some(old_filename), Some(new_filename)) => {
            // If the old one exists (loaded or on disk), return that
            match modified_files.get(old_filename) {
                // File is not in the database yet, check what is on disk...
                None => {
                    if config.base_dir.join(old_filename).exists() {
                        // It exists on disk, lets use it!
                        old_filename
                    } else {
                        // Otherwise we choose new_filename without any additional checks.
                        // See comment in the last match branch below.
                        new_filename
                    }
                }

                // File is in our database and it was not virtually deleted, lets use it!
                Some(ModifiedFile { deleted: false, .. }) => {
                    old_filename
                }

                // File is in our database and was virtually deleted, we will use new_filename.
                // There is no point in checking anything about it, because no matter if it exists
                // or not, we would fallback to using it in the end.
                Some(ModifiedFile { deleted: true, .. }) => {
                    // This matches behavior of patch in my tests, but it may not match every time.
                    // Patch actually uses strange logic for figuring the "best" of the two (three)
                    // filenames by comparing amount of components in path, length of basename and
                    // length of the full path. The code appears to be buggy, so it is basically
                    // undefined which file will be selected.
                    new_filename
                }
            }
        }

        (None, None) => {
            // Called without any??? Bug -> panic.
            panic!();
        }
    }
}

/// Contains the states of applied patches
#[derive(Debug)]
pub struct AppliedState<'arena, 'config> {
    pub config: &'config ApplyConfig<'config>,
    pub applied_patches: Vec::<PatchStatus<'arena, 'config>>,
    pub modified_files: ModifiedFiles<'arena, 'config>,
}

impl<'arena, 'config> AppliedState<'arena, 'config> {
    /// Constructs a new `AppliedState` with the specified capacity.
    pub fn new(config: &'config ApplyConfig, capacity: usize) -> AppliedState<'arena, 'config> {
        AppliedState {
            config,
            applied_patches: Vec::with_capacity(capacity),
            modified_files: ModifiedFiles::new(config),
        }
    }

    /// Applies single `FilePatch` to the appropriate file.
    ///
    /// `config`: The configuration of the task.
    /// `index`: Index of the **patch** in the configuration.
    /// `file_patch`: The `FilePatch` that should be applied.
    /// `applied_patches`: Vector of `PatchStatus`es with reports of previously applied patches. Report for this one will be appended in.
    /// `modified_files`: HashMap of modified files so far. The currently patched file will be taken from or added to here.
    /// `arena`: For loading files.
    ///
    /// Returns whether the patch applied successfully, or Err in case some other error happened.
    pub fn apply_one_file_patch(
        &mut self,
        index: usize,
        file_patch: TextFilePatch<'arena>,
        arena: &'arena dyn Arena,
        analyses: &AnalysisSet,
        fn_analysis_note: &dyn Fn(&dyn Note, &TextFilePatch))
        -> Result<bool, Error>
    {
        let config = self.config;
        let patch = &config.series_patches[index];

        // Get the file to patch
        let target_filename = choose_filename_to_patch(config, file_patch.old_filename(), file_patch.new_filename(), &self.modified_files).clone();
        let file = self.modified_files.get_or_load(&target_filename, arena)
            .with_context(|_| ApplyError::LoadFileToPatch { filename: target_filename.to_path_buf() })?;

        // If the patch renames the file. do it now...
        let (mut file, final_filename) = if file_patch.is_rename() {
            let new_filename = file_patch.new_filename().unwrap(); // NOTE(unwrap): It must be there for renaming patches.

            if *new_filename == target_filename {
                // TODO: Proper reporting!
                println!("Patch {} would rename file {} to {}, but it already has the name.",
                         patch.filename.display(),
                         target_filename.display(),
                         new_filename.display());
            }

            // Move out its content, but keep it among modified_files - we need a record on what
            // to do later - unless something else changes it, we will need to delete it from disk.
            let mut tmp_file = file.move_out();

            let new_file = self.modified_files.get_or_load(new_filename, arena)
                .with_context(|_| ApplyError::LoadFileToPatch { filename: new_filename.to_path_buf() })?;

            if !new_file.move_in(&mut tmp_file) {
                // Regular patch will just happily overwrite existing file if there is any...
                // We can not do that, because we would have no way to rollback.

                // TODO: Proper reporting!
                println!("Patch {} is renaming file {} to {}, which overwrites existing file!",
                         patch.filename.display(),
                         target_filename.display(),
                         new_filename.display());

                // Put the content back to the old file.
                let file = self.modified_files.get_or_load(&target_filename, arena)
                    .with_context(|_| ApplyError::LoadFileToPatch { filename: target_filename.to_path_buf() })?;
                file.move_in(&mut tmp_file);

                // Note that we don't place anything into applied_patches - the patch
                // was not applied at all.
                return Ok(false);
            }

//                 println!("Patch {} is renaming file {} to {}!",
//                         patch.filename.display(),
//                         file_patch.filename().display(),
//                         new_filename.display());

            (new_file, new_filename.clone())
        } else {
            (file, target_filename.clone())
        };

        let direction = if patch.reverse {
            PatchDirection::Revert
        } else {
            PatchDirection::Forward
        };

        // Apply the `FilePatch` on it.
        let report = file_patch.apply(&mut file, direction, config.fuzz, analyses, fn_analysis_note);

        let report_ok = report.ok();

        self.applied_patches.push(PatchStatus {
            index,
            file_patch,
            target_filename,
            final_filename,
            report,
            patch_filename: &patch.filename,
        });

        Ok(report_ok)
    }

    /// Rolls back all `FilePatch`es belonging to the `rejected_patch_index` and save
    /// ".rej" files for each `FilePatch` that failed applying
    pub fn rollback_and_save_rej_files(
        &mut self,
        rejected_patch_index: usize)
        -> Result<(), Error>
    {
        let config = self.config;
        while let Some(applied_patch) = self.applied_patches.last() {
            assert!(applied_patch.index <= rejected_patch_index);
            if applied_patch.index < rejected_patch_index {
                break;
            }

            self.modified_files.rollback(applied_patch);

            if applied_patch.report.failed() {
                let rej_filename = make_rej_filename(&applied_patch.target_filename);

                let file = match File::create(config.base_dir.join(&rej_filename)) {
                    Ok(file) => {
                        file
                    }

                    Err(ref err) if err.kind() == io::ErrorKind::NotFound => {
                        // This proably means the target directory doesn't exist.
                        // In that case quilt doesn't create the reject file, so we do the same.
                        // We still have to keep going, as other patches might be rejected.
                        self.applied_patches.pop();

                        if config.verbosity >= Verbosity::Normal {
                            println!("Bypassing reject {:?} as directory doesn't exist", rej_filename);
                        }

                        continue
                    }

                    Err(err) => {
                        return Err(err.into());
                    }
                };

                if config.verbosity >= Verbosity::Normal {
                    println!("Saving rejects to {:?}", rej_filename);
                }

                let mut writer = BufWriter::new(file);

                applied_patch.file_patch.write_rej_to(&mut writer, &applied_patch.report).
                    with_context(|_| ApplyError::SaveRejectFile { filename: rej_filename.clone() })?;
            }

            self.applied_patches.pop();
        }

        Ok(())
    }

    /// Rolls back all `FilePatch`es up to the one belonging to patch with
    /// `down_to_index` index and generates quilt backup files for all of them.
    pub fn rollback_and_save_backup_files(
        &mut self,
        down_to_index: usize)
        -> Result<(), Error>
    {
        let config = self.config;
        for applied_patch in self.applied_patches.iter().rev() {
            if applied_patch.index < down_to_index {
                break;
            }

            let file = self.modified_files.rollback(applied_patch);

            save_backup_file(config, &applied_patch.patch_filename, &applied_patch.target_filename, &file)?;

            if applied_patch.file_patch.is_rename() {
                // If it was a rename, we also have to backup the new file (it will be empty file).
                let new_filename = applied_patch.file_patch.new_filename().unwrap();
                // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
                let new_file = self.modified_files.get_mut(new_filename).unwrap();
                save_backup_file(config, applied_patch.patch_filename, new_filename, &new_file)?;
            }
        }

        Ok(())
    }

}
