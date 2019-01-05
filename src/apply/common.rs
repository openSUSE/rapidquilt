// Licensed under the MIT license. See LICENSE.md

use std::collections::{HashMap, hash_map::Entry};
use std::fs::{self, File};
use std::io::{self, Write};
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};

use colored::*;
use failure::{Error, ResultExt};

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

pub fn save_modified_file<P: AsRef<Path>>(filename: P, file: &InternedFile, interner: &LineInterner) -> Result<(), io::Error> {
    let filename = filename.as_ref();

//     println!("Saving modified file: {:?}: exited: {:?} deleted: {:?} len: {}", filename, file.existed, file.deleted, file.content.len());

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
        file.write_to(&interner, &mut output)?;
    }

    Ok(())
}

pub fn save_modified_files<
    'arena: 'interner,
    'interner,
    H: BuildHasher>
(
    modified_files: &HashMap<PathBuf, InternedFile, H>,
    interner: &'interner LineInterner<'arena>)
    -> Result<(), Error>
{
    for (filename, file) in modified_files {
        save_modified_file(filename, file, &interner)
            .with_context(|_| ApplyError::SaveModifiedFile { filename: filename.clone() })?;
    }

    Ok(())
}

pub fn save_backup_file(patch_filename: &Path, filename: &Path, original_file: &InternedFile, interner: &LineInterner) -> Result<(), Error> {
    let mut path = PathBuf::from(".pc");
    path.push(patch_filename);
    path.push(&filename); // Note that this may add multiple directories plus filename

//     println!("Saving backup file {:?}", path);

    (|| -> Result<(), io::Error> { // TODO: Replace me with try-block when stable.
        let path_parent = &path.parent().unwrap(); // NOTE(unwrap): We know that there is a parent, we just built it ourselves.

        fs::create_dir_all(path_parent)?;
        original_file.write_to(interner, &mut File::create(&path)?)
    })().with_context(|_| ApplyError::SaveQuiltBackupFile { filename: path })?;

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
    -> Result<bool, Error>
{
    let file_patch = text_file_patch.intern(interner);

    let file = get_interned_file(file_patch.filename(), modified_files, arena, interner)
        .with_context(|_| ApplyError::LoadFileToPatch { filename: file_patch.filename().clone() })?;

    // If the patch renames the file...
    let mut file = if let Some(new_filename) = file_patch.new_filename() {
        // Move out its content, but keep it among modified_files - we need a record on what
        // to do later - unless something else changes it, we will need to delete it from disk.
        let mut tmp_file = file.move_out();
        drop(file); // We can't hold mutable references to two items from modified_files...

        let new_file = get_interned_file(new_filename, modified_files, arena, interner)
            .with_context(|_| ApplyError::LoadFileToPatch { filename: new_filename.clone() })?;

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
            let file = get_interned_file(file_patch.filename(), modified_files, arena, interner)
                .with_context(|_| ApplyError::LoadFileToPatch { filename: file_patch.filename().clone() })?;
            file.move_in(&mut tmp_file);

            // Note that we don't place anything into applied_patches - the patch
            // was not applied at all.
            return Ok(false);
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

    applied_patches.push(PatchStatus {
        index,
        file_patch,
        report,
        patch_filename: &config.patch_filenames[index],
    });

    Ok(report_ok)
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
        let mut file = modified_files.get_mut(filename).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.

        applied_patch.file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

        // XXX: `file` is here dropped and later got again. I would prefer to just keep it, but
        // can't get it to pass borrowcheck
    }

    if let Some(new_filename) = applied_patch.file_patch.new_filename() {
        // Now we have to do the rename backwards
        let file = modified_files.get_mut(new_filename).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
        let mut tmp_file = file.move_out();
        drop(file);

        let old_file = modified_files.get_mut(applied_patch.file_patch.filename()).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
        let ok = old_file.move_in(&mut tmp_file);
        assert!(ok); // It must be ok during rollback, otherwise we made mistake during applying

        old_file
    } else {
        modified_files.get(filename).unwrap() // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
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

            File::create(&rej_filename).and_then(|mut output| {
                applied_patch.file_patch.write_rej_to(&interner, &mut output, &applied_patch.report)
            }).with_context(|_| ApplyError::SaveRejectFile { filename: rej_filename.clone() })?;
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
            let new_file = modified_files.get(new_filename).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
            save_backup_file(applied_patch.patch_filename, new_filename, &new_file, &interner)?;
        }
    }

    Ok(())
}

pub fn test_apply_with_fuzzes<H: BuildHasher>(
    patch_status: &PatchStatus,
    modified_files: &HashMap<PathBuf, InternedFile, H>)
    -> Option<usize>
{
    let file = modified_files.get(patch_status.file_patch.filename()).unwrap(); // NOTE(unwrap): It must be there, otherwise we got bad modified_files, which would be bug.

    // Make our own copy for experiments
    let mut file = file.clone();

    // Rollback the failed application
    patch_status.file_patch.rollback(&mut file, PatchDirection::Forward, &patch_status.report);

    let current_fuzz = patch_status.report.fuzz();
    let max_fuzz = patch_status.file_patch.max_useable_fuzz();

    if current_fuzz >= max_fuzz {
        return None;
    }

    for fuzz in (current_fuzz + 1)..=max_fuzz {
        // Make another copy for test application
        let mut file = file.clone();

        let report = patch_status.file_patch.apply(&mut file, PatchDirection::Forward, fuzz);

        if report.ok() {
            return Some(fuzz);
        }
    }

    None
}

pub fn analyze_patch_failure<H: BuildHasher, W: Write>(
    broken_patch_index: usize,
    applied_patches: &Vec<PatchStatus>,
    modified_files: &HashMap<PathBuf, InternedFile, H>,
    _interner: &LineInterner,
    writer: &mut W)
    -> Result<(), io::Error>
{
    for patch_status in applied_patches.iter().rev() {
        if patch_status.index != broken_patch_index {
            break;
        }

        write!(writer, "  {} {} ", "File".yellow(), patch_status.file_patch.filename().display())?;

        if patch_status.report.ok() {
            writeln!(writer, "{}", "ok".bright_green().bold())?;
        } else {
            writeln!(writer, "{}", "failed".bright_red().bold())?;

            for (i, hunk_report) in patch_status.report.hunk_reports().iter().enumerate() {
                write!(writer, "    {} #{}: ", "Hunk".yellow(), i + 1)?;

                match hunk_report {
                    HunkApplyReport::Applied { offset, .. } => {
                        write!(writer, "{}", "ok".bright_green().bold())?;

                        if *offset != 0 {
                            write!(writer, " with offset {}", offset)?;
                        }
                    }

                    HunkApplyReport::Failed => {
                        write!(writer, "{}", "failed".bright_red().bold())?;
                    }

                    HunkApplyReport::Skipped => {
                        write!(writer, "{}", "skipped".blue().bold())?;
                    }
                }

                writeln!(writer, )?;
            }

            // Find which other patches touched this file
            let mut other_patches = Vec::<&Path>::new();
            for other_patch_status in applied_patches.iter() {
                if other_patch_status.index >= broken_patch_index {
                    break;
                }

                if other_patch_status.file_patch.filename() == patch_status.file_patch.filename() {
                    other_patches.push(other_patch_status.patch_filename);
                }
            }

            // Fuzz hint
            writeln!(writer)?;
            if let Some(working_fuzz) = test_apply_with_fuzzes(patch_status, modified_files) {
                write!(writer, "    {} Patch would apply on this file with fuzz {}", "hint:".purple(), working_fuzz)?;
            } else {
                write!(writer, "    {} Patch would not apply on this file with any fuzz", "hint:".purple())?;
            }
            writeln!(writer)?;

            // Other patches hint
            writeln!(writer)?;
            write!(writer, "{}", "    hint: ".purple())?;

            if other_patches.len() == 0 {
                writeln!(writer, "No previous patches touched this file.")?;
            } else {
                writeln!(writer, "{} previous patches touched this file:", other_patches.len())?;

                for other_patch in other_patches {
                    writeln!(writer, "      {}", other_patch.display())?;
                }
            }

            writeln!(writer)?;
        }
    }

    Ok(())
}
