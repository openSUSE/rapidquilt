// Licensed under the MIT license. See LICENSE.md

use std::collections::HashMap;
use std::fs::File;
use std::hash::BuildHasherDefault;
use std::path::{Path, PathBuf};

use failure::Error;
use seahash;

use crate::apply::*;
use crate::apply::common::*;
use crate::file_arena::FileArena;
use crate::patch::{self, PatchDirection, FilePatchKind, InternedFilePatch, FilePatchApplyReport, HunkApplyReport};
use crate::line_interner::LineInterner;
use crate::interned_file::InternedFile;


pub fn apply_patches<'a>(config: &'a ApplyConfig) -> Result<ApplyResult<'a>, Error> {
    let arena = FileArena::new();
    let mut interner = LineInterner::new();

    let mut applied_patches = Vec::<PatchStatus>::new();

    let mut modified_files = HashMap::<PathBuf, InternedFile, BuildHasherDefault<seahash::SeaHasher>>::default();

    let mut final_patch = 0;

    println!("Applying {} patches single-threaded...", config.patch_filenames.len());

    for (index, patch_filename) in config.patch_filenames.iter().enumerate() {
//         println!("Patch: {:?}", patch_filename);

        final_patch = index;

        let data = arena.load_file(config.patches_path.join(patch_filename))?;
        let mut text_file_patches = patch::parse_unified(&data, config.strip)?;
        let file_patches: Vec<_> = text_file_patches.drain(..).map(|text_file_patch| text_file_patch.intern(&mut interner)).collect();
        let mut any_report_failed = false;

        for file_patch in file_patches {
            let mut file = modified_files.entry(file_patch.filename.clone() /* <-TODO: Avoid clone */).or_insert_with(|| {
                match arena.load_file(&file_patch.filename) {
                    Ok(data) => InternedFile::new(&mut interner, &data, true),
                    Err(_) => InternedFile::new_non_existent(), // If the file doesn't exist, make empty one. TODO: Differentiate between "doesn't exist" and other errors!
                }
            });

            let report = file_patch.apply(&mut file, PatchDirection::Forward, config.fuzz);

            if report.failed() {
                println!("Patch {} failed on file {} hunks {:?}.",
                    patch_filename.display(),
                    file_patch.filename.display(),
                    report.hunk_reports().iter().enumerate().filter(|r| *r.1 == HunkApplyReport::Failed).map(|r| r.0 + 1).collect::<Vec<_>>());
                any_report_failed = true;
            }

            applied_patches.push(PatchStatus {
                index,
                file_patch,
                report,
                patch_filename: &config.patch_filenames[index],
            });
        }

        if any_report_failed {
            rollback_and_save_rej_files(&mut applied_patches, &mut modified_files, index, &interner)?;
            break;
        }
    }

    println!("Saving modified files...");

    for (filename, file) in &modified_files {
        save_modified_file(filename, file, &interner)?;
    }

    if config.do_backups == ApplyConfigDoBackups::Always ||
       (config.do_backups == ApplyConfigDoBackups::OnFail &&
        final_patch != config.patch_filenames.len() - 1)
    {
        println!("Saving quilt backup files ({})...", config.backup_count);

        let down_to_index = match config.backup_count {
            ApplyConfigBackupCount::All => 0,
            ApplyConfigBackupCount::Last(n) => if final_patch > n { final_patch - n } else { 0 },
        };

        rollback_and_save_backup_files(&mut applied_patches, &mut modified_files, &interner, down_to_index)?;
    }

    Ok(ApplyResult {
        applied_patches: &config.patch_filenames[0..=final_patch],
        skipped_patches: &config.patch_filenames[(final_patch + 1)..],
    })
}
