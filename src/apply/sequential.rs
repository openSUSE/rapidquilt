// Licensed under the MIT license. See LICENSE.md

use std::collections::HashMap;
use std::io::{self, Write};
use std::hash::BuildHasherDefault;
use std::path::PathBuf;

use colored::*;
use failure::{Error, ResultExt};
use seahash;

use crate::apply::*;
use crate::apply::common::*;
use crate::file_arena::FileArena;
use crate::patch_unified::parse_unified;
use crate::line_interner::LineInterner;
use crate::interned_file::InternedFile;


pub fn apply_patches<'a>(config: &'a ApplyConfig) -> Result<ApplyResult<'a>, Error> {
    let arena = FileArena::new();
    let mut interner = LineInterner::new();

    let mut applied_patches = Vec::<PatchStatus>::new();

    let mut modified_files = HashMap::<PathBuf, InternedFile, BuildHasherDefault<seahash::SeaHasher>>::default();

    let mut final_patch = 0;

    let mut failure_analysis = Vec::<u8>::new();

    println!("Applying {} patches single-threaded...", config.patch_filenames.len());

    for (index, patch_filename) in config.patch_filenames.iter().enumerate() {
//         println!("Patch: {:?}", patch_filename);

        final_patch = index;

        let text_file_patches = (|| -> Result<_, Error> { // TODO: Replace me with try-block once it is stable.
            let data = arena.load_file(config.patches_path.join(patch_filename))?;
            let text_file_patches = parse_unified(&data, config.strip)?;
            Ok(text_file_patches)
        })().with_context(|_| ApplyError::PatchLoad { patch_filename: config.patch_filenames[index].clone() })?;

        let mut any_report_failed = false;

        for text_file_patch in text_file_patches {
            if !apply_one_file_patch(config,
                                     index,
                                     text_file_patch,
                                     &mut applied_patches,
                                     &mut modified_files,
                                     &arena,
                                     &mut interner)?
            {
                any_report_failed = true;
            }
        }

        if any_report_failed {
            // Analyze failure, in case there was any
            analyze_patch_failure(index, &applied_patches, &modified_files, &interner, &mut failure_analysis)?;

            rollback_and_save_rej_files(&mut applied_patches, &mut modified_files, index, &interner)?;
            break;
        }
    }

    println!("Saving modified files...");

    save_modified_files(&modified_files, &interner)?;

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

    if final_patch != config.patch_filenames.len() - 1 {
        let stderr = io::stderr();
        let mut out = stderr.lock();

        writeln!(out, "{} {} {}", "Patch".yellow(), config.patch_filenames[final_patch].display(), "failed".bright_red().bold())?;
        out.write(&failure_analysis)?;
    }

    Ok(ApplyResult {
        applied_patches: &config.patch_filenames[0..=final_patch],
        skipped_patches: &config.patch_filenames[(final_patch + 1)..],
    })
}
