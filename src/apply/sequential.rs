// Licensed under the MIT license. See LICENSE.md

//! This module contains function to apply the patches sequentially in single thread.
//!
//! Patches are read, parsed and applied one by one.

use std::collections::HashMap;
use std::io::{self, Write};
use std::hash::BuildHasherDefault;
use std::path::PathBuf;

use colored::*;
use failure::{Error, ResultExt};
use seahash;

use crate::apply::*;
use crate::apply::common::*;
use crate::apply::diagnostics::*;
use crate::arena::Arena;
use crate::line::Line;
use crate::patch::unified::parser::parse_patch;
use crate::modified_file::ModifiedFile;


pub fn apply_patches<
    'arena,
    'config,
    L: Line<'arena> + 'arena>
(
    config: &'config ApplyConfig,
    arena: &'arena dyn Arena)
    -> Result<ApplyResult<'config>, Error>
{
    let mut applied_patches = Vec::<PatchStatus<'config, L>>::new();

    let mut modified_files = HashMap::<PathBuf, ModifiedFile<L>, BuildHasherDefault<seahash::SeaHasher>>::default();

    let mut final_patch = 0;

    let mut failure_analysis = Vec::<u8>::new();

    println!("Applying {} patches single-threaded...", config.patch_filenames.len());

    for (index, patch_filename) in config.patch_filenames.iter().enumerate() {
//         println!("Patch: {:?}", patch_filename);

        final_patch = index;

        let file_patches = (|| -> Result<_, Error> { // TODO: Replace me with try-block once it is stable.
            let data = arena.load_file(&config.patches_path.join(patch_filename))?;
            let file_patches = parse_patch(&data, config.strip)?;
            Ok(file_patches)
        })().with_context(|_| ApplyError::PatchLoad { patch_filename: config.patch_filenames[index].clone() })?;

        let mut any_report_failed = false;

        for file_patch in file_patches {
            if !apply_one_file_patch(config,
                                     index,
                                     file_patch,
                                     &mut applied_patches,
                                     &mut modified_files,
                                     arena)?
            {
                any_report_failed = true;
            }
        }

        if any_report_failed {
            // Analyze failure, in case there was any
            analyze_patch_failure(index, &applied_patches, &modified_files, &mut failure_analysis)?;

            if !config.dry_run {
                rollback_and_save_rej_files(&mut applied_patches, &mut modified_files, index)?;
            }

            break;
        }
    }

    if !config.dry_run {
        println!("Saving modified files...");

        save_modified_files(&modified_files)?;

        if config.do_backups == ApplyConfigDoBackups::Always ||
          (config.do_backups == ApplyConfigDoBackups::OnFail &&
            final_patch != config.patch_filenames.len() - 1)
        {
            println!("Saving quilt backup files ({})...", config.backup_count);

            let down_to_index = match config.backup_count {
                ApplyConfigBackupCount::All => 0,
                ApplyConfigBackupCount::Last(n) => if final_patch > n { final_patch - n } else { 0 },
            };

            rollback_and_save_backup_files(&mut applied_patches, &mut modified_files, down_to_index)?;
        }
    }

    if final_patch != config.patch_filenames.len() - 1 {
        let stderr = io::stderr();
        let mut out = stderr.lock();

        writeln!(out, "{} {} {}", "Patch".yellow(), config.patch_filenames[final_patch].display(), "FAILED".bright_red().bold())?;
        out.write_all(&failure_analysis)?;
    }

    if config.stats {
        println!("{}", arena.stats());
    }

    Ok(ApplyResult {
        applied_patches: &config.patch_filenames[0..=final_patch],
        skipped_patches: &config.patch_filenames[(final_patch + 1)..],
    })
}
