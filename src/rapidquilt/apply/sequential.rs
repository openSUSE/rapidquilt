// Licensed under the MIT license. See LICENSE.md

//! This module contains function to apply the patches sequentially in single thread.
//!
//! Patches are read, parsed and applied one by one.

use std::collections::HashSet;
use std::hash::BuildHasherDefault;

use colored::*;
use failure::{Error, ResultExt};
use seahash;

use crate::apply::*;
use crate::apply::common::*;
use crate::apply::diagnostics::*;
use crate::arena::Arena;

use libpatch::analysis::{AnalysisSet, Note};
use libpatch::patch::TextFilePatch;
use libpatch::patch::unified::parser::parse_patch;

pub fn apply_patches<'a, 'arena>(config: &'a ApplyConfig, arena: &'arena dyn Arena, analyses: &AnalysisSet)
    -> Result<ApplyResult, Error> {
    let mut state = AppliedState::new(config, config.series_patches.len());

    let mut final_patch = 0;

    let mut failure_analysis = Vec::<u8>::new();

    if config.verbosity >= Verbosity::Normal {
        println!("Applying {} patches single-threaded...", config.series_patches.len());
    }

    for (index, series_patch) in config.series_patches.iter().enumerate() {
        if config.verbosity >= Verbosity::Verbose {
            println!("Patch: {:?}", series_patch.filename);
        }

        let patch = (|| -> Result<_, Error> { // TODO: Replace me with try-block once it is stable. (feature "try_blocks")
            let data = arena.load_file(&config.patches_path.join(&series_patch.filename))?;
            let patch = parse_patch(&data, series_patch.strip, false)?;
            Ok(patch)
        })().with_context(|_| ApplyError::PatchLoad { patch_filename: config.series_patches[index].filename.clone() })?;

        let mut any_report_failed = false;

        for text_file_patch in patch.file_patches {
            let fn_analysis_note = |note: &dyn Note, file_patch: &TextFilePatch| {
                // We ignore any error here because currently we don't have a way to propagate it out
                // of this callback. It's not so tragic, error here would most likely be IO error from
                // writing to terminal.
                let _ = print_analysis_note(&series_patch.filename, note, file_patch);
            };

            if !state.apply_one_file_patch(index,
                                           text_file_patch,
                                           arena,
                                           &analyses,
                                           &fn_analysis_note)?
            {
                any_report_failed = true;
            }
        }

        if any_report_failed {
            // Analyze failure, in case there was any
            analyze_patch_failure(config.verbosity, index, &state.applied_patches, &state.modified_files, &mut failure_analysis)?;

            if !config.dry_run {
                state.rollback_and_save_rej_files(index)?;
            }

            break;
        }

        final_patch = index + 1;
    }

    if !config.dry_run {
        if config.verbosity >= Verbosity::Normal {
            println!("Saving modified files...");
        }

        let mut directories_for_cleaning = HashSet::with_hasher(BuildHasherDefault::<seahash::SeaHasher>::default());
        state.modified_files.save(&mut directories_for_cleaning)?;
        clean_empty_directories(directories_for_cleaning)?;

        if config.do_backups == ApplyConfigDoBackups::Always ||
          (config.do_backups == ApplyConfigDoBackups::OnFail &&
            final_patch != config.series_patches.len())
        {
            if config.verbosity >= Verbosity::Normal {
                println!("Saving quilt backup files ({})...", config.backup_count);
            }

            let down_to_index = match config.backup_count {
                ApplyConfigBackupCount::All => 0,
                ApplyConfigBackupCount::Last(n) => if final_patch > n { final_patch - n } else { 0 },
            };

            state.rollback_and_save_backup_files(down_to_index)?;
        }
    }

    if final_patch != config.series_patches.len() {
        eprintln!("{} {} {}", "Patch".yellow(), config.series_patches[final_patch].filename.display(), "FAILED".bright_red().bold());
        eprint!("{}", String::from_utf8(failure_analysis)?);
    }

    if config.stats {
        println!("{}", arena.stats());
    }

    Ok(ApplyResult {
        applied_patches: final_patch,
        skipped_patches: config.series_patches.len() - final_patch,
    })
}
