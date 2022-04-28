// Licensed under the MIT license. See LICENSE.md

//! This module contains function to apply the patches parallel.
//!
//! The algorithm is:
//!
//! # Step 1 - multi-threaded
//!
//! First all patches are read and parsed in parallel. This can be done easily
//! because reading and parsing of one patch has no effect on reading and parsing
//! other patches.
//!
//! # Step 2 - single-threaded
//!
//! Patches are checked for reading/parsing errors. The list of affected files
//! is extracted.
//!
//! The affected files are assigned to threads. The assignment ensures that:
//! 1) The files are roughly equally distributed.
//! 2) If a filename A was ever renamed to filename B, both of them must be
//! processed by the same thread.
//! 3) Similarly, if a patch contains two different filenames A and B, even that
//! it is not renaming, both A and B are assigned to the same thread (because
//! whether A or B will be used is unknown at this moment).
//!
//! The `FilePatch`es are distributed to the threads based on the filenames
//! assigned to them.
//!
//! # Step 3 - multi-threaded
//!
//! The threads then each independently apply their `FilePatch`es to their files.
//! The affected files are loaded, then the `FilePatch` is applied.
//!
//! If any application fails, the thread terminates. At that point the others
//! may be ahead or behind. If they are ahead, they will also terminate
//! before applying the next patch. If they are behind, they continue until
//! they reach the same file (or until another `FilePatch` fails).
//! The first failed patch is known only when all threads terminate.
//!
//! # Step 4 - multi-threaded
//!
//! Each thread rolls back to the first failed patch. The result is then
//! saved to disk in parallel independently of each other.
//!
//! # Step 5 - single-threaded
//!
//! Collect results and print reports.


use std;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hash};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use colored::*;
use failure::{Error, ResultExt};
use seahash;
use rayon;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::apply::*;
use crate::apply::common::*;
use crate::apply::diagnostics::*;
use crate::arena::Arena;

use libpatch::analysis::{AnalysisSet, Note};
use libpatch::patch::{PatchDirection, TextFilePatch};
use libpatch::patch::unified::parser::parse_patch;

/// This is tool that distributes filenames among threads. Currently it doesn't
/// do any overly smart planning, it just distributes them one by one as they
/// come. However, it makes sure that every pair of filenames that was renamed
/// from one to another will end up assigned to the same thread.
///
/// We must ensure that if we get e.g. renames A->B, C->D, B->C, then all filenames
/// A, B, C, D must be assigned to the same thread, no matter in what order we saw
/// the renames. To solve this, we use algorithm for finding connected components
/// in a graph. Every filename is a node of the graph and every rename A->B is an edge
/// between nodes A->B. In the end every connected component is then assigned to a
/// singe thread. Typically most components consist of a single node.
pub struct FilenameDistributor<T: Hash + Eq> {
    thread_count: usize,
    filename_to_index: HashMap<T, usize, BuildHasherDefault<seahash::SeaHasher>>,
    connected_components: Vec<usize>,
}

impl<T: Hash + Eq> FilenameDistributor<T> {
    /// Create new distributor that distributes into `thread_count`-amount of threads
    pub fn new(thread_count: usize) -> Self {
        FilenameDistributor {
            thread_count,
            filename_to_index: HashMap::with_hasher(BuildHasherDefault::<seahash::SeaHasher>::default()),
            connected_components: Vec::new(),
        }
    }

    /// Add new `filename` to the distributor and optionally a `new_filename` if it is going to be
    /// renamed. It is ok if both `filename` and `new_filename` was already added.
    pub fn add(&mut self, filename: T, new_filename: Option<T>) {
        // Check if we already saw the filename. If not, add it to filename_to_index and to self.connected_components as alone component.
        let next_index = self.connected_components.len();
        let filename_index = *self.filename_to_index.entry(filename).or_insert(next_index);
        if filename_index == next_index {
            self.connected_components.push(filename_index);
        }

        if let Some(new_filename) = new_filename {
            // It is a rename, so also find or add the new filename.
            let next_index = self.connected_components.len();
            let new_filename_index = *self.filename_to_index.entry(new_filename).or_insert(next_index);
            if new_filename_index == next_index {
                self.connected_components.push(new_filename_index);
            }

            // Now merge the connected components
            if filename_index < new_filename_index {
                let i = self.connected_components[new_filename_index];
                self.connected_components[i] = filename_index;
            } else {
                let i = self.connected_components[filename_index];
                self.connected_components[i] = new_filename_index;
            }
        }
    }

    /// Consume the distributor and produce a map from `filename` to thread index.
    pub fn build(mut self) -> HashMap<T, usize, BuildHasherDefault<seahash::SeaHasher>> {
        for i in 0..self.connected_components.len() {
            if self.connected_components[i] != i {
                self.connected_components[i] = self.connected_components[self.connected_components[i]];
            }
        }

        for index in self.filename_to_index.values_mut() {
            *index = self.connected_components[*index] % self.thread_count;
        }

        self.filename_to_index
    }
}

/// This function is executed by every thread during the "Step 3" phase - when
/// applying all patches in parallel.
///
/// `config`: The configuration of the task.
/// `arena`: This arena is used for loading files.
/// `thread_file_patches`: The `FilePatch`es for this thread and the indexes of the original patch files they came from.
/// `earliest_broken_patch_index`: Atomic variable for sharing the index of the earlier patch that failed to apply.
/// `analyses`: Set of analyses to run.
fn apply_worker<'arena, 'config>(
    config: &'config ApplyConfig,
    arena: &'arena dyn Arena,
    thread_file_patches: Vec<(usize, TextFilePatch<'arena>)>,
    earliest_broken_patch_index: &AtomicUsize,
    analyses: &AnalysisSet)
    -> Result<AppliedState<'arena, 'config>, Error>
{
    let mut state = AppliedState::new(thread_file_patches.len());

    // First we go forward and apply patches until we apply all of them or get past the `earliest_broken_patch_index`
    for (index, text_file_patch) in thread_file_patches {
        if index > earliest_broken_patch_index.load(Ordering::Acquire) {
            // We are past the earliest broken patch. Time to stop applying.
            // Note that we DO WANT to apply the last broken patch itself, because
            // some hunks may fail to apply in this file as well, we want to get
            // the complete set of failed hunks for error message and '*.rej' files.
            break;
        }

        let fn_analysis_note = |note: &dyn Note, file_patch: &TextFilePatch| {
            // We ignore any error here because currently we don't have a way to propagate it out
            // of this callback. It's not so tragic, error here would most likely be IO error from
            // writing to terminal.
            let _ = print_analysis_note(&config.series_patches[index].filename, note, file_patch);
        };

        // Try to apply this one `FilePatch`
        match apply_one_file_patch(config,
                                   index,
                                   text_file_patch,
                                   &mut state,
                                   arena,
                                   &analyses,
                                   &fn_analysis_note) {
            Ok(false) => {
                // Patch failed to apply...

                earliest_broken_patch_index.fetch_min(index, Ordering::AcqRel);

                // We continue applying because it is quite possible that we have more `FilePatch`es
                // from the same `Patch` in queue and we must attempt to apply them all before we
                // are done. (So we get complete "*.rej" files.)
            }
            Err(err) => {
                // There was some other error! Signal everyone and terminate.
                return Err(err);
            }
            _ => {
                // All good
            }
        }
    }

    Ok(state)
}

/// Contains rendered report from the worker
#[derive(Default)]
struct WorkerReport {
    failure_analysis: Vec<u8>,
}

/// This function is executed by every thread during the "Step 4" phase - when
/// rolling back patches and saving files to disk.
///
/// `config`: The configuration of the task.
/// `arena`: This arena is used for loading files.
/// `thread_id`: Id of this thread. (Only used for logging)
/// `thread_file_patches`: The `FilePatch`es for this thread and the indexes of the original patch files they came from.
/// `final_patch`: Index of the earliest patch that failed to apply.
/// `analyses`: Set of analyses to run.
fn save_files_worker<'arena, 'config> (
    config: &'config ApplyConfig,
    thread_id: usize,
    mut state: AppliedState,
    final_patch: usize)
    -> Result<WorkerReport, Error>
{
    // Rollback if there is anything to rollback
    while let Some(applied_patch) = state.applied_patches.last() {
        if applied_patch.index <= final_patch {
            break;
        }

        // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
        let mut file = state.modified_files.get_mut(applied_patch.final_filename.as_ref()).unwrap();
        applied_patch.file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

        state.applied_patches.pop();
    };

    // Analyze failure, in case there was any
    let mut failure_analysis = Vec::<u8>::new();
    if let Err(err) = analyze_patch_failure(config.verbosity, final_patch, &state.applied_patches, &state.modified_files, &mut failure_analysis) {
        return Err(Error::from_boxed_compat(Box::new(err)));
    }

    // If this is not dry-run, save all the results
    if !config.dry_run {
        // Rollback the last applied patch and generate .rej files if any
        if let Err(err) = rollback_and_save_rej_files(config, &mut state, final_patch) {
            return Err(err);
        }

        if config.verbosity >= Verbosity::Normal && thread_id == 0 {
            println!("Saving modified files...");
        }

        // Save all the files we modified
        let mut directories_for_cleaning = HashSet::with_hasher(BuildHasherDefault::<seahash::SeaHasher>::default());
        if let Err(err) = save_modified_files(config, &state.modified_files, &mut directories_for_cleaning) {
            return Err(err);
        }
        clean_empty_directories(directories_for_cleaning)?;

        // Maybe save some backup files
        if config.do_backups == ApplyConfigDoBackups::Always ||
        (config.do_backups == ApplyConfigDoBackups::OnFail &&
            final_patch != config.series_patches.len())
        {
            if config.verbosity >= Verbosity::Normal && thread_id == 0 {
                println!("Saving quilt backup files ({})...", config.backup_count);
            }

            let down_to_index = match config.backup_count {
                ApplyConfigBackupCount::All => 0,
                ApplyConfigBackupCount::Last(n) => if final_patch > n { final_patch - n } else { 0 },
            };

            rollback_and_save_backup_files(config, &mut state, down_to_index)?;
        }
    }

    Ok(WorkerReport {
        failure_analysis,
    })
}

/// Apply all patches from the `config` in parallel
pub fn apply_patches<'config, 'arena>(config: &'config ApplyConfig, arena: &'arena dyn Arena, analyses: &AnalysisSet)
    -> Result<ApplyResult, Error>
{
    let threads = rayon::current_num_threads();

    if config.verbosity >= Verbosity::Normal {
        println!("Applying {} patches using {} threads...", config.series_patches.len(), threads);
    }

    if config.verbosity >= Verbosity::Verbose {
        println!("Parsing patches...");
    }

    // Load all patches multi-threaded using rayon's parallel iterator.
    let mut text_patches: Vec<_> = config.series_patches.par_iter().map(|series_patch| -> Result<_, Error> {
        if config.verbosity >= Verbosity::ExtraVerbose {
            // This will fight for stdout lock. But that's expected in ExtraVerbose mode...
            println!("Parsing patch: {:?}", series_patch.filename);
        }
        let raw_patch_data = arena.load_file(&config.patches_path.join(&series_patch.filename))?;
        let text_patch = parse_patch(raw_patch_data, series_patch.strip, false)?;
        Ok(text_patch)
    }).collect();

    if config.verbosity >= Verbosity::Verbose {
        println!("Scheduling files to threads...");
    }

    // Distribute the patches to queues for worker threads
    let mut filename_distributor = FilenameDistributor::<Cow<Path>>::new(threads);
    for text_patch in &text_patches {
        // Error checking later, here we'll look at the ok ones
        if let Ok(text_patch) = text_patch {
            for text_file_patch in &text_patch.file_patches {
                // This sucks, but the `FilePatch` may have different `old_filename` and `new_filename`
                // and we don't know which one will be used. It is decided based on which files
                // exist at the moment when the `FilePatch` will be applied. So for scheduling
                // purposes we act like if any `FilePatch` that has `old_filename != new_filename`
                // is renaming, so that both of them will be scheduled to the same thread.

                let (filename, rename_to_filename) = match (text_file_patch.old_filename(), text_file_patch.new_filename()) {
                    // Only `old_filename` => use that.
                    (Some(old_filename), None) => (old_filename, None),

                    // Only `new_filename` => use that.
                    (None, Some(new_filename)) => (new_filename, None),

                    // `old_filename` and `new_filename` that are the same => use that.
                    (Some(old_filename), Some(new_filename)) if old_filename == new_filename => (old_filename, None),

                    // `old_filename` and `new_filename` => consider it a rename!
                    (Some(old_filename), Some(new_filename)) => (old_filename, Some(new_filename)),

                    // Neither!? Such patch should not come from parser.
                    (None, None) => unreachable!(),
                };

                filename_distributor.add(filename.clone(), rename_to_filename.cloned()); // Note: clone/cloned is used on Cow, so most of the time it will be just copy of reference
            }
        }
    }

    let filename_to_thread_id = filename_distributor.build();

    // Now use the filename->thread_id map to distribute the actual `FilePatch`es into queues (`Vec`s)
    // for each thread.
    let mut text_file_patches_per_thread: Vec<Vec<(usize, TextFilePatch)>> = vec![Vec::with_capacity(
        config.series_patches.len() / threads * 11 / 10 // Heuristic, we expect mostly equal distribution with max 10% extra per thread.
    ); threads];
    for (index, text_patch) in text_patches.drain(..).enumerate() {
        let mut text_patch = text_patch.with_context(|_| ApplyError::PatchLoad { patch_filename: config.series_patches[index].filename.clone() })?;

        for text_file_patch in text_patch.file_patches.drain(..) {
            // Note that we can dispatch by `old_filename` or `new_filename`, we
            // made sure that both will be assigned to the same `thread_id`.
            let thread_id = filename_to_thread_id[text_file_patch.old_filename().or(text_file_patch.new_filename()).unwrap()];
            text_file_patches_per_thread[thread_id].push((index, text_file_patch));
        }
    }

    if config.verbosity >= Verbosity::Verbose {
        println!("Applying patches...");
    }

    // This is the earliest patch that was detected as broken. Note that this patch
    // **will be fully applied** by all threads and applying stops after that.
    // Only after that will all threads rollback to the patch before this one.
    // This is necessary to have complete set of ".rej" files.
    let earliest_broken_patch_index = &AtomicUsize::new(config.series_patches.len());

    // This results from the apply threads.
    let apply_results: Mutex<Vec<Result<AppliedState, Error>>> = Mutex::new(Vec::with_capacity(threads));
    let apply_results_ref = &apply_results;

    // Run the applying threads
    rayon::scope(move |scope| {
        for thread_file_patches in text_file_patches_per_thread.drain(..) {
            // Start the thread
            scope.spawn(move |_| {
                let result = apply_worker(
                    config,
                    arena,
                    thread_file_patches,
                    earliest_broken_patch_index,
                    analyses);

                // NOTE(unwrap): If the lock is poisoned, another thread panicked. We may as well.
                apply_results_ref.lock().unwrap().push(result);
            });
        }
    });

    // NOTE(unwrap): If the lock is poisoned, another thread panicked. We may as well.
    let mut apply_results = apply_results.into_inner().unwrap();

    // Check if we actually applied everything
    let final_patch = earliest_broken_patch_index.load(Ordering::Acquire);

    // This will record results from the threads.
    let thread_results: Mutex<Vec<Result<WorkerReport, Error>>> = Mutex::new(Vec::new());
    let thread_results_ref = &thread_results;

    // Run the saving threads
    rayon::scope(move |scope| {
        for (thread_id, apply_result) in apply_results.drain(..).enumerate() {
            match apply_result {
                Ok(state) => {
                    // Start the thread
                    scope.spawn(move |_| {
                        let result = save_files_worker(
                            config,
                            thread_id,
                            state,
                            final_patch);

                        // NOTE(unwrap): If the lock is poisoned, some other thread panicked. We may as well.
                        thread_results_ref.lock().unwrap().push(result);
                    });
                },
                Err(e) => {
                    thread_results_ref.lock().unwrap().push(Err(e));
                },
            };
        }
    });

    // NOTE(unwrap): If the lock is poisoned, some other thread panicked. We may as well.
    let thread_results = thread_results.into_inner().unwrap();

    // Split successfull reports and errors
    let (thread_reports, mut thread_errors): (_, Vec<Result<WorkerReport, Error>>) = thread_results.into_iter().partition(|r| {
        r.is_ok()
    });

    // If there was error in any of the applying threads, return the first one out
    // TODO: Should we return all of them?
    if let Some(Err(error)) = thread_errors.drain(..).next() {
        return Err(error);
    }

    // Print out failure analysis if we didn't apply everything
    if final_patch != config.series_patches.len() {
        eprintln!("{} {} {}", "Patch".yellow(), config.series_patches[final_patch].filename.display(), "FAILED".bright_red().bold());

        for result in thread_reports {
            // NOTE(unwrap): We already tested for errors above.
            eprint!("{}", String::from_utf8(result.unwrap().failure_analysis)?);
        }
    }

    if config.stats {
        println!("{}", arena.stats());
    }

    Ok(ApplyResult {
        applied_patches: final_patch,
        skipped_patches: config.series_patches.len() - final_patch,
    })
}

