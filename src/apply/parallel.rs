// Licensed under the MIT license. See LICENSE.md

use std;
use std::collections::HashMap;
use std::io::{self, Write};
use std::hash::{BuildHasherDefault, Hash};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};

use colored::*;
use failure::{Error, ResultExt};
use seahash;
use rayon;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::apply::*;
use crate::apply::common::*;
use crate::file_arena::FileArena;
use crate::patch::{PatchDirection, TextFilePatch};
use crate::patch_unified::parse_unified;
use crate::line_interner::LineInterner;
use crate::interned_file::InternedFile;


/// This is tool that distributes filenames among threads. Currently it doesn't
/// do any overly smart planning, it just distributes them one by one as they
/// come. However, it makes sure that every pair of filenames that was renamed
/// from one to another will end up assigned to the same thread.
pub struct FilenameDistributor<T: Hash + Eq> {
    thread_count: usize,
    filename_to_index: HashMap<T, usize, BuildHasherDefault<seahash::SeaHasher>>,
    connected_components: Vec<usize>,
}

impl<T: Hash + Eq> FilenameDistributor<T> {
    pub fn new(thread_count: usize) -> Self {
        FilenameDistributor {
            thread_count,
            filename_to_index: HashMap::default(),
            connected_components: Vec::new(), // TODO: Could we determine the capacity in advance?
        }
    }

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

#[derive(Clone, Debug)]
enum Message {
    NewEarliestBrokenPatchIndex,
    ThreadDoneApplying,
    TerminatingEarly,
}

#[derive(Default)]
struct WorkerReport {
    failure_analysis: Vec<u8>,
}

fn apply_worker_task<'a, BroadcastFn: Fn(Message)> (
    config: &'a ApplyConfig,
    arena: &FileArena<'a>,
    thread_id: usize,
    threads: usize,
    thread_file_patches: Vec<(usize, TextFilePatch)>,
    receiver: &mpsc::Receiver<Message>,
    broadcast_message: BroadcastFn,
    earliest_broken_patch_index: &AtomicUsize)
    -> Result<WorkerReport, Error>
{
    let mut interner = LineInterner::new();
    let mut applied_patches = Vec::<PatchStatus>::new();
    let mut modified_files = HashMap::<PathBuf, InternedFile, BuildHasherDefault<seahash::SeaHasher>>::default();

    // First we go forward and apply patches until we apply all of them or get pass the `earliest_broken_patch_index`
    for (index, text_file_patch) in thread_file_patches {
        if index > earliest_broken_patch_index.load(Ordering::Acquire) {
            // We are past the earliest broken patch. Time to stop applying.
            // Note that we DO WANT to apply the last broken patch itself.
            break;
        }

//         println!("TID {} - Applying patch #{} file {:?}", thread_id, index, text_file_patch.filename());

        match apply_one_file_patch(config,
                                   index,
                                   text_file_patch,
                                   &mut applied_patches,
                                   &mut modified_files,
                                   &arena,
                                   &mut interner) {
            Ok(false) => {
//                 println!("TID {} - Patch #{} failed to apply, signaling everyone!", thread_id, index);

                // Atomically set `earliest_broken_patch_index = min(earliest_broken_patch_index, index)`.
                let mut current = earliest_broken_patch_index.load(Ordering::Acquire);
                while index < current {
                    current = earliest_broken_patch_index.compare_and_swap(current, index, Ordering::AcqRel);
                }

                broadcast_message(Message::NewEarliestBrokenPatchIndex);
            }
            Err(err) => {
                broadcast_message(Message::TerminatingEarly);
                return Err(err);
            }
            _ => {}
        }
    }

    // Signal that we are done applying
    broadcast_message(Message::ThreadDoneApplying);

    let mut received_done_applying_count = 0;
    loop {
        // Rollback if there is anything to rollback
        while let Some(applied_patch) = applied_patches.last() {
            if applied_patch.index <= earliest_broken_patch_index.load(Ordering::Acquire) {
                break;
            }

            let file_patch = &applied_patch.file_patch;

//             println!("TID {} - Rolling back #{} file {:?}", thread_id, applied_patch.index, file_patch.filename());

            let mut file = modified_files.get_mut(file_patch.filename()).unwrap(); // NOTE(unwrap): It must be there, we must have loaded it when applying the patch.
            file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

            applied_patches.pop();
        }

        if received_done_applying_count == threads {
            // Everybody is done applying => nobody will be able to find
            // earlier failed patch. Since we already rollbacked everything,
            // it is time to proceed with next step.
            break;
        }

        // Wait until everybody is done or someone finds that earlier patch failed
        match receiver.recv().unwrap() { // NOTE(unwrap): Receive can only fail if the receiving side is disconnected, which can not happen in our case - it is held by everybody including us.
            Message::NewEarliestBrokenPatchIndex => {
//                 println!("TID {} - Received NewEarliestBrokenPatchIndex", thread_id);

                // Ok, time to rollback some more...
                continue;
            },

            Message::ThreadDoneApplying => {
//                 println!("TID {} - Received ThreadDoneApplying", thread_id);

                received_done_applying_count += 1;
                // Time to rollback some more TODO: Is this needed? It won't hurt much, but still...
                continue;
            },

            Message::TerminatingEarly => {
//                 println!("TID {} - Received TerminatingEarly", thread_id);

                // Some other thread gave up early because of error, if we
                // proceed we may end up waiting for them forever. Lets quit
                // early too. Their error will be reported to the user.
                return Ok(WorkerReport::default());
            }
        }
    }

    // Make a last atomic load. From now on it won't be changing.
    let earliest_broken_patch_index = earliest_broken_patch_index.load(Ordering::Acquire);

    // Analyze failure, in case there was any
    let mut failure_analysis = Vec::<u8>::new();
    analyze_patch_failure(earliest_broken_patch_index, &applied_patches, &modified_files, &interner, &mut failure_analysis)?;

    // Rollback the last applied patch and generate .rej files if any
    rollback_and_save_rej_files(&mut applied_patches, &mut modified_files, earliest_broken_patch_index, &interner)?;

//     println!("TID {} - Saving result...", thread_id);

    if thread_id == 0 {
        println!("Saving modified files...");
    }

    save_modified_files(&modified_files, &interner)?;

    if config.do_backups == ApplyConfigDoBackups::Always ||
    (config.do_backups == ApplyConfigDoBackups::OnFail &&
        earliest_broken_patch_index != std::usize::MAX)
    {
        if thread_id == 0 {
            println!("Saving quilt backup files ({})...", config.backup_count);
        }

        let final_patch = if earliest_broken_patch_index == std::usize::MAX {
            config.patch_filenames.len() - 1
        } else {
            earliest_broken_patch_index
        };

        let down_to_index = match config.backup_count {
            ApplyConfigBackupCount::All => 0,
            ApplyConfigBackupCount::Last(n) => if final_patch > n { final_patch - n } else { 0 },
        };

        rollback_and_save_backup_files(&mut applied_patches, &mut modified_files, &interner, down_to_index)?;
    }

    Ok(WorkerReport {
        failure_analysis,
    })
}

pub fn apply_patches<'a>(config: &'a ApplyConfig) -> Result<ApplyResult<'a>, Error> {
    let threads = rayon::current_num_threads();

    println!("Applying {} patches using {} threads...", config.patch_filenames.len(), threads);

    let arena = &FileArena::new();

    // Load all patches multi-threaded.
    let mut text_patches: Vec<_> = config.patch_filenames.par_iter().map(|patch_filename| -> Result<_, Error> {
        let raw_patch_data = arena.load_file(config.patches_path.join(patch_filename))?;
        let text_file_patches = parse_unified(raw_patch_data, config.strip)?;
        Ok(text_file_patches)
    }).collect();

    // Distribute the patches to queues for worker threads
    let mut filename_distributor = FilenameDistributor::<PathBuf>::new(threads);
    for text_file_patches in &text_patches {
        // Error checking later, here we'll look at the ok ones
        if let Ok(text_file_patches) = text_file_patches {
            for text_file_patch in text_file_patches {
                filename_distributor.add(text_file_patch.filename().clone(), text_file_patch.new_filename().cloned()); // TODO: Get rid of clone?
            }
        }
    }

    let filename_to_thread_id = filename_distributor.build();

    let mut text_file_patches_per_thread: Vec<Vec<(usize, TextFilePatch)>> = vec![Vec::with_capacity(
        config.patch_filenames.len() / threads * 11 / 10 // Heuristic, we expect mostly equal distribution with max 10% extra per thread.
    ); threads];
    for (index, text_file_patches) in text_patches.drain(..).enumerate() {
        let mut text_file_patches = text_file_patches.with_context(|_| ApplyError::PatchLoad { patch_filename: config.patch_filenames[index].clone() })?;

        for text_file_patch in text_file_patches.drain(..) {
            let thread_id = filename_to_thread_id[text_file_patch.filename()];
            text_file_patches_per_thread[thread_id].push((index, text_file_patch));
        }
    }

    // This is the earliest patch that was detected as broken. Note that this patch
    // **will be fully applied** by all threads and applying stops after that.
    // Only after that will all threads rollback to the patch before this one.
    // This is necessary to have complete set of ".rej" files.
    let earliest_broken_patch_index = &AtomicUsize::new(std::usize::MAX);

    // Prepare channels to send messages between applying threads.
    let (senders, receivers): (Vec<_>, Vec<_>) = (0..threads).map(|_| {
        mpsc::sync_channel::<Message>(threads * 2) // At the moment every thread can send at most 2 messages, so lets use fixed size channel.
    }).unzip();

    // This will record results from the threads.
    let thread_results: Mutex<Vec<Result<WorkerReport, Error>>> = Mutex::new(Vec::new());

    let thread_results_ref = &thread_results;

    // Run the applying threads
    rayon::scope(move |scope| {
        for ((thread_id, thread_file_patches), receiver) in text_file_patches_per_thread.drain(..).enumerate().zip(receivers) {
            let broadcast_message = {
                let senders = senders.clone();
                move |message: Message| {
                    for sender in &senders {
                        let _ = sender.send(message.clone()); // The only error this can return is when the receiving thread disconnected - i.e. terminated early. That could happen if it terminated because of error (e.g. permissions error when reading file), we can ignore that.
                    }
                }
            };

            scope.spawn(move |_| {
                let result = apply_worker_task(
                    config,
                    arena,
                    thread_id,
                    threads,
                    thread_file_patches,
                    &receiver,
                    broadcast_message,
                    earliest_broken_patch_index);

                thread_results_ref.lock().unwrap().push(result); // NOTE(unwrap): If the lock is poisoned, some other thread panicked. We may as well.
            });
        }
    });

    let thread_results = thread_results.into_inner().unwrap(); // NOTE(unwrap): If the lock is poisoned, some other thread panicked. We may as well.

    let (thread_reports, mut thread_errors): (_, Vec<Result<WorkerReport, Error>>) = thread_results.into_iter().partition(|r| {
        r.is_ok()
    });

    // If there was error in any of the applying threads, report the first one out
    // TODO: Should we report all of them?
    if let Some(Err(error)) = thread_errors.drain(..).next() {
        return Err(error);
    }

    let mut final_patch = earliest_broken_patch_index.load(Ordering::Acquire);
    if final_patch == std::usize::MAX {
        final_patch = config.patch_filenames.len();
    }

    // Print out failure analysis if there was any
    if final_patch != config.patch_filenames.len() {
        let stderr = io::stderr();
        let mut out = stderr.lock();

        writeln!(out, "{} {} {}", "Patch".yellow(), config.patch_filenames[final_patch].display(), "FAILED".bright_red().bold())?;

        for result in thread_reports {
            out.write_all(&result.unwrap().failure_analysis)?; // NOTE(unwrap): We already tested for errors above.
        }
    }

    Ok(ApplyResult {
        applied_patches: &config.patch_filenames[0..final_patch],
        skipped_patches: &config.patch_filenames[final_patch..],
    })
}

