use std;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::fs;
use std::hash::BuildHasherDefault;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crossbeam;
use failure::Error;
use seahash;

use crate::apply::make_rej_filename;
use crate::file_arena::FileArena;
use crate::patch::{self, PatchDirection, InternedFilePatch, TextFilePatch, FilePatchKind, FilePatchApplyReport};
use crate::line_interner::LineInterner;
use crate::interned_file::InternedFile;


enum Message<'a> {
    NextPatch(usize, TextFilePatch<'a>),
    AllPatchesSent,
    NewEarliestBrokenPatchIndex,
    ThreadDoneApplying,
}

pub fn apply_patches<'a, P: AsRef<Path>>(patch_filenames: &[PathBuf], patches_path: P, strip: usize, threads: usize) -> Result<(), Error> {
    let patches_path = patches_path.as_ref();

    println!("Applying {} patches using {} threads...", patch_filenames.len(), threads);

    // Loading and parsing of patches is done by two threads, but we consider it as
    // one thread - the first one should use almost no CPU, but is always blocked on IO.
    // The applying threads will use the remaining threads.
    let applying_threads_count: usize = std::cmp::max(threads, 2) - 1;

    let arena_ = FileArena::new();

    // This is the earliest patch that was detected as broken. Note that this patch
    // **will be fully applied** by all threads and applying stops after that.
    // Only after that will all threads rollback to the patch before this one.
    // This is necessary to have complete set of ".rej" files.
    let earliest_broken_patch_index_ = AtomicUsize::new(std::usize::MAX);

    // Prepare channels to send messages to the applying threads.
    let (senders_, receivers): (Vec<_>, Vec<_>) = (0..applying_threads_count).map(|_| {
        crossbeam::channel::bounded::<Message>(32) // TODO: Fine-tune the capacity.
    }).unzip();

    // Prepare channel to send loaded patch files
    let (raw_patch_sender, raw_patch_receiver) = crossbeam::channel::bounded::<(usize, Result<&[u8], Error>)>(16); // We'll be preloading up to this many patches in advance.

    crossbeam::thread::scope(|scope| {
        let arena = &arena_;
        let earliest_broken_patch_index = &earliest_broken_patch_index_;

        // This thread loads the patch files in and sends them into the channel for parsing in next step.
        // It should keep the IO utilized unless the channel fills up, then it will wait.
        scope.spawn(move |_| {
            for (index, patch_filename) in patch_filenames.iter().enumerate() {
                if index > earliest_broken_patch_index.load(Ordering::Acquire) {
                    break;
                }

//                 println!("Loading patch #{}: {:?}", index, patch_filename);

                let raw_patch_data = arena.load_file(patches_path.join(patch_filename));
                raw_patch_sender.send((index, raw_patch_data)).unwrap();
            }
        });

        // This thread parses the patches, breaks them into individual file patches and sends those
        // to the individual applying threads based on the target filename.
        let senders = senders_.clone();
        scope.spawn(move |_| {
            for (index, raw_patch_data) in raw_patch_receiver.iter() {
                if index > earliest_broken_patch_index.load(Ordering::Acquire) {
                    break;
                }

//                 println!("Parsing patch #{}: {:?}", index, patch_filename);

                let text_file_patches = raw_patch_data.and_then(|d| patch::parse_unified(d, strip));

                match text_file_patches {
                    Ok(mut text_file_patches) => {
                        // Success, send the individual text file patches to their respective threads
                        for text_file_patch in text_file_patches.drain(..) {
                            let thread_index = (text_file_patch.filename_hash % applying_threads_count as u64) as usize;
                            senders[thread_index].send(Message::NextPatch(index, text_file_patch)).unwrap(); // TODO: Properly propagate up?
                        }
                    }
                    Err(err) => {
                        // TODO: Failure, signal that this is the new goal and save the error somewhere up...
                        //       But for now just terminate!
                        Err::<(), Error>(err).unwrap();
                    }
                };
            }

            for sender in senders {
                sender.send(Message::AllPatchesSent).unwrap();
            }
        });

        // These threads each process FilePatches that target filenames assigned to them.
        for (thread_index, receiver) in receivers.iter().enumerate() {
            let arena = &arena_;
            let senders = senders_.clone();

            scope.spawn(move |_| -> Result<(), Error> {
                let mut interner = LineInterner::new();

                struct PatchStatus<'a> {
                    index: usize,
                    file_patch: InternedFilePatch<'a>,
                    report: FilePatchApplyReport,
                };

                let mut applied_patches = Vec::<PatchStatus>::new();

                let mut modified_files = HashMap::<PathBuf, InternedFile, BuildHasherDefault<seahash::SeaHasher>>::default();
                let mut removed_files = HashSet::<PathBuf, BuildHasherDefault<seahash::SeaHasher>>::default();

                let mut done_applying = false;
                let mut signalled_done_applying = false;
                let mut received_done_applying_signals = 0;

                for message in receiver.iter() {
                    match message {
                        Message::NextPatch(index, text_file_patch) => {
                            if index > earliest_broken_patch_index.load(Ordering::Acquire) {
//                                 println!("TID {} - Skipping patch #{} file {:?}, we are supposed to stop before this.", thread_index, index, text_file_patch.filename);
                                done_applying = true;
                                continue;
                            }

                            assert!(!signalled_done_applying); // If we already signalled that we are done, there is now way we should have more patches to forward-apply

//                             println!("TID {} - Applying patch #{} file {:?}", thread_index, index, text_file_patch.filename);

                            let file_patch = text_file_patch.intern(&mut interner);

                            let mut file = modified_files.entry(file_patch.filename.clone() /* <-TODO: Avoid clone */).or_insert_with(|| {
                                let data = match arena.load_file(&file_patch.filename) {
                                    Ok(data) => data,
                                    Err(_) => &[], // If the file doesn't exist, make empty one. TODO: Differentiate between "doesn't exist" and other errors!
                                };
                                InternedFile::new(&mut interner, &data)
                            });

                            if file_patch.kind == FilePatchKind::Delete {
                                removed_files.insert(file_patch.filename.clone());
                            } else {
                                removed_files.remove(&file_patch.filename);
                            }

                            let report = file_patch.apply(&mut file, PatchDirection::Forward);

                            if report.failed() {
//                                 println!("TID {} - Patch #{} failed to apply, signaling everyone! Report: {:?}", thread_index, index, report);

                                // Atomically set `earliest_broken_patch_index = min(earliest_broken_patch_index, index)`.
                                let mut current = earliest_broken_patch_index.load(Ordering::Acquire);
                                while index < current {
                                    current = earliest_broken_patch_index.compare_and_swap(current, index, Ordering::AcqRel);
                                }

                                // Notify other threads that the earliest_broken_patch_index changed
                                for sender in &senders {
                                    sender.send(Message::NewEarliestBrokenPatchIndex).unwrap();
                                }
                            }

                            applied_patches.push(PatchStatus {
                                index,
                                file_patch,
                                report,
                            });
                        },
                        Message::NewEarliestBrokenPatchIndex => {
//                             println!("TID {} - Got new earliest_broken_patch_index = {}", thread_index, earliest_broken_patch_index.load(Ordering::Acquire));

                            // If we already applied past this stop point, signal that we are done forward applying.
                            if let Some(applied_patch) = applied_patches.last() {
                                if applied_patch.index > earliest_broken_patch_index.load(Ordering::Acquire) {
                                    done_applying = true;
                                }
                            }

                            // If we already applied past this stop point, revert all applied patches until we get to the right point.
                            while let Some(applied_patch) = applied_patches.last() {
                                if applied_patch.index <= earliest_broken_patch_index.load(Ordering::Acquire) {
                                    break;
                                }

                                let file_patch = &applied_patch.file_patch;

//                                 println!("TID {} - Rolling back #{} file {:?}", thread_index, applied_patch.index, file_patch.filename);

                                let mut file = modified_files.get_mut(&file_patch.filename).unwrap(); // It must be there, we must have loaded it when applying the patch.
                                file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

                                if file_patch.kind == FilePatchKind::Delete {
                                    removed_files.remove(&file_patch.filename);
                                }

                                applied_patches.pop();
                            }
                        },
                        Message::ThreadDoneApplying => {
                            received_done_applying_signals += 1;

//                             println!("TID {} - Received ThreadDoneApplying signal, total received: {}", thread_index, received_done_applying_signals);

                            if received_done_applying_signals == applying_threads_count {
                                break;
                            }
                        },
                        Message::AllPatchesSent => {
                            done_applying = true;
                        }
                    }

                    if done_applying && !signalled_done_applying {
//                         println!("TID {} - Signalling ThreadDoneApplying", thread_index);
                        for sender in &senders {
                            sender.send(Message::ThreadDoneApplying).unwrap();
                        }
                        signalled_done_applying = true;
                    }
                }

//                 println!("TID {} - Saving result...", thread_index);

                // Rollback the last applied patch and generate .rej files if any
                for applied_patch in applied_patches.iter().rev() {
                    assert!(applied_patch.index <= earliest_broken_patch_index.load(Ordering::Acquire));
                    if applied_patch.index < earliest_broken_patch_index.load(Ordering::Acquire) {
                        break;
                    }

                    let mut file = modified_files.get_mut(&applied_patch.file_patch.filename).unwrap(); // It must be there, we must have loaded it when applying the patch.
                    applied_patch.file_patch.rollback(&mut file, PatchDirection::Forward, &applied_patch.report);

                    if applied_patch.file_patch.kind == FilePatchKind::Delete {
                        removed_files.remove(&applied_patch.file_patch.filename);
                    }

                    if applied_patch.report.failed() {
                        let rej_filename = make_rej_filename(&applied_patch.file_patch.filename);
                        println!("Saving rejects to {:?}", rej_filename);
                        let mut output = File::create(rej_filename)?;
                        applied_patch.file_patch.write_rej_to(&interner, &mut output, &applied_patch.report)?;
                    }
                }

                for (filename, file) in &modified_files {
//                     println!("Modified file: {:?}", filename);
                    let _ = fs::remove_file(filename);
                    if let Some(parent) = filename.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut output = File::create(filename)?;
                    file.write_to(&interner, &mut output)?;
                }

                for filename in &removed_files {
//                     println!("Removed file: {:?}", filename);
                    fs::remove_file(filename)?;
                }

                Ok(())
            });
        }
    }).unwrap(); // XXX!

    Ok(())
}

