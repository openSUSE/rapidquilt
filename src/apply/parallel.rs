use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::fs;
use std::hash::BuildHasherDefault;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

use crossbeam;
use failure::Error;
use seahash;

use file_arena::FileArena;
use patch::{self, PatchDirection, InternedFilePatch, TextFilePatch, FilePatchKind};
use line_interner::LineInterner;
use interned_file::InternedFile;


enum Message<'a> {
    NextPatch(usize, TextFilePatch<'a>),
    NewMaxTarget(usize),
}

pub fn apply_patches<'a, P: AsRef<Path>>(patch_filenames: &[PathBuf], patches_path: P, direction: PatchDirection, strip: usize) -> Result<(), Error> {
    let patches_path = patches_path.as_ref();

    let applying_threads_count: usize = 7;


    println!("Patching...");

    let arena_ = FileArena::new();

    // TODO: Nicer way?
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..applying_threads_count {
        let (s, r) = crossbeam::channel::bounded::<Message>(32); // TODO: Fine-tune the capacity.
        senders.push(s);
        receivers.push(r);
    }

    crossbeam::thread::scope(|scope| {
        let arena = &arena_;

        scope.spawn(move |_| {
            for (index, patch_filename) in patch_filenames.iter().enumerate() {

//                 println!("Loading patch #{}: {:?}", index, patch_filename);

                let mut text_file_patches = (|| -> Result<_, Error> { // Poor man's try block
                    let data = arena.load_file(patches_path.join(patch_filename))?;
                    patch::parse_unified(&data, strip)
                })();

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
//                         panic!();
                        Err::<(), Error>(err).unwrap();
                    }
                };
            }
        });

        for (thread_index, receiver) in receivers.iter().enumerate() {
            let arena = &arena_;

            scope.spawn(move |_| -> Result<(), Error> {
                let mut interner = LineInterner::new();

                struct PatchStatus {
                    index: usize,
                    file_patch: InternedFilePatch,
                    // TODO...
                };

                let mut our_patches = Vec::<PatchStatus>::new();
                let mut current_patch = 0;

                let mut modified_files = HashMap::<PathBuf, InternedFile, BuildHasherDefault<seahash::SeaHasher>>::default();
                let mut removed_files = HashSet::<PathBuf, BuildHasherDefault<seahash::SeaHasher>>::default();

                for message in receiver.iter() {
                    match message {
                        Message::NextPatch(index, text_file_patch) => {

        //                     println!("Applying patch #{} file {:?}", index, text_file_patch.filename);

                            let file_patch = text_file_patch.intern(&mut interner);

                            let mut file = modified_files.entry(file_patch.filename.clone() /* <-TODO: Avoid clone */).or_insert_with(|| {
                                let data = match arena.load_file(&file_patch.filename) {
                                    Ok(data) => data,
                                    Err(_) => &[], // If the file doesn't exist, make empty one. TODO: Differentiate between "doesn't exist" and other errors!
                                };
                                InternedFile::new(&mut interner, &data)
                            });

                            removed_files.remove(&file_patch.filename);

                            file_patch.apply(&mut file, direction)?;

                            if file_patch.kind == FilePatchKind::Delete {
                                removed_files.insert(file_patch.filename.clone());
                            }

                            // The end condition **for now**
                            if index == patch_filenames.len() - 1 {
                                break;
                            }
                        },
                        _ => {
                            unimplemented!();
                        }
                    }
                }

                println!("Saving result...");

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

