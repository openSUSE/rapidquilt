#[macro_use] extern crate failure;
#[macro_use] extern crate lazy_static;
extern crate regex;
extern crate libc;
extern crate seahash;
extern crate crossbeam;

mod line_interner;
mod file_arena;
mod interned_file;
mod patch;

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::fs;
use std::hash::BuildHasherDefault;
use std::io::BufRead;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use failure::Error;

use file_arena::FileArena;
use patch::{PatchDirection, TextFilePatch, FilePatchKind};
use line_interner::LineInterner;
use interned_file::InternedFile;


fn read_series_file<P: AsRef<Path>>(series_path: P) -> Result<Vec<PathBuf>, Error> {
    let file = File::open(series_path)?;
    let file = BufReader::new(file);

    let patch_filenames = file
        .lines()
        .map(|line| line.unwrap() /* <- TODO: Propagate up. */)
        .filter(|line| line.len() > 0 && !line.starts_with('#')) // man quilt says that comment lines start with '#', it does not mention any whitespace before that (TODO: Verify)
        .map(|line| {
            // TODO: Handle comments after the patch name

            std::path::PathBuf::from(line)
        }).collect();

    Ok(patch_filenames)
}

fn backup_file(patch_filename: &Path, filename: &Path, original_file: &InternedFile, interner: &LineInterner) -> Result<(), Error> {
    let mut path = PathBuf::from(".pc");
    path.push(patch_filename);
    path.push(&filename);

    fs::create_dir_all(&path.parent().unwrap())?;
    original_file.write_to(interner, &mut File::create(path)?)?;

    Ok(())
}

fn apply_patches<P: AsRef<Path>>(patch_filenames: &[PathBuf], patches_path: P, direction: PatchDirection, strip: usize) -> Result<(), Error> {
    let arena = FileArena::new();
    let mut interner = LineInterner::new();

    let mut modified_files = HashMap::<PathBuf, InternedFile, BuildHasherDefault<seahash::SeaHasher>>::default();
    let mut removed_files = HashSet::<PathBuf, BuildHasherDefault<seahash::SeaHasher>>::default();

//     let mut applied_patches_file = {
//         fs::create_dir_all(".pc")?;
//         File::create(".pc/applied-patches")?
//     };

    println!("Patching...");

    let patches_path = patches_path.as_ref();
    for patch_filename in patch_filenames {
//         println!("Patch: {:?}", patch_filename);

        let data = arena.load_file(patches_path.join(patch_filename))?;
        let mut text_file_patches = patch::parse_unified(&data, strip)?;
        let file_patches: Vec<_> = text_file_patches.drain(..).map(|text_file_patch| text_file_patch.intern(&mut interner)).collect();

        for file_patch in file_patches {
            let mut file = modified_files.entry(file_patch.filename.clone() /* <-TODO: Avoid clone */).or_insert_with(|| {
                let data = match arena.load_file(&file_patch.filename) {
                    Ok(data) => data,
                    Err(_) => &[], // If the file doesn't exist, make empty one. TODO: Differentiate between "doesn't exist" and other errors!
                };
                InternedFile::new(&mut interner, &data)
            });

//             backup_file(patch_filename, file_patch.filename, file, &interner.lock().unwrap())?;

            removed_files.remove(&file_patch.filename);

            file_patch.apply(&mut file, direction)?;

            if file_patch.kind == FilePatchKind::Delete {
                removed_files.insert(file_patch.filename.clone());
            }
        }

//         writeln!(applied_patches_file, "{}", patch_filename.to_str().unwrap_or("<BAD UTF-8>"));
    }

    println!("Saving result...");

    // XXX:
    println!("...or NOT!");
    return Ok(());

    for (filename, file) in &modified_files {
//         println!("Modified file: {:?}", filename);
        let _ = fs::remove_file(filename);
        if let Some(parent) = filename.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut output = File::create(filename)?;
        file.write_to(&interner, &mut output)?;
    }

    for filename in &removed_files {
//         println!("Removed file: {:?}", filename);
        fs::remove_file(filename)?;
    }

    Ok(())
}

fn apply_patches_parallel<P: AsRef<Path>>(patch_filenames: &[PathBuf], patches_path: P, direction: PatchDirection, strip: usize) -> Result<(), Error> {
    let patches_path = patches_path.as_ref();

    let applying_threads_count: usize = 7;


    println!("Patching...");

    let arena_ = FileArena::new();

    // TODO: Nicer way?
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..applying_threads_count {
        let (s, r) = crossbeam::channel::bounded::<(usize, TextFilePatch)>(32); // TODO: Fine-tune the capacity.
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
                            senders[thread_index].send((index, text_file_patch)).unwrap(); // TODO: Properly propagate up?
                        }
                    }
                    Err(err) => {
                        // TODO: Failure, signal that this is the new goal and save the error somewhere up...
                        //       But for now just terminate!
                        panic!();
                    }
                };
            }
        });

        for (thread_index, receiver) in receivers.iter().enumerate() {
            let arena = &arena_;

            scope.spawn(move |_| -> Result<(), Error> {
                let mut interner = LineInterner::new();

                let mut modified_files = HashMap::<PathBuf, InternedFile, BuildHasherDefault<seahash::SeaHasher>>::default();
                let mut removed_files = HashSet::<PathBuf, BuildHasherDefault<seahash::SeaHasher>>::default();

                for (index, text_file_patch) in receiver.iter() {

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
                }

                println!("Saving result...");

                // XXX:
                println!("...or NOT!");
                return Ok(());

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

fn main() {
    let args: Vec<_> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: rapidquilt push|pop [<to patch> [<from patch>]]");
        return;
    }

    let mut direction = PatchDirection::Forward;
    if args[1] == "pop" {
        direction = PatchDirection::Revert;
    }

    let patch_filenames = {
        let mut patch_filenames = read_series_file("series").unwrap();
        if direction == PatchDirection::Revert {
            patch_filenames.reverse();
        }
        patch_filenames
    };

    let mut to_patch = patch_filenames.len() - 1;
    if args.len() >= 3 {
        let patch_filename = PathBuf::from(&args[2]);
        if let Some(index) = patch_filenames.iter().position(|item| *item == patch_filename) {
            to_patch = index;
        } else {
            println!("Patch not in series: {:?}", patch_filename);
            return;
        }
    }

    let mut from_patch = 0;
    if args.len() >= 4 {
        let patch_filename = PathBuf::from(&args[3]);
        if let Some(index) = patch_filenames.iter().position(|item| *item == patch_filename) {
            from_patch = index;
        } else {
            println!("Patch not in series: {:?}", patch_filename);
            return;
        }
    }

    apply_patches/*_parallel*/(&patch_filenames[from_patch..=to_patch], "patches", direction, 1).unwrap();
}
