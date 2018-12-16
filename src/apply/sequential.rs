use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::fs;
use std::hash::BuildHasherDefault;
use std::path::{Path, PathBuf};

use failure::Error;
use seahash;

use crate::file_arena::FileArena;
use crate::patch::{self, PatchDirection, FilePatchKind, InternedFilePatch, FilePatchApplyReport};
use crate::line_interner::LineInterner;
use crate::interned_file::InternedFile;


pub fn apply_patches<P: AsRef<Path>>(patch_filenames: &[PathBuf], patches_path: P, strip: usize) -> Result<(), Error> {
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
        println!("Patch: {:?}", patch_filename);

        let data = arena.load_file(patches_path.join(patch_filename))?;
        let mut text_file_patches = patch::parse_unified(&data, strip)?;
        let file_patches: Vec<_> = text_file_patches.drain(..).map(|text_file_patch| text_file_patch.intern(&mut interner)).collect();
        let mut reports = Vec::with_capacity(file_patches.len());
        let mut any_report_failed = false;
//         let mut failure_reports = HashMap::<PathBuf, FilePatchApplyReport>::new();

        for file_patch in &file_patches {
            let mut file = modified_files.entry(file_patch.filename.clone() /* <-TODO: Avoid clone */).or_insert_with(|| {
                let data = match arena.load_file(&file_patch.filename) {
                    Ok(data) => data,
                    Err(_) => &[], // If the file doesn't exist, make empty one. TODO: Differentiate between "doesn't exist" and other errors!
                };
                InternedFile::new(&mut interner, &data)
            });

//             backup_file(patch_filename, file_patch.filename, file, &interner.lock().unwrap())?;

            removed_files.remove(&file_patch.filename);

            let report = file_patch.apply(&mut file, PatchDirection::Forward);

            if file_patch.kind == FilePatchKind::Delete {
                removed_files.insert(file_patch.filename.clone());
            }

            if report.failed() {
                any_report_failed = true;
            }

            reports.push(report);
        }

        if any_report_failed {
            println!("Patch failed! Reports: {:?}", reports);

            // Rollback the file
            for (file_patch, report) in file_patches.iter().zip(reports) {
                let mut file = modified_files.get_mut(&file_patch.filename).unwrap(); // It must be there, we must have loaded it when applying the patch.
                file_patch.rollback(&mut file, PatchDirection::Forward, &report);

                if file_patch.kind == FilePatchKind::Delete {
                    removed_files.remove(&file_patch.filename);
                }
            }

            // TODO: Generate .rej file

            break;
        }

//         writeln!(applied_patches_file, "{}", patch_filename.to_str().unwrap_or("<BAD UTF-8>"));
    }

    println!("Saving result...");

    for (filename, file) in &modified_files {
        println!("Modified file: {:?}", filename);
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
