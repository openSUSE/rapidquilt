use std::collections::HashMap;
use std::fs::File;
use std::hash::BuildHasherDefault;
use std::path::{Path, PathBuf};

use failure::Error;
use seahash;

use crate::apply::common::*;
use crate::file_arena::FileArena;
use crate::patch::{self, PatchDirection, FilePatchKind, InternedFilePatch, FilePatchApplyReport};
use crate::line_interner::LineInterner;
use crate::interned_file::InternedFile;


pub fn apply_patches<'a, P: AsRef<Path>>(patch_filenames: &'a [PathBuf], patches_path: P, strip: usize) -> Result<ApplyResult<'a>, Error> {
    let arena = FileArena::new();
    let mut interner = LineInterner::new();

    let mut applied_patches = Vec::<PatchStatus>::new();

    let mut modified_files = HashMap::<PathBuf, InternedFile, BuildHasherDefault<seahash::SeaHasher>>::default();

    let mut final_patch = 0;

    println!("Applying {} patches single-threaded...", patch_filenames.len());

    let patches_path = patches_path.as_ref();
    for (index, patch_filename) in patch_filenames.iter().enumerate() {
//         println!("Patch: {:?}", patch_filename);

        final_patch = index;

        let data = arena.load_file(patches_path.join(patch_filename))?;
        let mut text_file_patches = patch::parse_unified(&data, strip)?;
        let file_patches: Vec<_> = text_file_patches.drain(..).map(|text_file_patch| text_file_patch.intern(&mut interner)).collect();
        let mut any_report_failed = false;

        for file_patch in file_patches {
            let mut file = modified_files.entry(file_patch.filename.clone() /* <-TODO: Avoid clone */).or_insert_with(|| {
                match arena.load_file(&file_patch.filename) {
                    Ok(data) => InternedFile::new(&mut interner, &data),
                    Err(_) => InternedFile::new_non_existent(), // If the file doesn't exist, make empty one. TODO: Differentiate between "doesn't exist" and other errors!
                }
            });

            let report = file_patch.apply(&mut file, PatchDirection::Forward);

            if report.failed() {
                any_report_failed = true;
            }

            applied_patches.push(PatchStatus {
                index,
                file_patch,
                report,
                patch_filename: &patch_filenames[index],
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

    if final_patch != patch_filenames.len() {
        println!("Saving quilt backup files...");

        rollback_and_save_backup_files(&mut applied_patches, &mut modified_files, &interner)?;
    }

    Ok(ApplyResult {
        applied_patches: &patch_filenames[0..final_patch],
        skipped_patches: &patch_filenames[final_patch..],
    })
}
