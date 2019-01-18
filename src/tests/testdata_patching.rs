use std::fs;
use std::io::Write;
use std::vec::Vec;

use failure::Error;

use crate::arena::{Arena, FileArena};
use crate::modified_file::ModifiedFile;
use crate::patch::PatchDirection;
use crate::patch::unified::parser::parse_patch;


#[cfg(test)]
#[test]
fn all_files() -> Result<(), Error> {
    for entry in fs::read_dir("testdata/patching")? {
        // Skip everything that doesn't end with ".patch"
        let entry = entry?;
        let path = entry.path();
        match path.extension() {
            Some(extension) if extension == "patch" => {},
            _ => continue,
        }

        eprintln!("Testing patch {}", path.display());

        let arena = FileArena::new();

        // Load and parse the patch
        let patch_data = arena.load_file(&path)?;
        let strip = 0;
        let mut file_patches = parse_patch::<&[u8]>(&patch_data, strip)?;

        // Check that there is exactly one FilePatch
        if file_patches.len() != 1 {
            panic!("Test patch {} is for {} files, expected exactly one!", path.display(), file_patches.len());
        }
        let file_patch = file_patches.pop().unwrap();

        // Load the target file
        // Note: In this case we always expect the old_filename to exist, so we
        //       select it directly.
        let file = arena.load_file(&path.with_file_name(file_patch.old_filename().expect("old_filename missing!")))?;
        let mut modified_file = ModifiedFile::new(&file, true);

        // Patch it
        let report = file_patch.apply(&mut modified_file, PatchDirection::Forward, 0);
        assert!(report.ok());

        // Write the output to a buffer
        let mut output = Vec::<u8>::new();
        modified_file.write_to(&mut output)?;

        // Compare with the expected output
        let expected_output = fs::read(path.with_extension("out"))?;

        if output != expected_output {
            let stderr = std::io::stderr();
            let mut stderr = stderr.lock();
            writeln!(stderr, "*** EXPECTED ***")?;
            stderr.write(&expected_output)?;
            writeln!(stderr, "*** WROTE ***")?;
            stderr.write(&output)?;

            // Try to save what we thought should be there, but ignore errors
            if let Ok(mut file) = fs::File::create(path.with_extension("out-bad")) {
                let _ = file.write_all(&output);
            }

            panic!("The patched file does not match the expected output!");
        }
    }

    Ok(())
}
