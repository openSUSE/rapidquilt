use std::fs;
use std::io::Write;
use std::vec::Vec;

use anyhow::{bail, Context, Result};

use crate::analysis::{AnalysisSet, fn_analysis_note_noop};
use crate::modified_file::ModifiedFile;
use crate::patch::PatchDirection;
use crate::patch::unified::parser::parse_patch;


#[cfg(test)]
#[test]
fn all_files() -> Result<()> {
    for entry in fs::read_dir("testdata/patching")? {
        // Skip everything that doesn't end with ".patch"
        let entry = entry?;
        let path = entry.path();
        match path.extension() {
            Some(extension) if extension == "patch" => {},
            _ => continue,
        }

        eprintln!("Testing patch {}", path.display());

        // Load and parse the patch
        let patch_data = fs::read(&path)?;
        let strip = 0;
        let patch = parse_patch(&patch_data, strip)?;

        // Parse our special headers
        let mut fuzz = 0;
        for header_line in patch.header.split(|&c| c == b'\n') {
            let header_line = String::from_utf8_lossy(header_line);
            match &header_line.splitn(2, ": ").collect::<Vec<_>>()[..] {
                ["fuzz", fuzz_str] => {
                    fuzz = fuzz_str.parse()?;
                }
                _ => {}
            }
        }

        // Check that there is exactly one FilePatch
        if patch.file_patches.len() != 1 {
            panic!("Test patch {} is for {} files, expected exactly one!", path.display(), patch.file_patches.len());
        }
        let file_patch = &patch.file_patches[0];

        // Load the target file
        // Note: In this case we always expect the old_filename to exist, so we
        //       select it directly.
        let file = if let Some(old_filename) = file_patch.old_filename() {
	    fs::read(path.with_file_name(old_filename.as_ref()))?
	} else {
	    vec![]
	};
        let mut modified_file = ModifiedFile::new(&file, true, None);

        // Patch it
        let report = file_patch.apply(&mut modified_file, PatchDirection::Forward, fuzz, &AnalysisSet::default(), &fn_analysis_note_noop);

        // Check if it failed when shouldn't or succeeded when it was expected to fail
        let error_file = path.with_extension("error");
        let should_fail = error_file.exists();
        if should_fail {
            if report.ok() {
                panic!("The {} file exists, so apply failure is expected, but patch applied successfully!", error_file.display());
            }

            // We are done with this patch then
            continue
        }
        if !should_fail && report.failed() {
            panic!("The patch unexpectedly failed to apply! Report: {:#?}", report);
        }

        // Write the output to a buffer
        let mut output = Vec::<u8>::new();
        modified_file.write_to(&mut output)?;

        // Compare with the expected output
	let expected_file = path.with_extension("out");
	let expected_output = if modified_file.deleted {
	    if expected_file.try_exists()? {
		bail!("{} exists, but the patch was interpreted as delete!", expected_file.display());
	    }
	    vec![]
	} else {
            fs::read(&expected_file).with_context(|| format!("Failed to open {}", expected_file.display()))?
	};

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

	// Try to rollback
	file_patch.rollback(&mut modified_file, PatchDirection::Forward, &report);
	let mut rollback = Vec::<u8>::new();
	modified_file.write_to(&mut rollback)?;
	if rollback != file {
	    let stderr = std::io::stderr();
	    let mut stderr = stderr.lock();
	    writeln!(stderr, "*** ORIGINAL ***")?;
	    stderr.write(&file)?;
	    writeln!(stderr, "*** ROLLBACK ***")?;
	    stderr.write(&rollback)?;
	    panic!("Content after rollback does not match the original input!");
	}
    }

    Ok(())
}
