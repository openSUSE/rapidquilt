use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::vec::Vec;

use failure::{Error, ResultExt};

use crate::patch::unified::parser::parse_patch;
use crate::patch::unified::writer::UnifiedPatchWriter;
use crate::patch::TextPatch;

#[cfg(test)]
fn compare_output<'a>(path: &Path, patch: TextPatch<'a>) -> Result<(), Error> {
    let mut output = Vec::<u8>::new();
    patch.write_to(&mut output)?;

    let expected_output = fs::read(path.with_extension("patch-expected")).with_context(|_| {
        "Patch parsed ok, but test could not open \"*.patch-expected\" file".to_string()
    })?;

    if output != expected_output {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        writeln!(stderr, "*** EXPECTED ***")?;
        stderr.write(&expected_output)?;
        writeln!(stderr, "*** WROTE ***")?;
        stderr.write(&output)?;

        // Try to save what we thought should be there, but ignore errors
        if let Ok(mut file) = fs::File::create(path.with_extension("patch-bad")) {
            let _ = file.write_all(&output);
        }

        panic!("The patch in its canonical form does not match the expected output!");
    }

    Ok(())
}

#[cfg(test)]
fn compare_error(path: &Path, error: Error) -> Result<(), Error> {
    use std::fmt::Write;
    let mut error_str = String::new();
    write!(error_str, "{:?}\n{}", error, error)?;

    let file = File::open(path.with_extension("error")).with_context(|_| {
        "Patch failed to parse, but test could not open \"*.error\" file".to_string()
    })?;
    let reader = BufReader::new(file);
    let expected_error = reader.lines().next().unwrap()?;

    if !error_str.contains(&expected_error) {
        panic!(
            "Expected error containing: \"{}\", but got this instead: \"{}\"",
            expected_error, error_str
        );
    }

    Ok(())
}

#[cfg(test)]
#[test]
fn all_files() -> Result<(), Error> {
    for entry in fs::read_dir("testdata/parsing")? {
        let entry = entry?;
        let path = entry.path();
        match path.extension() {
            Some(extension) if extension == "patch" => {}
            _ => continue,
        }

        eprintln!("Testing patch {}", path.display());

        let patch_data = fs::read(&path)?;

        let strip = 0;
        match parse_patch(&patch_data, strip, true) {
            Ok(patch) => {
                compare_output(&path, patch)?;
            }
            Err(error) => {
                compare_error(&path, error)?;
            }
        };
    }

    Ok(())
}
