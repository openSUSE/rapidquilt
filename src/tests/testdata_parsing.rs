use std::fs;
use std::io::Write;
use std::vec::Vec;

use failure::Error;

use crate::patch::unified::parser::parse_patch;
use crate::patch::unified::writer::UnifiedPatchWriter;
use crate::line_interner::LineInterner;


#[cfg(test)]
#[test]
fn all_files() -> Result<(), Error> {
    for entry in fs::read_dir("testdata/parsing")? {
        let entry = entry?;
        let path = entry.path();
        match path.extension() {
            Some(extension) if extension == "patch" => {},
            _ => continue,
        }

        eprintln!("Testing patch {}", path.display());

        let patch_data = fs::read(&path)?;

        let strip = 0;
        let file_patches = parse_patch(&patch_data, strip)?;

        // XXX: We could implement UnifiedPatchWriter for TextFilePatch and completely
        //      skip the interning in this test. But we don't really need to print
        //      pre-interned patches anywhere else but in this test.
        let mut interner = LineInterner::new();

        let mut output = Vec::<u8>::new();
        for file_patch in file_patches {
            let file_patch = file_patch.intern(&mut interner);
            file_patch.write_to(&interner, &mut output)?;
        }

        let expected_output = fs::read(path.with_extension("patch-expected"))?;

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
    }

    Ok(())
}
