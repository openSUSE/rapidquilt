// Licensed under the MIT license. See LICENSE.md

use std::io::{self, BufWriter, Write};

use crate::patch::*;
use crate::patch::unified::*;


pub trait UnifiedPatchHunkWriter {
    fn write_header_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error>;
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error>;
}

pub trait UnifiedPatchWriter {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error>;
}

pub trait UnifiedPatchRejWriter {
    fn write_rej_to<W: Write>(&self, writer: &mut W, report: &FilePatchApplyReport) -> Result<(), io::Error>;
}

impl<'a, L: Line<'a>> UnifiedPatchHunkWriter for Hunk<L> {
    fn write_header_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        let add_count = self.add.content.len();
        let remove_count = self.remove.content.len();

        let add_line = if add_count == 0 {
            0
        } else {
            self.add.target_line + 1
        };

        let remove_line = if remove_count == 0 {
            0
        } else {
            self.remove.target_line + 1
        };

        write!(writer, "@@ -{},{} +{},{} @@", remove_line, remove_count, add_line, add_count)?;

        let function: &[u8] = self.function.into();
        if !function.is_empty() {
            writer.write_all(b" ")?;
            writer.write_all(function)?;
        }

        Ok(())
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        self.write_header_to(writer)?;

        writer.write_all(b"\n")?;

        fn find_closest_match<'a, L: Line<'a>>(a: &[L], b: &[L]) -> (usize, usize) {
            for i in 0..(a.len() + b.len()) {
                for j in 0..std::cmp::min(i + 1, a.len()) {
                    if (i - j) < b.len() && a[j] == b[i - j] {
                        return (j, i - j);
                    }
                }
            }

            (a.len(), b.len())
        }

        let mut write_line = |c: u8, line: L| -> Result<(), io::Error> {
            let line: &[u8] = line.into();

            writer.write_all(&[c])?;
            writer.write_all(line)?;
            if line.last() != Some(&b'\n') {
                // If the line doesn't end with newline character, we have to write it ourselves
                // (otherwise it would not be valid patch file), but we also print the "No newline..."
                // tag which informs that the newline is not part of the file.
                writer.write_all(b"\n")?;
                writer.write_all(NO_NEW_LINE_TAG)?;
            }

            Ok(())
        };

        let mut add_i = 0;
        let mut remove_i = 0;

        let add = &self.add.content;
        let remove = &self.remove.content;

        while add_i < add.len() || remove_i < remove.len() {
            let (add_count, remove_count) = find_closest_match(&add[add_i..], &remove[remove_i..]);
            for _ in 0..remove_count {
                write_line(b'-', remove[remove_i])?;
                remove_i += 1;
            }
            for _ in 0..add_count {
                write_line(b'+', add[add_i])?;
                add_i += 1;
            }
            if add_i < add.len() && remove_i < remove.len() {
                write_line(b' ', remove[remove_i])?;
                remove_i += 1;
                add_i += 1;
            }
        }

        Ok(())
    }
}


fn write_file_patch_header_to<'a, L: Line<'a>, W: Write>(filepatch: &FilePatch<L>, writer: &mut BufWriter<W>) -> Result<(), io::Error> {
    // TODO: Currently we are writing patches with `strip` level 0, which is exactly
    //       what we need for .rej files. But we could add option to configure it?

    // Use the right one if there is, or the other one otherwise. At least one of them has to be there.
    let old_filename = filepatch.old_filename().or_else(|| filepatch.new_filename()).unwrap(); // NOTE(unwrap): At least one of them must be there.
    let new_filename = filepatch.new_filename().or_else(|| filepatch.old_filename()).unwrap(); // NOTE(unwrap): At least one of them must be there.

    // The "diff --git" line always seem to have real filenames, never "/dev/null"
    writeln!(writer, "diff --git {} {}", old_filename.display(), new_filename.display())?;

    // Print rename metadata
    if filepatch.is_rename() {
        writeln!(writer, "rename from {}", old_filename.display())?;
        writeln!(writer, "rename to {}", new_filename.display())?;
    }

    // Print permissions metadata
    if cfg!(unix) {
        use std::os::unix::fs::PermissionsExt;

        if let Some(permissions) = filepatch.old_permissions() {
            if filepatch.kind() == FilePatchKind::Delete {
                writeln!(writer, "delete file mode {:o}", permissions.mode())?;
            } else {
                writeln!(writer, "old mode {:o}", permissions.mode())?;
            }
        }

        if let Some(permissions) = filepatch.new_permissions() {
            if filepatch.kind() == FilePatchKind::Delete {
                writeln!(writer, "new file mode {:o}", permissions.mode())?;
            } else {
                writeln!(writer, "new mode {:o}", permissions.mode())?;
            }
        }
    }

    // Print --- line
    if filepatch.kind() == FilePatchKind::Create {
        writer.write_all(b"--- ")?;
        writer.write_all(&NULL_FILENAME)?;
        writer.write_all(b"\n")?;
    } else {
        writeln!(writer, "--- {}", old_filename.display())?;
    }

    // Print +++ line
    if filepatch.kind() == FilePatchKind::Delete {
        writer.write_all(b"+++ ")?;
        writer.write_all(&NULL_FILENAME)?;
        writer.write_all(b"\n")?;
    } else {
        writeln!(writer, "+++ {}", new_filename.display())?;
    }

    Ok(())
}

impl<'a, L: Line<'a>> UnifiedPatchWriter for FilePatch<L> {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        let mut writer = BufWriter::new(writer);

        write_file_patch_header_to(self, &mut writer)?;

        for hunk in &self.hunks {
            hunk.write_to(&mut writer)?;
        }

        Ok(())
    }
}

impl<'a, L: Line<'a>> UnifiedPatchRejWriter for FilePatch<L> {
    fn write_rej_to<W: Write>(&self, writer: &mut W, report: &FilePatchApplyReport) -> Result<(), io::Error> {
        if report.ok() {
            return Ok(())
        }

        let mut writer = BufWriter::new(writer);

        write_file_patch_header_to(self, &mut writer)?;

        for (hunk, report) in self.hunks.iter().zip(report.hunk_reports()) {
            if let HunkApplyReport::Failed = report {
                hunk.write_to(&mut writer)?;
            }
        }

        Ok(())
    }
}

