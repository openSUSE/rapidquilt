// Licensed under the MIT license. See LICENSE.md

use std::io::{self, BufWriter, Write};

use crate::patch::*;
use crate::patch::unified::*;


pub trait UnifiedPatchHunkWriter {
    fn write_header_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error>;
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error>;
}

pub trait UnifiedPatchWriter {
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error>;
}

pub trait UnifiedPatchRejWriter {
    fn write_rej_to<W: Write>(&self, interner: &LineInterner, writer: &mut W, report: &FilePatchApplyReport) -> Result<(), io::Error>;
}

impl<'a> UnifiedPatchHunkWriter for Hunk<'a, LineId> {
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
        if !self.function.is_empty() {
            writer.write_all(b" ")?;
            writer.write_all(self.function)?;
        }

        Ok(())
    }

    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error> {
        self.write_header_to(writer)?;

        writer.write_all(b"\n")?;

        fn find_closest_match(a: &[LineId], b: &[LineId]) -> (usize, usize) {
            for i in 0..(a.len() + b.len()) {
                for j in 0..std::cmp::min(i + 1, a.len()) {
                    if (i - j) < b.len() && a[j] == b[i - j] {
                        return (j, i - j);
                    }
                }
            }

            (a.len(), b.len())
        }

        let mut write_line = |c: u8, line_id: LineId| -> Result<(), io::Error> {
            let line = interner.get(line_id).unwrap(); // NOTE(unwrap): Must succeed, we are printing patch that was already interned. If it is not there, it is a bug.

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


fn write_file_patch_header_to<'a, W: Write>(filepatch: &FilePatch<'a, LineId>, writer: &mut BufWriter<W>) -> Result<(), io::Error> {
    // TODO: Currently we are writing patches with `strip` level 0, which is exactly
    //       what we need for .rej files. But we could add option to configure it?

    if filepatch.kind() == FilePatchKind::Create {
        writer.write_all(b"--- ")?;
        writer.write_all(&NULL_FILENAME)?;
        writer.write_all(b"\n")?;
    } else {
        writeln!(writer, "--- {}", filepatch.filename().display())?;
    }

    if filepatch.kind() == FilePatchKind::Delete {
        writer.write_all(b"+++ ")?;
        writer.write_all(&NULL_FILENAME)?;
        writer.write_all(b"\n")?;
    } else {
        writeln!(writer, "+++ {}", filepatch.filename().display())?;
    }

    Ok(())
}

impl<'a> UnifiedPatchWriter for FilePatch<'a, LineId> {
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error> {
        let mut writer = BufWriter::new(writer);

        write_file_patch_header_to(self, &mut writer)?;

        for hunk in &self.hunks {
            hunk.write_to(interner, &mut writer)?;
        }

        Ok(())
    }
}

impl<'a> UnifiedPatchRejWriter for FilePatch<'a, LineId> {
    fn write_rej_to<W: Write>(&self, interner: &LineInterner, writer: &mut W, report: &FilePatchApplyReport) -> Result<(), io::Error> {
        if report.ok() {
            return Ok(())
        }

        let mut writer = BufWriter::new(writer);

        write_file_patch_header_to(self, &mut writer)?;

        for (hunk, report) in self.hunks.iter().zip(report.hunk_reports()) {
            if let HunkApplyReport::Failed = report {
                hunk.write_to(interner, &mut writer)?;
            }
        }

        Ok(())
    }
}

