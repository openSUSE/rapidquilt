// Licensed under the MIT license. See LICENSE.md

use std::io::{BufWriter, Write};
use std::vec::Vec;
use std::path::PathBuf;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::str;

use failure::Error;
use regex::bytes::{Regex, RegexSet};

use crate::line_interner::{LineId, LineInterner, EMPTY_LINE_ID, EMPTY_LINE_SLICE};
use crate::patch::*;


const NO_NEW_LINE_TAG: &[u8] = b"\\ No newline at end of file";
const NULL_FILENAME: &[u8] = b"/dev/null";

lazy_static! {
    static ref MINUS_FILENAME: Regex = Regex::new(r"^--- ([^\t]+)").unwrap();
    static ref PLUS_FILENAME: Regex = Regex::new(r"^\+\+\+ ([^\t]+)").unwrap();

    // Warning: It seems that patch accepts if the second '@' in the second "@@" group is missing!
    static ref CHUNK: Regex = Regex::new(r"^@@ -(?P<remove_line>[\d]+)(?:,(?P<remove_count>[\d]+))? \+(?P<add_line>[\d]+)(?:,(?P<add_count>[\d]+))? @@?(?P<place_name>.*)").unwrap();

    // Same order as MatchedMetadata enum
    static ref METADATA: RegexSet = RegexSet::new(&[
        r"^index", // TODO: ?
        r"^old mode +(?P<permissions>[0-9]+)$",
        r"^new mode +(?P<permissions>[0-9]+)$",
        r"^deleted file mode +(?P<permissions>[0-9]+)$",
        r"^new file mode +(?P<permissions>[0-9]+)$",
        r"^rename from ",  // patch ignores the filename behind this
        r"^rename to ",    // patch ignores the filename behind this
        r"^copy from ",    // patch ignores the filename behind this
        r"^copy to ",      // patch ignores the filename behind this
        r"^GIT binary patch", // TODO: ???
    ]).unwrap();
}

// Same order as METADATA RegexSet!
#[repr(usize)]
enum MatchedMetadata {
    Index = 0,
    OldMode,
    NewMode,
    DeletedFileMode,
    NewFileMode,
    RenameFrom,
    RenameTo,
    CopyFrom,
    CopyTo,
    GitBinaryPatch
}

struct FilePatchMetadata {
    rename_from: bool,
    rename_to: bool,
}

impl Default for FilePatchMetadata {
    fn default() -> Self {
        FilePatchMetadata {
            rename_from: false,
            rename_to: false,
        }
    }
}

pub fn parse_unified<'a>(bytes: &'a [u8], strip: usize) -> Result<Vec<TextFilePatch<'a>>, Error> {
    let mut file_patches = Vec::new();

    let mut lines = bytes.split(|c| *c == b'\n').peekable();

    let mut filepatch_metadata = FilePatchMetadata::default();

    while let Some(line) = lines.next() {
        if let Some(metadata) = METADATA.matches(line).iter().next() { // There will be at most one match because the METADATA regexes are mutually exclusive
            // TODO: Use TryFrom instead of transmute when stable.
            match unsafe { std::mem::transmute::<usize, MatchedMetadata>(metadata) } {
                MatchedMetadata::RenameFrom => {
                    // We do not actually care about the filename written next to the "rename from" line.
                    // patch doesn't care either
                    filepatch_metadata.rename_from = true;
                },
                MatchedMetadata::RenameTo => {
                    // We do not actually care about the filename written next to the "rename to" line.
                    // patch doesn't care either
                    filepatch_metadata.rename_to = true;
                },
                MatchedMetadata::GitBinaryPatch => {
                    return Err(format_err!("GIT binary patch is not supported!"));
                }
                _ => {
                    // TODO: Handle the other metadata...
                }
            }
            continue;
        }

        let minus_filename = match MINUS_FILENAME.captures(line) {
            Some(capture) => capture.get(1).unwrap().as_bytes(),
            None => continue // It was garbage, go for next line
        };

        let plus_filename = match lines.peek().and_then(|line| PLUS_FILENAME.captures(line)) {
            Some(capture) => {
                lines.next(); // We just peeked, so consume it now.
                capture.get(1).unwrap().as_bytes()
            },
            None => {
                // patch ignores if there is "--- filename1" line followed by something else than "+++ filename2", so we have to ignore it too.
                continue
            }
        };

        let mut filepatch = {
            let (kind, filename, other_filename) = if minus_filename == NULL_FILENAME {
                (FilePatchKind::Create, plus_filename, None)
            } else if plus_filename == NULL_FILENAME {
                (FilePatchKind::Delete, minus_filename, None)
            } else {
                // TODO: What to do if plus_filename and minus_filename differ after stripping the beginning?

                (FilePatchKind::Modify, plus_filename, Some(minus_filename))
            };

            fn strip_filename(filename: &[u8], strip: usize) -> Result<PathBuf, Error> {
                let filename = PathBuf::from(OsStr::from_bytes(filename));
                if !filename.is_relative() {
                    return Err(format_err!("Path in patch is not relative: \"{:?}\"", filename));
                }

                let mut components = filename.components();
                for _ in 0..strip { components.next(); }
                Ok(components.as_path().to_path_buf())
            }

            let filename = strip_filename(filename, strip)?;

            if filepatch_metadata.rename_from && filepatch_metadata.rename_to && other_filename.is_some() {
                let original_filename = strip_filename(other_filename.unwrap(), strip)?;
                FilePatch::new_renamed(kind, filename, original_filename)
            } else {
                FilePatch::new(kind, filename)
            }
        };

        // Read hunks
        loop {
            let (mut remove_line, mut remove_count, mut add_line, mut add_count, place_name) =
                match lines.peek().and_then(|line| CHUNK.captures(line)) {
                    Some(capture) => {
                        fn parse_bytes_to_isize(bytes: &[u8]) -> isize {
                            // Unsafe and unwrap is ok because we are giving it only digit characters
                            unsafe { str::from_utf8_unchecked(bytes) }.parse().unwrap()
                        }

                        // Unwraps are ok because the regex guarantees that it will be valid number
                        let remove_line  = parse_bytes_to_isize(capture.name("remove_line").unwrap().as_bytes());
                        let remove_count = capture.name("remove_count").map(|m| parse_bytes_to_isize(m.as_bytes())).unwrap_or(1);
                        let add_line  = parse_bytes_to_isize(capture.name("add_line").unwrap().as_bytes());
                        let add_count = capture.name("add_count").map(|m| parse_bytes_to_isize(m.as_bytes())).unwrap_or(1);

                        let place_name = capture.name("place_name").unwrap().as_bytes();

                        (remove_line, remove_count, add_line, add_count, place_name)
                    }
                    None => break // No more hunks, next file to patch, garbage or end of file.
                };

            lines.next(); // Pull out the line we peeked

            // It seems that there are patches that do not use the /dev/null filename, yet they add or remove
            // complete files. Recognize these as well.
            if remove_line == 0 {
                filepatch.change_kind(FilePatchKind::Create);
            } else if add_line == 0 {
                filepatch.change_kind(FilePatchKind::Delete);
            }

            // Convert lines to zero-based numbering. But don't do that if we are creating/deleting (in that case it is 0 and would underflow)
            if filepatch.kind() == FilePatchKind::Create {
                remove_count = 0;
            } else {
                remove_line -= 1;
            }
            if filepatch.kind() == FilePatchKind::Delete {
                add_count = 0;
            } else {
                add_line -= 1;
            }
            let mut hunk = Hunk::new(remove_line, add_line, place_name);
            hunk.add.content.reserve(add_count as usize);
            hunk.remove.content.reserve(remove_count as usize);

            // Counters for amount of context
            let mut there_was_a_non_context_line = false;

            // Newline at the end markers
            let mut minus_newline_at_end = false;
            let mut plus_newline_at_end = false;

            // Read hunk lines
            while remove_count > 0 || add_count > 0 {
                let line = match lines.next() {
                    Some(line) => line,
                    None => {
                        return Err(format_err!("Unexpected EOF in patch!"));
                    }
                };

                // XXX: It seems that patches may have empty lines representing
                //      empty line of context. So if we see that, lets replace it
                //      what should have been there - a single space.
                let line = if line.len() == 0 {
                    b" "
                } else {
                    line
                };

                let mut line_content = &line[1..];

                match line[0] {
                    b' ' | b'\t' => {
                        // Apparently patch accepts tabs in context too and just takes the
                        // whole line as context...
                        // TODO: Maybe it accepts just anything that doesn't start with space, plus or minus?
                        if line[0] == b'\t' {
                            line_content = &line[..];
                        }

                        hunk.remove.content.push(line_content);
                        hunk.add.content.push(line_content);
                        remove_count -= 1;
                        add_count -= 1;

                        if !there_was_a_non_context_line {
                            hunk.context_before += 1;
                        } else {
                            hunk.context_after += 1;
                        }

                        if minus_newline_at_end || plus_newline_at_end {
                            return Err(format_err!("Badly formated patch!"));
                        }

                        if lines.peek() == Some(&NO_NEW_LINE_TAG) {
                            lines.next(); // Skip it
                            plus_newline_at_end = true;
                            minus_newline_at_end = true;
                        }
                    }
                    b'-' => {
                        hunk.remove.content.push(line_content);
                        remove_count -= 1;

                        there_was_a_non_context_line = true;
                        hunk.context_after = 0;

                        if minus_newline_at_end {
                            return Err(format_err!("Badly formated patch!"));
                        }

                        if lines.peek() == Some(&NO_NEW_LINE_TAG) {
                            lines.next(); // Skip it
                            minus_newline_at_end = true;
                        }
                    }
                    b'+' => {
                        hunk.add.content.push(line_content);
                        add_count -= 1;

                        there_was_a_non_context_line = true;
                        hunk.context_after = 0;

                        if plus_newline_at_end {
                            return Err(format_err!("Badly formated patch!"));
                        }

                        if lines.peek() == Some(&NO_NEW_LINE_TAG) {
                            lines.next(); // Skip it
                            plus_newline_at_end = true;
                        }
                    }
                    _ => {
                        return Err(format_err!("Badly formated patch line: \"{}\"", str::from_utf8(line).unwrap_or("<BAD UTF-8>")));
                    }
                }
            }

            // man patch: "Hunks with less prefix context than suffix context (after applying fuzz) must apply at the
            //             start of the file if their first line  number is 1. Hunks with more prefix context than suffix
            //             context (after applying fuzz) must apply at the end of the file."
            if hunk.context_before < hunk.context_after && add_line == 0 {
                hunk.position = HunkPosition::Start;
            } else if hunk.context_before > hunk.context_after {
                hunk.position = HunkPosition::End;
            }

            if hunk.context_after == 0 || hunk.context_after < hunk.context_before {
                // If we are applying the end, add the implicit empty new line, unless there was the "No newline" tag.
                if !plus_newline_at_end && filepatch.kind() != FilePatchKind::Delete {
                    hunk.add.content.push(&EMPTY_LINE_SLICE);
                }
                if !minus_newline_at_end && filepatch.kind() != FilePatchKind::Create {
                    hunk.remove.content.push(&EMPTY_LINE_SLICE);
                }
            }

            filepatch.hunks.push(hunk);
        }

        file_patches.push(filepatch);
    }

    Ok(file_patches)
}

pub trait UnifiedPatchWriter {
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), Error>;
}

pub trait UnifiedPatchRejWriter {
    fn write_rej_to<W: Write>(&self, interner: &LineInterner, writer: &mut W, report: &FilePatchApplyReport) -> Result<(), Error>;
}

impl<'a> UnifiedPatchWriter for Hunk<'a, LineId> {
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), Error> {
        // If you think this looks more complicated than it should be, it is because it must correctly print out "No newline at the end of file" lines

        let hunk_goes_to_end = (self.position == HunkPosition::End || /*filepatch_kind != FilePatchKind::Modify*/ self.add.content.len() == 0 || self.remove.content.len() == 0);

        let add_has_end_empty_line = hunk_goes_to_end && self.add.content.last() == Some(&EMPTY_LINE_ID);
        let add_count = if add_has_end_empty_line {
            self.add.content.len() - 1
        } else {
            self.add.content.len()
        };

        let remove_has_end_empty_line = hunk_goes_to_end && self.remove.content.last() == Some(&EMPTY_LINE_ID);
        let remove_count = if remove_has_end_empty_line {
            self.remove.content.len() - 1
        } else {
            self.remove.content.len()
        };

        let add_line = if /*filepatch_kind == FilePatchKind::Delete*/ self.add.content.len() == 0 {
            0
        } else {
            self.add.target_line + 1
        };

        let remove_line = if /*filepatch_kind == FilePatchKind::Create*/ self.remove.content.len() == 0 {
            0
        } else {
            self.remove.target_line + 1
        };

        write!(writer, "@@ -{},{} +{},{} @@", remove_line, remove_count, add_line, add_count)?;
        writer.write(self.place_name)?;
        writer.write(b"\n")?;

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

        let mut write_line = |c: u8, line_id: LineId, last_line: bool| -> Result<(), Error> {
            // We mustn't write the empty line at the end
            if !last_line || line_id != EMPTY_LINE_ID {
                writer.write(&[c])?;
                writer.write(interner.get(line_id).unwrap())?;
                writer.write(b"\n")?;
            }

            // If it was last line and wasn't empty line, write the No new line message...
            if last_line && line_id != EMPTY_LINE_ID {
                writer.write(NO_NEW_LINE_TAG)?;
                writer.write(b"\n")?;
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
                write_line(b'-', remove[remove_i], hunk_goes_to_end && remove_i == remove.len() - 1)?;
                remove_i += 1;
            }
            for _ in 0..add_count {
                write_line(b'+', add[add_i], hunk_goes_to_end && add_i == add.len() - 1)?;
                add_i += 1;
            }
            if add_i < add.len() && remove_i < remove.len() {
                if hunk_goes_to_end && add_has_end_empty_line != remove_has_end_empty_line && (remove_i == remove.len() - 1 || add_i == add.len() - 1) {
                    write_line(b'-', remove[remove_i], hunk_goes_to_end && remove_i == remove.len() - 1)?;
                    write_line(b'+', add[add_i],       hunk_goes_to_end && add_i == add.len() - 1)?;
                } else {
                    write_line(b' ', remove[remove_i], hunk_goes_to_end && remove_i == remove.len() - 1)?;
                }
                remove_i += 1;
                add_i += 1;
            }
        }

        Ok(())
    }
}


fn write_file_patch_header_to<'a, W: Write>(filepatch: &FilePatch<'a, LineId>, writer: &mut BufWriter<W>) -> Result<(), Error> {
    // TODO: Currently we are writing patches with `strip` level 0, which is exactly
    //       what we need for .rej files. But we could add option to configure it?

    if filepatch.kind() == FilePatchKind::Create {
        writer.write(b"--- ")?;
        writer.write(&NULL_FILENAME)?;
        writer.write(b"\n")?;
    } else {
        writeln!(writer, "--- {}", filepatch.filename().display())?;
    }

    if filepatch.kind() == FilePatchKind::Delete {
        writer.write(b"+++ ")?;
        writer.write(&NULL_FILENAME)?;
        writer.write(b"\n")?;
    } else {
        writeln!(writer, "+++ {}", filepatch.filename().display())?;
    }

    Ok(())
}

impl<'a> UnifiedPatchWriter for FilePatch<'a, LineId> {
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), Error> {
        let mut writer = BufWriter::new(writer);

        write_file_patch_header_to(self, &mut writer)?;

        for hunk in &self.hunks {
            hunk.write_to(interner, &mut writer)?;
        }

        Ok(())
    }
}

impl<'a> UnifiedPatchRejWriter for FilePatch<'a, LineId> {
    fn write_rej_to<W: Write>(&self, interner: &LineInterner, writer: &mut W, report: &FilePatchApplyReport) -> Result<(), Error> {
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
