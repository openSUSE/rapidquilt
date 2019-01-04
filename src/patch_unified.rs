// Licensed under the MIT license. See LICENSE.md

use std::io::{self, BufWriter, Write};
use std::vec::Vec;
use std::path::PathBuf;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::str;

use regex::bytes::{Regex, RegexSet};

use crate::line_interner::{LineId, LineInterner};
use crate::patch::*;
use crate::util::split_lines_with_endings;


const NO_NEW_LINE_TAG: &[u8] = b"\\ No newline at end of file\n";
const NULL_FILENAME: &[u8] = b"/dev/null";

lazy_static! {
    static ref MINUS_FILENAME: Regex = Regex::new(r"^--- ([^\t]+)\n$").unwrap();
    static ref PLUS_FILENAME: Regex = Regex::new(r"^\+\+\+ ([^\t]+)\n$").unwrap();

    // Warning: It seems that patch accepts if the second '@' in the second "@@" group is missing!
    static ref CHUNK: Regex = Regex::new(r"^@@ -(?P<remove_line>[\d]+)(?:,(?P<remove_count>[\d]+))? \+(?P<add_line>[\d]+)(?:,(?P<add_count>[\d]+))? @@?(?P<place_name>.*)\n$").unwrap();

    static ref DIFF_GIT: Regex = Regex::new(r"^diff --git +(?P<oldfilename>[^ ]+) +(?P<newfilename>[^ ]+)\n$").unwrap();

    // Same order as MatchedMetadata enum
    static ref METADATA: RegexSet = RegexSet::new(&[
        r"^git --diff ", // this is exactly what patch uses to recognize end of hunk-less filepatch
        r"^index", // TODO: ?
        r"^old mode +(?P<permissions>[0-9]+)\n$",
        r"^new mode +(?P<permissions>[0-9]+)\n$",
        r"^deleted file mode +(?P<permissions>[0-9]+)\n$",
        r"^new file mode +(?P<permissions>[0-9]+)\n$",
        r"^rename from ",  // patch ignores the filename behind this
        r"^rename to ",    // patch ignores the filename behind this
        r"^copy from ",    // patch ignores the filename behind this
        r"^copy to ",      // patch ignores the filename behind this
        r"^GIT binary patch", // TODO: ???
    ]).unwrap();
}

// Same order as METADATA RegexSet!
#[repr(usize)]
#[allow(unused)]
enum MatchedMetadata {
    GitDiffSeparator = 0,
    Index,
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

#[derive(Debug, Fail, PartialEq)]
pub enum ParseError {
    #[fail(display = "Path in patch is not relative: {:?}", path)]
    AbsolutePathInPatch { path: PathBuf },

    #[fail(display = "Unsupported metadata: \"{}\"", line)]
    UnsupportedMetadata { line: String },

    #[fail(display = "Could not figure out the filename for hunk \"{}\"", hunk_line)]
    MissingFilenameForHunk { hunk_line: String },

    #[fail(display = "Unexpected end of file")]
    UnexpectedEndOfFile,

    #[fail(display = "Unexpected line in the middle of hunk: \"{}\"", line)]
    BadLineInHunk { line: String },
}

fn debug_line_to_string(line: &[u8]) -> String {
    String::from_utf8_lossy(line).replace('\n', "")
}

struct FilePatchMetadata<'a> {
    old_filename: Option<&'a [u8]>,
    new_filename: Option<&'a [u8]>,
    rename_from: bool,
    rename_to: bool,
}

impl<'a> Default for FilePatchMetadata<'a> {
    fn default() -> Self {
        FilePatchMetadata {
            old_filename: None,
            new_filename: None,
            rename_from: false,
            rename_to: false,
        }
    }
}

fn new_filepatch<'a>(filepatch_metadata: &FilePatchMetadata, strip: usize) -> Result<Option<TextFilePatch<'a>>, ParseError> {
    if let (Some(old_filename), Some(new_filename)) = (filepatch_metadata.old_filename, filepatch_metadata.new_filename) {
        let (kind, filename, other_filename) = if old_filename == NULL_FILENAME {
            (FilePatchKind::Create, new_filename, None)
        } else if new_filename == NULL_FILENAME {
            (FilePatchKind::Delete, old_filename, None)
        } else {
            // TODO: What to do if new_filename and old_filename differ after stripping the beginning?

            (FilePatchKind::Modify, new_filename, Some(old_filename))
        };

        fn strip_filename(filename: &[u8], strip: usize) -> Result<PathBuf, ParseError> {
            let filename = PathBuf::from(OsStr::from_bytes(filename));
            if !filename.is_relative() {
                return Err(ParseError::AbsolutePathInPatch { path: filename });
            }

            let mut components = filename.components();
            for _ in 0..strip { components.next(); }
            Ok(components.as_path().to_path_buf())
        }

        let filename = strip_filename(filename, strip)?;

        if filepatch_metadata.rename_from && filepatch_metadata.rename_to && other_filename.is_some() {
            let other_filename = strip_filename(other_filename.unwrap(), strip)?;
            Ok(Some(FilePatch::new_renamed(kind, other_filename, filename)))
        } else {
            Ok(Some(FilePatch::new(kind, filename)))
        }
    } else {
        Ok(None)
    }
}

pub fn parse_unified<'a>(bytes: &'a [u8], strip: usize) -> Result<Vec<TextFilePatch<'a>>, ParseError> {
    let mut file_patches = Vec::new();

    let mut lines = split_lines_with_endings(bytes).peekable();

    let mut filepatch_metadata = FilePatchMetadata::default();

    while let Some(line) = lines.peek() {
        if let Some(metadata) = METADATA.matches(line).iter().next() { // There will be at most one match because the METADATA regexes are mutually exclusive
            // TODO: Use TryFrom instead of transmute when stable.
            match unsafe { std::mem::transmute::<usize, MatchedMetadata>(metadata) } {
                MatchedMetadata::RenameFrom => {
                    // We do not actually care about the filename written next to the "rename from" line.
                    // patch doesn't care either
                    filepatch_metadata.rename_from = true;
                }
                MatchedMetadata::RenameTo => {
                    // We do not actually care about the filename written next to the "rename to" line.
                    // patch doesn't care either
                    filepatch_metadata.rename_to = true;
                }
                MatchedMetadata::GitBinaryPatch => {
                    // These metadata are not (yet) supported and ignoring them would be bad
                    return Err(ParseError::UnsupportedMetadata { line: debug_line_to_string(line) });
                }
                _ => {
                    // TODO: Handle the other metadata... For now they can be ignored.
                }
            }
            lines.next();
            continue;
        }

        if let Some(capture) = MINUS_FILENAME.captures(line) {
            filepatch_metadata.old_filename = Some(capture.get(1).unwrap().as_bytes());
            lines.next();
            continue;
        }

        if let Some(capture) = PLUS_FILENAME.captures(line) {
            filepatch_metadata.new_filename = Some(capture.get(1).unwrap().as_bytes());
            lines.next();
            continue;
        }

        if let Some(capture) = DIFF_GIT.captures(line) {
            // patch uses "diff --git " as a separator that can mean a filepatch ended even if it had no hunks
            {
                if let Some(file_patch) = new_filepatch(&filepatch_metadata, strip)? {
                    file_patches.push(file_patch);
                }
                filepatch_metadata = FilePatchMetadata::default();
            }

            filepatch_metadata.old_filename = Some(capture.name("oldfilename").unwrap().as_bytes());
            filepatch_metadata.new_filename = Some(capture.name("newfilename").unwrap().as_bytes());

            lines.next();
            continue;
        }

        if !CHUNK.is_match(line) {
            lines.next();
            continue;
        }

        let mut file_patch = match new_filepatch(&filepatch_metadata, strip)? {
            Some(file_patch) => file_patch,
            None => {
                return Err(ParseError::MissingFilenameForHunk { hunk_line: debug_line_to_string(line) });
            }
        };
        filepatch_metadata = FilePatchMetadata::default();

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
                file_patch.change_kind(FilePatchKind::Create);
            } else if add_line == 0 {
                file_patch.change_kind(FilePatchKind::Delete);
            }

            // Convert lines to zero-based numbering. But don't do that if we are creating/deleting (in that case it is 0 and would underflow)
            if file_patch.kind() == FilePatchKind::Create {
                remove_count = 0;
            } else {
                remove_line -= 1;
            }
            if file_patch.kind() == FilePatchKind::Delete {
                add_count = 0;
            } else {
                add_line -= 1;
            }
            let mut hunk = Hunk::new(remove_line, add_line, place_name);
            hunk.add.content.reserve(add_count as usize);
            hunk.remove.content.reserve(remove_count as usize);

            // Counters for amount of context
            let mut there_was_a_non_context_line = false;

            // Read hunk lines
            while remove_count > 0 || add_count > 0 {
                let line = match lines.next() {
                    Some(line) => line,
                    None => {
                        return Err(ParseError::UnexpectedEndOfFile);
                    }
                };

                // XXX: It seems that patches may have empty lines representing
                //      empty line of context. So if we see that, lets replace it
                //      what should have been there - a single space.
                let line = if line == b"\n" {
                    b" \n"
                } else {
                    line
                };

                let mut line_content = &line[1..];

                // Check for the "No newline..." tag
                if lines.peek() == Some(&NO_NEW_LINE_TAG) && line_content.last() == Some(&b'\n') {
                    // Cut away the '\n' from the end of the line. It does not belong to the content,
                    // it is just there for patch formating.
                    line_content = &line_content[..(line_content.len()-1)];

                    // Skip the line with the tag
                    lines.next();
                }

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
                    }
                    b'-' => {
                        hunk.remove.content.push(line_content);
                        remove_count -= 1;

                        there_was_a_non_context_line = true;
                        hunk.context_after = 0;
                    }
                    b'+' => {
                        hunk.add.content.push(line_content);
                        add_count -= 1;

                        there_was_a_non_context_line = true;
                        hunk.context_after = 0;
                    }
                    _ => {
                        return Err(ParseError::BadLineInHunk { line: debug_line_to_string(line) });
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

            file_patch.hunks.push(hunk);
        }

        file_patches.push(file_patch);
    }

    Ok(file_patches)
}

pub trait UnifiedPatchWriter {
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error>;
}

pub trait UnifiedPatchRejWriter {
    fn write_rej_to<W: Write>(&self, interner: &LineInterner, writer: &mut W, report: &FilePatchApplyReport) -> Result<(), io::Error>;
}

impl<'a> UnifiedPatchWriter for Hunk<'a, LineId> {
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error> {
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

        let mut write_line = |c: u8, line_id: LineId| -> Result<(), io::Error> {
            let line = interner.get(line_id).unwrap(); // NOTE(unwrap): Must succeed, we are printing patch that was already interned. If it is not there, it is a bug.

            writer.write(&[c])?;
            writer.write(line)?;
            if line.last() != Some(&b'\n') {
                // If the line doesn't end with newline character, we have to write it ourselves
                // (otherwise it would not be valid patch file), but we also print the "No newline..."
                // tag which informs that the newline is not part of the file.
                writer.write(b"\n")?;
                writer.write(NO_NEW_LINE_TAG)?;
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
