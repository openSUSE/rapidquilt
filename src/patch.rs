use std::io::Write;
use std::hash::{Hash, Hasher};
use std::vec::Vec;
use std::path::PathBuf;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::str;

use failure::Error;
use seahash::SeaHasher;
use regex::bytes::Regex;

use crate::line_interner::{LineId, LineInterner, EMPTY_LINE_ID, EMPTY_LINE_SLICE};
use crate::interned_file::InternedFile;


const NO_NEW_LINE_TAG: &[u8] = b"\\ No newline at end of file";
const NULL_FILENAME: &[u8] = b"/dev/null";


#[derive(Clone, Debug)]
struct HunkPart<Line> {
    content: Vec<Line>,

    /// Numbered from zero. Could be usize, but this makes calculating
    /// offsets easier.
    target_line: isize,
}

impl<'a> HunkPart<&'a [u8]> {
    pub fn intern(mut self, interner: &mut LineInterner<'a>) -> HunkPart<LineId> {
        HunkPart {
            content: self.content.drain(..).map(|line| interner.add(line)).collect(),

            target_line: self.target_line,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HunkPosition {
    Start,
    End,
    Middle,
}

#[derive(Clone, Debug)]
pub struct Hunk<'a, Line> {
    remove: HunkPart<Line>,
    add: HunkPart<Line>,

    position: HunkPosition,

    // TODO: Better name?
    /// The string that follows the second "@@"
    place_name: &'a [u8],
}

impl<'a, Line> Hunk<'a, Line> {
    pub fn new(remove_line: isize, add_line: isize, place_name: &'a [u8]) -> Self {
        Hunk {
            remove: HunkPart {
                content: Vec::new(),
                target_line: remove_line,
            },

            add: HunkPart {
                content: Vec::new(),
                target_line: add_line,
            },

            position: HunkPosition::Middle,

            place_name,
        }
    }
}

impl<'a> Hunk<'a, &'a [u8]> {
    pub fn intern(self, interner: &mut LineInterner<'a>) -> Hunk<'a, LineId> {
        Hunk {
            remove: self.remove.intern(interner),
            add: self.add.intern(interner),
            position: self.position,
            place_name: self.place_name,
        }
    }
}

impl<'a> Hunk<'a, LineId> {
    pub fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W, filepatch_kind: FilePatchKind) -> Result<(), Error> {
        // If you think this looks more complicated than it should be, it is because it must correctly print out "No newline at the end of file" lines

        let hunk_goes_to_end = (self.position == HunkPosition::End || filepatch_kind != FilePatchKind::Modify);

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

        let add_line = if filepatch_kind == FilePatchKind::Delete {
            0
        } else {
            self.add.target_line + 1
        };

        let remove_line = if filepatch_kind == FilePatchKind::Create {
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FilePatchKind {
    Modify,
    Create,
    Delete,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PatchDirection {
    Forward,
    Revert
}

impl PatchDirection {
    pub fn opposite(self) -> PatchDirection {
        match self {
            PatchDirection::Forward => PatchDirection::Revert,
            PatchDirection::Revert => PatchDirection::Forward,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HunkApplyReport {
    AppliedAtLine(isize),
    Failed,
}

#[derive(Debug)]
pub struct FilePatchApplyReport {
    any_failed: bool,
    hunk_reports: Vec<HunkApplyReport>,
}

impl FilePatchApplyReport {
    fn new() -> Self {
        FilePatchApplyReport {
            hunk_reports: Vec::new(),
            any_failed: false,
        }
    }

    fn single_hunk_success(line: isize) -> Self {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::AppliedAtLine(line)],
            any_failed: false,
        }
    }

    fn single_hunk_failure() -> Self {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::Failed],
            any_failed: true,
        }
    }

    fn push_hunk_success(&mut self, line: isize) {
        self.hunk_reports.push(HunkApplyReport::AppliedAtLine(line));
    }

    fn push_hunk_failure(&mut self) {
        self.hunk_reports.push(HunkApplyReport::Failed);
        self.any_failed = true;
    }

    pub fn ok(&self) -> bool { !self.any_failed }
    pub fn failed(&self) -> bool { self.any_failed }
    pub fn hunk_reports(&self) -> &[HunkApplyReport] { &self.hunk_reports }
}

#[derive(Debug)]
pub struct FilePatch<'a, Line> {
    // TODO: Review if those can be safely public

    pub kind: FilePatchKind,

    pub filename: PathBuf,
    pub filename_hash: u64,

    pub hunks: Vec<Hunk<'a, Line>>,
}

impl<'a, Line> FilePatch<'a, Line> {
    fn new(kind: FilePatchKind, filename: PathBuf) -> Self {
        let mut hasher = SeaHasher::default();
        filename.hash(&mut hasher);
        let filename_hash = hasher.finish();

        Self {
            kind,

            filename,
            filename_hash,

            hunks: Vec::new(),
        }
    }
}

pub type TextFilePatch<'a> = FilePatch<'a, &'a [u8]>;
pub type InternedFilePatch<'a> = FilePatch<'a, LineId>;

impl<'a> TextFilePatch<'a> {
    pub fn intern(mut self, interner: &mut LineInterner<'a>) -> InternedFilePatch<'a> {
        FilePatch {
            kind: self.kind,

            filename: self.filename,
            filename_hash: self.filename_hash,

            hunks: self.hunks.drain(..).map(|hunk| hunk.intern(interner)).collect(),
        }
    }
}

impl<'a> InternedFilePatch<'a> {
    fn write_header_to<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        // TODO: Currently we are writing patches with `strip` level 0, which is exactly
        //       what we need for .rej files. But we could add option to configure it?

        if self.kind == FilePatchKind::Create {
            writer.write(b"--- ")?;
            writer.write(&NULL_FILENAME)?;
            writer.write(b"\n")?;
        } else {
            writeln!(writer, "--- {}", self.filename.display())?;
        }

        if self.kind == FilePatchKind::Delete {
            writer.write(b"+++ ")?;
            writer.write(&NULL_FILENAME)?;
            writer.write(b"\n")?;
        } else {
            writeln!(writer, "+++ {}", self.filename.display())?;
        }

        Ok(())
    }

    pub fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), Error> {
        self.write_header_to(writer)?;

        for hunk in &self.hunks {
            hunk.write_to(interner, writer, self.kind)?;
        }

        Ok(())
    }

    pub fn write_rej_to<W: Write>(&self, interner: &LineInterner, writer: &mut W, report: &FilePatchApplyReport) -> Result<(), Error> {
        if !report.any_failed {
            return Ok(())
        }

        self.write_header_to(writer)?;

        for (hunk, report) in self.hunks.iter().zip(&report.hunk_reports) {
            if let HunkApplyReport::Failed = report {
                hunk.write_to(interner, writer, self.kind)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
enum ApplyMode<'a> {
    Normal,
    Rollback(&'a FilePatchApplyReport),
}

impl<'a> InternedFilePatch<'a> {
    pub fn apply(&self, interned_file: &mut InternedFile, direction: PatchDirection) -> FilePatchApplyReport {
        self.apply_internal(interned_file, direction, ApplyMode::Normal)
    }

    pub fn rollback(&self, interned_file: &mut InternedFile, direction: PatchDirection, apply_report: &FilePatchApplyReport) {
        assert!(self.hunks.len() == apply_report.hunk_reports().len());

        let result = self.apply_internal(interned_file, direction.opposite(), ApplyMode::Rollback(apply_report));
        assert!(result.ok()); // Rollback must apply cleanly. If not, we have a bug somewhere.
    }

    fn apply_internal(&self, interned_file: &mut InternedFile, direction: PatchDirection, apply_mode: ApplyMode) -> FilePatchApplyReport {
        match (self.kind, direction) {
            (FilePatchKind::Modify, _) =>
                self.apply_modify(interned_file, direction, apply_mode),

            (FilePatchKind::Create, PatchDirection::Forward) |
            (FilePatchKind::Delete, PatchDirection::Revert) =>
                self.apply_create(interned_file, direction),

            (FilePatchKind::Delete, PatchDirection::Forward) |
            (FilePatchKind::Create, PatchDirection::Revert) =>
                self.apply_delete(interned_file, direction),
        }
    }

    fn apply_create(&self, interned_file: &mut InternedFile, direction: PatchDirection) -> FilePatchApplyReport {
        assert!(self.hunks.len() == 1);

        if interned_file.content.len() > 0 {
            // It may be single new line, we must tolerate that
            if interned_file.content.len() > 1 || interned_file.content[0] != EMPTY_LINE_ID {
                return FilePatchApplyReport::single_hunk_failure();
            }
        }

        let new_content = match direction {
            PatchDirection::Forward => &self.hunks[0].add.content,
            PatchDirection::Revert => &self.hunks[0].remove.content,
        };

        interned_file.content = new_content.clone();

        FilePatchApplyReport::single_hunk_success(0)
    }

    fn apply_delete(&self, interned_file: &mut InternedFile, direction: PatchDirection) -> FilePatchApplyReport {
        assert!(self.hunks.len() == 1);

        let expected_content = match direction {
            PatchDirection::Forward => &self.hunks[0].remove.content,
            PatchDirection::Revert => &self.hunks[0].add.content,
        };

        if *expected_content != interned_file.content {
            return FilePatchApplyReport::single_hunk_failure();
        }

        interned_file.content.clear();

        FilePatchApplyReport::single_hunk_success(0)
    }

    fn apply_modify(&self, interned_file: &mut InternedFile, direction: PatchDirection, apply_mode: ApplyMode) -> FilePatchApplyReport {
        let mut report = FilePatchApplyReport::new();

        let mut last_hunk_offset = 0isize;

        let mut for_each_hunk = |i, hunk: &Hunk<LineId>| {
            let (part_add, part_remove) = match direction {
                PatchDirection::Forward => (&hunk.add, &hunk.remove),
                PatchDirection::Revert => (&hunk.remove, &hunk.add),
            };

            let mut target_line = match apply_mode {
                // In normal mode, pick what is in the hunk
                ApplyMode::Normal => match hunk.position {
                    HunkPosition::Start |
                    HunkPosition::Middle => part_add.target_line,
                    HunkPosition::End => (interned_file.content.len() as isize - part_remove.content.len() as isize),
                },

                // In rollback mode, take it from the report
                ApplyMode::Rollback(report) => match report.hunk_reports()[i] {
                    // If the hunk was applied at specific line, choose that line now.
                    HunkApplyReport::AppliedAtLine(line) => line,

                    // If the hunk failed to apply, skip it now.
                    HunkApplyReport::Failed => return,
                }
            };

//             println!("Hunk intended for line {} (add: {}, remove: {})", target_line, part_add.target_line, part_remove.target_line);

            // If the hunk tries to remove more than the file has, reject it now.
            // So in the following code we can assume that it is smaller or equal.
            if part_remove.content.len() > interned_file.content.len() {
                report.push_hunk_failure();
                return;
            }

            fn matches(needle: &[LineId], haystack: &[LineId], at: isize) -> bool {
                assert!(at >= 0);
                let at = at as usize;
                if needle.len() + at > haystack.len() {
                    return false;
                }

//                 println!("{:?} == {:?} ?", &haystack[at..(at + needle.len())], needle);

                &haystack[at..(at + needle.len())] == needle
            }

            // Check if it matches on the originally intended target_line
            if !matches(&part_remove.content, &interned_file.content, target_line) {
                // If it failed to apply in rollback mode, do not try to search for better place.
                if let ApplyMode::Rollback(_) = apply_mode {
                    report.push_hunk_failure();
                    return;
                }

                // Only hunks that are intended for somewhere in the middle of the code
                // can be applied somewhere else based on context.
                if hunk.position != HunkPosition::Middle {
                    report.push_hunk_failure();
                    return;
                }

//                 if last_hunk_offset != 0 {
//                     println!("... did not match! Will test offset of previous: {} + {} = {}!", target_line, last_hunk_offset, target_line + last_hunk_offset);
//                 }

                // man patch: "With  context  diffs, and to a lesser extent with normal diffs, patch can detect
                //             when the line numbers mentioned in the patch are incorrect, and attempts to find
                //             the correct place to apply each hunk of the patch.  As a first guess, it takes the
                //             line number mentioned for the hunk, plus or minus any offset used in applying the
                //             previous hunk.."
                if last_hunk_offset != 0 && target_line + last_hunk_offset >= 0 &&
                   matches(&part_remove.content, &interned_file.content, target_line + last_hunk_offset) {
//                     println!("... matched!");
                    target_line = target_line + last_hunk_offset;
                } else {
//                     println!("... did not match! Will search for place closest to {}", part_add.target_line);

                    // man patch: "If that is not the correct place, patch scans both forwards and backwards for a
                    //             set of lines matching the context given in the hunk."

                    // XXX: This needs to be done better! More optimized!
                    let mut best_target_line: Option<isize> = None;
                    for possible_target_line in 0..=(interned_file.content.len() as isize - part_remove.content.len() as isize) {
                        if matches(&part_remove.content, &interned_file.content, possible_target_line) {
//                             println!("... found match at {}", possible_target_line);
                            if best_target_line.is_none() || (possible_target_line - target_line).abs() < (best_target_line.unwrap() - target_line).abs() {
                                best_target_line = Some(possible_target_line);
                            }
                        }
                    }

                    match best_target_line {
                        Some(new_target_line) => {
//                             println!("... best match is {}", new_target_line);
                            target_line = new_target_line;
                        },
                        None => {
                            report.push_hunk_failure();
                            return;
                        }
                    }
                }
            }

            assert!(target_line >= 0);
            last_hunk_offset = target_line - part_add.target_line;
            let range = (target_line as usize)..(target_line as usize + part_remove.content.len());

            report.push_hunk_success(target_line);

//             println!("Hunk applied on line {}", target_line);

            interned_file.content.splice(range.clone(), part_add.content.clone());
        };

        // TODO: Nicer way to conditionally iterate forwards or backwards?
        match direction {
            PatchDirection::Forward =>
                for (i, hunk) in self.hunks.iter().enumerate() {
                    for_each_hunk(i, hunk);
                }
            PatchDirection::Revert =>
                for (i, hunk) in self.hunks.iter().enumerate().rev() {
                    for_each_hunk(i, hunk);
                }
        };

        report
    }
}

// #[derive(Debug)]
// pub struct Patch<'a> {
//     pub files: Vec<TextFilePatch<'a>>
// }
//
// impl<'a> Patch<'a> {
//     fn new() -> Self {
//         Patch {
//             files: Vec::new(),
//         }
//     }

    pub fn parse_unified<'a>(bytes: &'a [u8], strip: usize) -> Result<Vec<TextFilePatch<'a>>, Error> {
        let mut file_patches = Vec::new();

        let mut lines = bytes.split(|c| *c == b'\n').peekable();

        lazy_static! {
            static ref MINUS_FILENAME: Regex = Regex::new(r"^--- ([^\t]+)").unwrap();
            static ref PLUS_FILENAME: Regex = Regex::new(r"^\+\+\+ ([^\t]+)").unwrap();
            static ref CHUNK: Regex = Regex::new(r"^@@ -(?P<remove_line>[\d]+)(?:,(?P<remove_count>[\d]+))? \+(?P<add_line>[\d]+)(?:,(?P<add_count>[\d]+))? @@(?P<place_name>.*)").unwrap();
        }

        while let Some(line) = lines.next() {
            let minus_filename = match MINUS_FILENAME.captures(line) {
                Some(capture) => capture.get(1).unwrap().as_bytes(),
                None => continue // It was garbage, go for next line
            };

            let plus_filename = match lines.next().and_then(|line| PLUS_FILENAME.captures(line)) {
                Some(capture) => capture.get(1).unwrap().as_bytes(),
                None => return Err(format_err!("--- not followed by +++!")) // TODO: Better handling.
            };

            let (kind, filename) = if minus_filename == NULL_FILENAME {
                (FilePatchKind::Create, plus_filename)
            } else if plus_filename == NULL_FILENAME {
                (FilePatchKind::Delete, minus_filename)
            } else {
                // TODO: What to do if plus_filename and minus_filename differ after stripping the beginning?

                (FilePatchKind::Modify, plus_filename)
            };

            let filename = PathBuf::from(OsStr::from_bytes(filename));
            if !filename.is_relative() {
                return Err(format_err!("Path in patch is not relative: \"{:?}\"", filename));
            }
            let filename = {
                let mut components = filename.components();
                for _ in 0..strip { components.next(); }
                components.as_path().to_path_buf()
            };

            let mut filepatch = FilePatch::new(kind, filename);

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

                // Convert lines to zero-based numbering. But don't do that if we are creating/deleting (in that case it is 0 and would underflow)
                if kind == FilePatchKind::Create {
                    remove_count = 0;
                } else {
                    remove_line -= 1;
                }
                if kind == FilePatchKind::Delete {
                    add_count = 0;
                } else {
                    add_line -= 1;
                }
                let mut hunk = Hunk::new(remove_line, add_line, place_name);
                hunk.add.content.reserve(add_count as usize);
                hunk.remove.content.reserve(remove_count as usize);

                // Counters for amount of context
                let mut context_prefix = 0;
                let mut context_suffix = 0;
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

                    let line_content = &line[1..];

                    match line[0] {
                        b' ' => {
                            hunk.remove.content.push(line_content);
                            hunk.add.content.push(line_content);
                            remove_count -= 1;
                            add_count -= 1;

                            if !there_was_a_non_context_line {
                                context_prefix += 1;
                            } else {
                                context_suffix += 1;
                            }

                            if minus_newline_at_end || plus_newline_at_end {
                                return Err(format_err!("Badly formated patch!"));
                            }
                        }
                        b'-' => {
                            hunk.remove.content.push(line_content);
                            remove_count -= 1;

                            there_was_a_non_context_line = true;
                            context_suffix = 0;

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
                            context_suffix = 0;

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
                if context_prefix < context_suffix && add_line == 0 {
                    hunk.position = HunkPosition::Start;
                } else if context_prefix > context_suffix {
                    hunk.position = HunkPosition::End;
                }

                if context_suffix == 0 || context_suffix < context_prefix {
                    // If we are applying the end, add the implicit empty new line, unless there was the "No newline" tag.
                    if !plus_newline_at_end && kind != FilePatchKind::Delete {
                        hunk.add.content.push(&EMPTY_LINE_SLICE);
                    }
                    if !minus_newline_at_end && kind != FilePatchKind::Create {
                        hunk.remove.content.push(&EMPTY_LINE_SLICE);
                    }
                }

                filepatch.hunks.push(hunk);
            }

            file_patches.push(filepatch);
        }

        Ok(file_patches)
    }
// }
