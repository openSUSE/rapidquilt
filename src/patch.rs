// Licensed under the MIT license. See LICENSE.md

use std::borrow::Cow;
use std::vec::Vec;
use std::path::PathBuf;

use crate::line_interner::{LineId, LineInterner};
use crate::interned_file::InternedFile;


#[derive(Clone, Debug)]
pub struct HunkPart<Line> {
    pub content: Vec<Line>,

    /// Numbered from zero. Could be usize, but this makes calculating
    /// offsets easier.
    pub target_line: isize,
}

impl<Line> HunkPart<Line> where Line: Clone {
    fn clone_with_fuzz(&self, fuzz_before: usize, fuzz_after: usize) -> HunkPart<Line> {
        HunkPart {
            content: self.content[fuzz_before..(self.content.len() - fuzz_after)].to_vec(),
            target_line: self.target_line + fuzz_before as isize,
        }
    }
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
    pub remove: HunkPart<Line>,
    pub add: HunkPart<Line>,

    pub context_before: usize,
    pub context_after: usize,

    pub position: HunkPosition,

    // TODO: Better name?
    /// The string that follows the second "@@"
    pub place_name: &'a [u8],
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

            context_before: 0,
            context_after: 0,

            position: HunkPosition::Middle,

            place_name,
        }
    }

    pub fn max_useable_fuzz(&self) -> usize {
        std::cmp::max(self.context_before, self.context_after)
    }
}


impl<'a, Line> Hunk<'a, Line> where Line: Clone {
    // XXX: This function is relatively costly, but it shouldn't be needed too often
    pub fn clone_with_fuzz(&self, fuzz: usize) -> Hunk<'a, Line> {
        let fuzz_before = std::cmp::min(self.context_before, fuzz);
        let fuzz_after = std::cmp::min(self.context_after, fuzz);

        Hunk {
            remove: self.remove.clone_with_fuzz(fuzz_before, fuzz_after),
            add: self.add.clone_with_fuzz(fuzz_before, fuzz_after),

            context_before: self.context_before - fuzz_before,
            context_after: self.context_after - fuzz_after,

            position: self.position,

            place_name: self.place_name,
        }
    }
}

impl<'a> Hunk<'a, &'a [u8]> {
    pub fn intern(self, interner: &mut LineInterner<'a>) -> Hunk<'a, LineId> {
        Hunk {
            remove: self.remove.intern(interner),
            add: self.add.intern(interner),
            context_before: self.context_before,
            context_after: self.context_after,
            position: self.position,
            place_name: self.place_name,
        }
    }
}

impl<'a> Hunk<'a, LineId> {
    fn apply_modify(&self,
                    my_index: usize,
                    interned_file: &mut InternedFile,
                    direction: PatchDirection,
                    apply_mode: ApplyMode,
                    last_hunk_offset: isize)
                    -> HunkApplyReport
    {
        if interned_file.deleted {
            return HunkApplyReport::Failed;
        }

        let (part_add, part_remove) = match direction {
            PatchDirection::Forward => (&self.add, &self.remove),
            PatchDirection::Revert => (&self.remove, &self.add),
        };

        let mut target_line = match apply_mode {
            // In normal mode, pick what is in the hunk
            ApplyMode::Normal => match self.position {
                HunkPosition::Start |
                HunkPosition::Middle => part_add.target_line,
                HunkPosition::End => (interned_file.content.len() as isize - part_remove.content.len() as isize),
            },

            // In rollback mode, take it from the report
            ApplyMode::Rollback(report) => match report.hunk_reports()[my_index] {
                // If the hunk was applied at specific line, choose that line now.
                HunkApplyReport::Applied { line, .. } => line,

                // Nothing else should get here
                _ => unreachable!(),
            }
        };

//             println!("Hunk intended for line {} (add: {}, remove: {})", target_line, part_add.target_line, part_remove.target_line);

        // If the hunk tries to remove more than the file has, reject it now.
        // So in the following code we can assume that it is smaller or equal.
        if part_remove.content.len() > interned_file.content.len() {
            return HunkApplyReport::Failed;
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
                return HunkApplyReport::Failed;
            }

            // Only hunks that are intended for somewhere in the middle of the code
            // can be applied somewhere else based on context.
            if self.position != HunkPosition::Middle {
                return HunkApplyReport::Failed;
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
                let benchmark_target_line = target_line + last_hunk_offset;
                let mut best_target_line: Option<isize> = None;
                for possible_target_line in 0..=(interned_file.content.len() as isize - part_remove.content.len() as isize) {
                    if matches(&part_remove.content, &interned_file.content, possible_target_line) {
//                             println!("... found match at {}", possible_target_line);
                        if best_target_line.is_none() || (possible_target_line - benchmark_target_line).abs() < (best_target_line.unwrap() - benchmark_target_line).abs() {
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
                        return HunkApplyReport::Failed;
                    }
                }
            }
        }

        assert!(target_line >= 0);

        let range = (target_line as usize)..(target_line as usize + part_remove.content.len());

//             println!("Hunk applied on line {}", target_line);

        interned_file.content.splice(range.clone(), part_add.content.clone());

        return HunkApplyReport::Applied { line: target_line, offset: target_line - part_add.target_line, fuzz: 0 };

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
    Applied { line: isize, offset: isize, fuzz: usize },
    Failed,

    /// Used when rolling back and skipping hunks that previously failed
    Skipped,
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

    fn single_hunk_success(line: isize, offset: isize, fuzz: usize) -> Self {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::Applied { line, offset, fuzz }],
            any_failed: false,
        }
    }

    fn single_hunk_failure() -> Self {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::Failed],
            any_failed: true,
        }
    }

    fn push_hunk_report(&mut self, hunk_report: HunkApplyReport) {
        self.hunk_reports.push(hunk_report);
        if hunk_report == HunkApplyReport::Failed {
            self.any_failed = true;
        }
    }

    pub fn ok(&self) -> bool { !self.any_failed }
    pub fn failed(&self) -> bool { self.any_failed }
    pub fn hunk_reports(&self) -> &[HunkApplyReport] { &self.hunk_reports }
}

#[derive(Clone, Debug)]
pub struct FilePatch<'a, Line> {
    // TODO: Review if those can be safely public

    kind: FilePatchKind,

    filename: PathBuf,
    new_filename: Option<PathBuf>,

    pub hunks: Vec<Hunk<'a, Line>>,
}

impl<'a, Line> FilePatch<'a, Line> {
    pub fn new(kind: FilePatchKind, filename: PathBuf) -> Self {
        Self::new_internal(kind, filename, None)
    }

    pub fn new_renamed(kind: FilePatchKind, filename: PathBuf, new_filename: PathBuf) -> Self {
        Self::new_internal(kind, filename, Some(new_filename))
    }

    fn new_internal(kind: FilePatchKind, filename: PathBuf, new_filename: Option<PathBuf>) -> Self {
        Self {
            kind,

            filename,
            new_filename,

            hunks: Vec::new(),
        }
    }

    pub fn kind(&self) -> FilePatchKind { self.kind }

    pub fn change_kind(&mut self, kind: FilePatchKind) {
        self.kind = kind;
    }

    pub fn filename(&self) -> &PathBuf { &self.filename }
    pub fn new_filename(&self) -> Option<&PathBuf> { self.new_filename.as_ref() }

    #[allow(dead_code)]
    pub fn is_rename(&self) -> bool { self.new_filename.is_some() }
}

pub type TextFilePatch<'a> = FilePatch<'a, &'a [u8]>;
pub type InternedFilePatch<'a> = FilePatch<'a, LineId>;

impl<'a> TextFilePatch<'a> {
    pub fn intern(mut self, interner: &mut LineInterner<'a>) -> InternedFilePatch<'a> {
        FilePatch {
            kind: self.kind,

            filename: self.filename,
            new_filename: self.new_filename,

            hunks: self.hunks.drain(..).map(|hunk| hunk.intern(interner)).collect(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
enum ApplyMode<'a> {
    Normal,
    Rollback(&'a FilePatchApplyReport),
}

impl<'a> InternedFilePatch<'a> {
    pub fn apply(&self, interned_file: &mut InternedFile, direction: PatchDirection, fuzz: usize) -> FilePatchApplyReport {
        self.apply_internal(interned_file, direction, fuzz, ApplyMode::Normal)
    }

    pub fn rollback(&self, interned_file: &mut InternedFile, direction: PatchDirection, apply_report: &FilePatchApplyReport) {
        assert!(self.hunks.len() == apply_report.hunk_reports().len());

        let result = self.apply_internal(interned_file, direction.opposite(), 0, ApplyMode::Rollback(apply_report));
        assert!(result.ok()); // Rollback must apply cleanly. If not, we have a bug somewhere.
    }

    fn apply_internal(&self, interned_file: &mut InternedFile, direction: PatchDirection, fuzz: usize, apply_mode: ApplyMode) -> FilePatchApplyReport {
        match (self.kind, direction) {
            (FilePatchKind::Modify, _) =>
                self.apply_modify(interned_file, direction, fuzz, apply_mode),

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
            return FilePatchApplyReport::single_hunk_failure();
        }

        let new_content = match direction {
            PatchDirection::Forward => &self.hunks[0].add.content,
            PatchDirection::Revert => &self.hunks[0].remove.content,
        };

        interned_file.content = new_content.clone();
        interned_file.deleted = false;

        FilePatchApplyReport::single_hunk_success(0, 0, 0)
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
        interned_file.deleted = true;

        FilePatchApplyReport::single_hunk_success(0, 0, 0)
    }

    fn apply_modify(&self, interned_file: &mut InternedFile, direction: PatchDirection, fuzz: usize, apply_mode: ApplyMode) -> FilePatchApplyReport {
        let mut report = FilePatchApplyReport::new();

        let mut last_hunk_offset = 0isize;

        let mut for_each_hunk = |i, hunk: &Hunk<LineId>| {
            let mut hunk_report = HunkApplyReport::Skipped;

            let possible_fuzz_levels = match apply_mode {
                // In normal mode consider fuzz 0 up to given maximum fuzz or what is useable for this hunk
                ApplyMode::Normal =>
                    0..(std::cmp::min(fuzz, hunk.max_useable_fuzz()) + 1),

                // In rollback mode use what worked in normal mode
                ApplyMode::Rollback(ref report) => match report.hunk_reports[i] {
                    // If the hunk applied, pick the specific fuzz level
                    HunkApplyReport::Applied { fuzz, ..} =>
                        fuzz..(fuzz + 1),

                    // If the hunk failed to apply, skip it now.
                    HunkApplyReport::Failed |
                    HunkApplyReport::Skipped =>
                        0..0,
                }
            };

            for current_fuzz in possible_fuzz_levels {
                let hunk = match current_fuzz {
                    0 => Cow::Borrowed(hunk),
                    _ => Cow::Owned(hunk.clone_with_fuzz(current_fuzz)),
                };

                hunk_report = hunk.apply_modify(i, interned_file, direction, apply_mode, last_hunk_offset);

                if let HunkApplyReport::Applied { line, offset, .. } = hunk_report {
                    if current_fuzz > 0 {
                        println!("Patch ? applied with fuzz {}.", current_fuzz); // TODO: Proper warning!
                        hunk_report = HunkApplyReport::Applied { line, offset, fuzz: current_fuzz, };
                    }
                    break;
                }
            }

            if let HunkApplyReport::Applied { offset, .. } = hunk_report {
                last_hunk_offset = offset;
            }

            report.push_hunk_report(hunk_report);
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
