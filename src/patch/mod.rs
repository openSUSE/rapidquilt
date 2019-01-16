// Licensed under the MIT license. See LICENSE.md

//! This module defines the structures representing a patch and algorithms for
//! applying them on `InternedFile`s.
//!
//! The hierarchy is:
//! Top: `Vec<FilePatch>`     ... a single "blabla.patch" file
//!   Has many: `FilePatch`   ... a part of patch that changes single file
//!     Has many: `Hunk`      ... a single hunk
//!       Has two: `HunkPart` ... one for content to be added, one to be removed
//!         Has many: `Line`  ... a line
//!
//! All structures are generic over the representation of line. Currently used
//! ones are:
//!
//! * `Line = &[u8]`: The line is a slice of some external buffer. This is how
//!                   patches come from parser.
//!                   Type alliases `TextFilePatch` and `TextHunk` can be used
//!                   as shortcut.
//!
//! * `Line = LineId`: The line is a unique 32-bit ID. This is how patches look
//!                    after interning.
//!                    Type alliases `InternedFilePatch` and `InternedHunk` can
//!                    be used as shortcut.
//!
//! Other line representations would be possible, for example one where
//! `Line = String` for a patch that owns its data.
//!
//! Hunks are not represented using remove-lines, add-lines and context-lines,
//! but only using remove-lines and add-lines. Every context-line is used as
//! remove-line and add-line.


use std::borrow::Cow;
use std::fs;
use std::vec::Vec;
use std::path::{Path, PathBuf};

use derive_builder::Builder;
use smallvec::SmallVec;

use crate::line_interner::{LineId, LineInterner};
use crate::interned_file::InternedFile;
use crate::util::Searcher;

pub mod unified;


type ContentVec<Line> = SmallVec<[Line; 13]>; // Optimal size found empirically on SUSE's kernel patches. It may change in future.

/// This is part of hunk representing the lines to be added or removed together
/// with the target line.
#[derive(Clone, Debug)]
pub struct HunkPart<Line> {
    pub content: ContentVec<Line>,

    /// Numbered from zero. Could be usize, but this makes calculating
    /// offsets easier.
    pub target_line: isize,
}

impl<Line> HunkPart<Line> where Line: Copy {
    /// Create a copy of the hunk part with given fuzz, i.e. cutting away
    /// context lines from start and end.
    fn clone_with_fuzz(&self, fuzz_before: usize, fuzz_after: usize) -> HunkPart<Line> {
        HunkPart {
            content: SmallVec::from_slice(&self.content[fuzz_before..(self.content.len() - fuzz_after)]),
            target_line: self.target_line + fuzz_before as isize,
        }
    }
}

impl<'a> HunkPart<&'a [u8]> {
    /// Consumes this text-based HunkPart and produces interned HunkPart.
    pub fn intern(mut self, interner: &mut LineInterner<'a>) -> HunkPart<LineId> {
        HunkPart {
            content: self.content.drain().map(|line| interner.add(line)).collect(),

            target_line: self.target_line,
        }
    }
}

/// Represents the expected relative placement of the hunk.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HunkPosition {
    /// The hunk must be placed at the start of the file.
    Start,

    /// The hunk must be placed at the end of the file.
    End,

    /// The hunk can be placed anywhere in the file based on the target line.
    Middle,
}

/// Represents single hunk from a patch
#[derive(Clone, Debug)]
pub struct Hunk<'a, Line> {
    /// Content to be removed from the file (including context)
    pub remove: HunkPart<Line>,
    /// Content to be added to the file (including context)
    pub add: HunkPart<Line>,

    /// How many lines at start of both `remove` and `add` are actually context
    /// lines. (Useful for fuzzy patching.)
    pub context_before: usize,
    /// How many lines at the end of both `remove` and `add` are actually context
    /// lines. (Useful for fuzzy patching.)
    pub context_after: usize,

    /// Expected placement of this hunk
    pub position: HunkPosition,

    /// The string that follows the second "@@"
    /// Not necessarily a name of a function, but that's how it is called in diff.
    pub function: &'a [u8],
}

impl<'a, Line> Hunk<'a, Line> {
    /// Create new hunk for given parameters.
    pub fn new(remove_line: isize, add_line: isize, function: &'a [u8]) -> Self {
        Hunk {
            remove: HunkPart {
                content: ContentVec::new(),
                target_line: remove_line,
            },

            add: HunkPart {
                content: ContentVec::new(),
                target_line: add_line,
            },

            context_before: 0,
            context_after: 0,

            position: HunkPosition::Middle,

            function,
        }
    }

    /// Return the maximum fuzz that can be applied to this hunk. Applying more
    /// has no effect because there would be no more context lines to ignore.
    pub fn max_useable_fuzz(&self) -> usize {
        std::cmp::max(self.context_before, self.context_after)
    }
}


impl<'a, Line> Hunk<'a, Line> where Line: Copy {
    /// Create a copy of the hunk part with given fuzz, i.e. cutting away
    /// context lines from start and end.
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

            function: self.function,
        }
    }
}

pub type TextHunk<'a> = Hunk<'a, &'a [u8]>;
pub type InternedHunk<'a> = Hunk<'a, LineId>;

impl<'a> TextHunk<'a> {
    /// Consumes this text-based Hunk and produces interned Hunk.
    pub fn intern(self, interner: &mut LineInterner<'a>) -> InternedHunk<'a> {
        Hunk {
            remove: self.remove.intern(interner),
            add: self.add.intern(interner),
            context_before: self.context_before,
            context_after: self.context_after,
            position: self.position,
            function: self.function,
        }
    }
}

impl<'a> InternedHunk<'a> {
    /// Applies this `InternedHunk` onto the `InternedFile`.
    ///
    /// `my_index`: the index of this hunk in the `FilePatch`
    ///
    /// `interned_file`: the changes are done to this file
    ///
    /// `direction`: whether the patch is being applied forward (normally) or reverted
    ///
    /// `apply_mode`: whether the patch is being applied or rolled-back . This is different from `direction`. See documentation of `ApplyMode`.
    ///
    /// `last_hunk_offset`: the offset on which the previous hunk applied
    fn apply_modify(&self,
                    my_index: usize,
                    interned_file: &mut InternedFile,
                    direction: PatchDirection,
                    apply_mode: ApplyMode,
                    last_hunk_offset: isize)
                    -> HunkApplyReport
    {
        // If the file doesn't exist, fail immediatelly
        if interned_file.deleted {
            return HunkApplyReport::Failed;
        }

        // Decide which part of the hunk should be added and which should be
        // deleted depending on the direction of applying.
        let (part_add, part_remove) = match direction {
            PatchDirection::Forward => (&self.add, &self.remove),
            PatchDirection::Revert => (&self.remove, &self.add),
        };

        // Determine the target line.
        let mut target_line = match apply_mode {
            // In normal mode, pick what is in the hunk
            ApplyMode::Normal => match self.position {
                HunkPosition::Start => part_add.target_line,

                // man patch: "With  context  diffs, and to a lesser extent with normal diffs, patch can detect
                //             when the line numbers mentioned in the patch are incorrect, and attempts to find
                //             the correct place to apply each hunk of the patch.  As a first guess, it takes the
                //             line number mentioned for the hunk, plus or minus any offset used in applying the
                //             previous hunk.."
                HunkPosition::Middle => part_add.target_line + last_hunk_offset,

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

        // If the hunk tries to remove more than the file has, reject it now.
        // So in the following code we can assume that it is smaller or equal.
        if part_remove.content.len() > interned_file.content.len() {
            return HunkApplyReport::Failed;
        }

        // Helper function to decide if the needle matches haystack at give offset.
        fn matches(needle: &[LineId], haystack: &[LineId], at: isize) -> bool {
            assert!(at >= 0);
            let at = at as usize;
            if needle.len() + at > haystack.len() {
                return false;
            }

            &haystack[at..(at + needle.len())] == needle
        }

        // Check if the part we want to remove is at the originally intended target_line
        if !matches(&part_remove.content, &interned_file.content, target_line) {
            // It is not on the indended target_line...

            // If we are in rollback mode, we are in big trouble. Fail early.
            if let ApplyMode::Rollback(_) = apply_mode {
                return HunkApplyReport::Failed;
            }

            // Only hunks that are intended for somewhere in the middle of the code
            // can be applied somewhere else based on context. I.e. if the hunk is
            // targeting the start or the end of the file and it did not match, we
            // can not try to find any better offset.
            if self.position != HunkPosition::Middle {
                return HunkApplyReport::Failed;
            }

            // man patch (continuation):
            // "If that is not the correct place, patch scans both forwards and
            // backwards for a set of lines matching the context given in the hunk."

            // We'll find every occurence of `part_remove.content` in the file and pick the one that is closest
            // to the `target_line`
            let mut best_target_line: Option<isize> = None;

            for possible_target_line in Searcher::new(&part_remove.content).search_in(&interned_file.content) {
                let possible_target_line = possible_target_line as isize;

                // WARNING: The "<=" in the comparison below is important! If a hunk can be placed with two offsets that
                // have the same magnitude, but one positive and the other other negative, patch prefers the positive one!
                if best_target_line.is_none() || (possible_target_line - target_line).abs() <= (best_target_line.unwrap() - target_line).abs() {
                    // We found a position that is better (or there was no best position yet), remember it.
                    best_target_line = Some(possible_target_line);
                } else {
                    // We found a position that is worse than the best one so far. We are searching the file from start to end, so the
                    // possible_target_line will be getting closer and closer to the target_line until we pass it and it will
                    // start getting worse. At that point we can cut off the search.
                    break;
                }
            }

            // Did we find the line or not?
            match best_target_line {
                Some(new_target_line) => {
                    target_line = new_target_line;
                },
                None => {
                    return HunkApplyReport::Failed;
                }
            }
        }

        assert!(target_line >= 0);

        // Replace that part of the `interned_file` with the new one!
        let range = (target_line as usize)..(target_line as usize + part_remove.content.len());
        interned_file.content.splice(range.clone(), part_add.content.clone());

        // Report success
        HunkApplyReport::Applied { line: target_line, offset: target_line - part_add.target_line }
    }
}

/// Whether the `FilePatch` is creating, deleting or modifying existing file.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum FilePatchKind {
    Modify,
    Create,
    Delete,
}

/// Is the patch being applied forward = normally, or reverted.
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

/// The result of applying a `Hunk`.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HunkApplyReport {
    /// It was applied on given line, with given offset.
    Applied { line: isize, offset: isize },

    /// It failed to apply.
    Failed,

    /// It was skipped. Used when rolling back and skipping hunks that
    /// previously failed.
    Skipped,
}

/// The result of applying a `FilePatch`
#[derive(Debug)]
pub struct FilePatchApplyReport {
    any_failed: bool,
    hunk_reports: Vec<HunkApplyReport>,
    fuzz: usize,
    previous_permissions: Option<fs::Permissions>,
}

impl FilePatchApplyReport {
    /// Create a report for given amount of hunks
    fn new_with_capacity(fuzz: usize, capacity: usize) -> Self {
        FilePatchApplyReport {
            hunk_reports: Vec::with_capacity(capacity),
            any_failed: false,
            fuzz,
            previous_permissions: None,
        }
    }

    /// Create a report with single hunk that succeeded
    fn single_hunk_success(line: isize, offset: isize, fuzz: usize) -> Self {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::Applied { line, offset }],
            any_failed: false,
            fuzz,
            previous_permissions: None,
        }
    }

    /// Create a report with single hunk that failed
    fn single_hunk_failure(fuzz: usize) -> Self {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::Failed],
            any_failed: true,
            fuzz,
            previous_permissions: None,
        }
    }

    /// Add a hunk report
    fn push_hunk_report(&mut self, hunk_report: HunkApplyReport) {
        self.hunk_reports.push(hunk_report);
        if hunk_report == HunkApplyReport::Failed {
            self.any_failed = true;
        }
    }

    /// Did the applying went ok? All hunks succeeded?
    pub fn ok(&self) -> bool { !self.any_failed }

    /// Did the applying failed? Any hunk failed?
    pub fn failed(&self) -> bool { self.any_failed }

    /// Get the reports for the individual hunks.
    pub fn hunk_reports(&self) -> &[HunkApplyReport] { &self.hunk_reports }

    /// Fuzz level used during the applying.
    pub fn fuzz(&self) -> usize { self.fuzz }
}

pub type HunksVec<'a, Line> = SmallVec<[Hunk<'a, Line>; 2]>; // Optimal size found empirically on SUSE's kernel patches. It may change in future.

/// This represents all changes done to single file.
#[derive(Builder, Clone, Debug)]
#[builder]
pub struct FilePatch<'a, Line> {
    /// Does it create, delete or modify a file?
    kind: FilePatchKind,

    /// The old filename (e.g. after --- line)
    #[builder(default)]
    old_filename: Option<PathBuf>,

    /// The new filename (e.g. after +++ line)
    #[builder(default)]
    new_filename: Option<PathBuf>,

    #[builder(default)]
    is_rename: bool,

    /// The old permissions, if any were mentioned in the patch
    #[builder(default)]
    old_permissions: Option<fs::Permissions>,

    /// The new permissions, if any were mentioned in the patch
    #[builder(default)]
    new_permissions: Option<fs::Permissions>,

    #[builder(default)]
    hunks: HunksVec<'a, Line>,
}

impl<'a, Line> FilePatch<'a, Line> {
    pub fn kind(&self) -> FilePatchKind { self.kind }

    pub fn old_filename(&self) -> Option<&PathBuf> { self.old_filename.as_ref() }
    pub fn new_filename(&self) -> Option<&PathBuf> { self.new_filename.as_ref() }

    #[allow(dead_code)]
    pub fn is_rename(&self) -> bool { self.is_rename }

    #[allow(dead_code)]
    pub fn old_permissions(&self) -> Option<&fs::Permissions> { self.old_permissions.as_ref() }
    #[allow(dead_code)]
    pub fn new_permissions(&self) -> Option<&fs::Permissions> { self.new_permissions.as_ref() }

    pub fn hunks(&self) -> &[Hunk<'a, Line>] { &self.hunks }

    /// Strip the leading path from the filename and new_filename
    pub fn strip(&mut self, strip: usize) {
        fn strip_path(path: &Path, strip: usize) -> PathBuf {
            let mut components = path.components();
            for _ in 0..strip { components.next(); }
            components.as_path().to_path_buf()

            // TODO: Handle error if it is too short!
        }

        if let Some(old_filename) = &self.old_filename {
            self.old_filename = Some(strip_path(old_filename, strip));
        }
        if let Some(new_filename) = &self.new_filename {
            self.new_filename = Some(strip_path(new_filename, strip));
        }
    }

    /// Return the maximum fuzz that can be applied to this file patch. Applying
    /// more has no effect because there would be no more context lines to ignore.
    pub fn max_useable_fuzz(&self) -> usize {
        self.hunks.iter().map(|hunk| hunk.max_useable_fuzz()).max().unwrap_or(0)
    }
}

pub type TextFilePatch<'a> = FilePatch<'a, &'a [u8]>;
pub type InternedFilePatch<'a> = FilePatch<'a, LineId>;

impl<'a> TextFilePatch<'a> {
    /// Consumes this text-based FilePatch and produces interned FilePatch.
    pub fn intern(mut self, interner: &mut LineInterner<'a>) -> InternedFilePatch<'a> {
        FilePatch {
            kind: self.kind,

            old_filename: self.old_filename,
            new_filename: self.new_filename,

            is_rename: self.is_rename,

            old_permissions: self.old_permissions,
            new_permissions: self.new_permissions,

            hunks: self.hunks.drain().map(|hunk| hunk.intern(interner)).collect(),
        }
    }
}

/// The mode of application. This is different from `PatchDirection`.
#[derive(Copy, Clone, Debug)]
enum ApplyMode<'a> {
    /// In normal mode, the patch is applied (or reverted) the way patch does
    /// it - first it will try the target line, then various offsets.
    Normal,

    /// In rollback mode, the patch was already applied (successfully or not)
    /// and now it has to be rolled back. It will be reverted (or applied) at
    /// the exact same lines where it was applied (or reverted) before.
    Rollback(&'a FilePatchApplyReport),
}

impl<'a> InternedFilePatch<'a> {
    /// Apply (or revert - based on `direction`) this patch to the `interned_file` using the given `fuzz`.
    pub fn apply(&self, interned_file: &mut InternedFile, direction: PatchDirection, fuzz: usize) -> FilePatchApplyReport {
        self.apply_internal(interned_file, direction, fuzz, ApplyMode::Normal)
    }

    /// Rollback the application (or the revertion - based on direction) of this patch from the `interned_file`
    /// using the information from the `apply_report`.
    pub fn rollback(&self, interned_file: &mut InternedFile, direction: PatchDirection, apply_report: &FilePatchApplyReport) {
        assert!(self.hunks.len() == apply_report.hunk_reports().len());

        let result = self.apply_internal(interned_file, direction.opposite(), 0, ApplyMode::Rollback(apply_report));
        assert!(result.ok()); // Rollback must apply cleanly. If not, we have a bug somewhere.
    }

    /// Internal function that does the function of both `apply` and `rollback`.
    fn apply_internal(&self, interned_file: &mut InternedFile, direction: PatchDirection, fuzz: usize, apply_mode: ApplyMode) -> FilePatchApplyReport {
        // Call the appropriate specialized function
        let mut report = match (self.kind, direction) {
            (FilePatchKind::Modify, _) =>
                self.apply_modify(interned_file, direction, fuzz, apply_mode),

            (FilePatchKind::Create, PatchDirection::Forward) |
            (FilePatchKind::Delete, PatchDirection::Revert) =>
                self.apply_create(interned_file, direction, fuzz),

            (FilePatchKind::Delete, PatchDirection::Forward) |
            (FilePatchKind::Create, PatchDirection::Revert) =>
                self.apply_delete(interned_file, direction, fuzz),
        };

        // Set new mode to the file, if there is any
        let change_permissions_to = match (apply_mode, direction) {
            (ApplyMode::Rollback(report), _) => &report.previous_permissions,
            (ApplyMode::Normal, PatchDirection::Forward) => &self.new_permissions,
            (ApplyMode::Normal, PatchDirection::Revert) => &self.old_permissions,
        };
        report.previous_permissions = if let Some(change_permissions_to) = change_permissions_to {
            interned_file.permissions.replace(change_permissions_to.clone())
        } else {
            interned_file.permissions.clone()
        };

        report
    }

    /// Apply this `FilePatchKind::Create` patch on the file.
    fn apply_create(&self, interned_file: &mut InternedFile, direction: PatchDirection, fuzz: usize) -> FilePatchApplyReport {
        assert!(self.hunks.len() == 1);

        // If we are creating it, it must be empty.
        if !interned_file.content.is_empty() {
            return FilePatchApplyReport::single_hunk_failure(fuzz);
        }

        let new_content = match direction {
            PatchDirection::Forward => &self.hunks[0].add.content,
            PatchDirection::Revert => &self.hunks[0].remove.content,
        };

        // Just copy in it the content of our single hunk and we are done.
        interned_file.content = new_content.clone().into_vec();
        interned_file.deleted = false;

        FilePatchApplyReport::single_hunk_success(0, 0, fuzz)
    }

    /// Apply this `FilePatchKind::Delete` patch on the file.
    fn apply_delete(&self, interned_file: &mut InternedFile, direction: PatchDirection, fuzz: usize) -> FilePatchApplyReport {
        assert!(self.hunks.len() == 1);

        let expected_content = match direction {
            PatchDirection::Forward => &self.hunks[0].remove.content,
            PatchDirection::Revert => &self.hunks[0].add.content,
        };

        // If we are deleting it, it must contain exactly what we want to remove.
        if &expected_content[..] != &interned_file.content[..] {
            return FilePatchApplyReport::single_hunk_failure(fuzz);
        }

        // Just delete everything and we are done
        interned_file.content.clear();
        interned_file.deleted = true;

        FilePatchApplyReport::single_hunk_success(0, 0, fuzz)
    }

    /// Apply this `FilePatchKind::Modify` patch on the file.
    fn apply_modify(&self, interned_file: &mut InternedFile, direction: PatchDirection, fuzz: usize, apply_mode: ApplyMode) -> FilePatchApplyReport {
        let mut report = FilePatchApplyReport::new_with_capacity(fuzz, self.hunks.len());

        let mut last_hunk_offset = 0isize;

        // This function is applied on every hunk one by one, either from beginning
        // to end, or the opposite way (depends if we are applying or reverting)
        let mut for_each_hunk = |i, hunk: &Hunk<LineId>| {
            let mut hunk_report = HunkApplyReport::Skipped;

            // Decide which fuzz levels we should try
            #[allow(clippy::range_plus_one)] // We need all ranges to be the same type and the last one has to be empty
            let possible_fuzz_levels = match apply_mode {
                // In normal mode consider fuzz 0 up to given maximum fuzz, but no more than what is useable for this hunk
                ApplyMode::Normal =>
                    0..(std::cmp::min(fuzz, hunk.max_useable_fuzz()) + 1),

                // In rollback mode use what worked in normal mode
                ApplyMode::Rollback(ref report) => match report.hunk_reports[i] {
                    // If the hunk applied, pick the specific fuzz level
                    HunkApplyReport::Applied { .. } =>
                        report.fuzz()..(report.fuzz() + 1),

                    // If the hunk failed to apply, skip it now.
                    HunkApplyReport::Failed |
                    HunkApplyReport::Skipped =>
                        0..0, // Empty interval = it won't try at all
                }
            };

            for current_fuzz in possible_fuzz_levels {
                // If we are at fuzz 0, borrow the hunk, otherwise make a copy
                // for the fuzz level.
                let hunk = match current_fuzz {
                    0 => Cow::Borrowed(hunk),
                    _ => Cow::Owned(hunk.clone_with_fuzz(current_fuzz)),
                };

                // Attempt to apply the hunk...
                hunk_report = hunk.apply_modify(i, interned_file, direction, apply_mode, last_hunk_offset);

                // If it succeeded, we are done with this hunk, do not try any
                // more fuzz levels.
                if let HunkApplyReport::Applied { .. } = hunk_report {
                    break;
                }
            }

            // If it applied, remember the offset, so we can use it for the
            // next hunk.
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
