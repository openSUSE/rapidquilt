// Licensed under the MIT license. See LICENSE.md

//! This module defines the structures representing a patch and algorithms for
//! applying them on `InternedFile`s.
//!
//! The hierarchy is:
//! Top: `Patch`              ... a single "blabla.patch" file
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
//!                   Type aliases `TextPatch`, `TextFilePatch` and `TextHunk`
//!                   can be used as shortcut.
//!
//! * `Line = LineId`: The line is a unique 32-bit ID. This is how patches look
//!                    after interning.
//!                    Type aliases `InternedPatch`, `InternedFilePatch` and
//!                    `InternedHunk` can be used as shortcut.
//!
//! Other line representations would be possible, for example one where
//! `Line = String` for a patch that owns its data.
//!
//! Hunks are not represented using remove-lines, add-lines and context-lines,
//! but only using remove-lines and add-lines. Every context-line is used as
//! remove-line and add-line.


use std::fs;
use std::vec::Vec;
use std::path::{Path, PathBuf};

use derive_builder::Builder;
use smallvec::SmallVec;

use crate::analysis::{Analysis, AnalysisSet, Note, fn_analysis_note_noop};
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

            function,
        }
    }

    /// Return the maximum fuzz that can be applied to this hunk. Applying more
    /// has no effect because there would be no more context lines to ignore.
    pub fn max_useable_fuzz(&self) -> usize {
        std::cmp::max(self.context_before, self.context_after)
    }

    pub fn view<'hunk>(&'hunk self, direction: PatchDirection, fuzz: usize)
           -> HunkView<'a, 'hunk, Line>
    {
        HunkView::new(self, direction, fuzz)
    }
}

pub type TextHunk<'a> = Hunk<'a, &'a [u8]>;
pub type InternedHunk<'a> = Hunk<'a, LineId>;

#[derive(Clone, Debug)]
pub struct HunkView<'a, 'hunk, Line> {
    hunk: &'hunk Hunk<'a, Line>,

    fuzz: usize,
    fuzz_before: usize,
    fuzz_after: usize,

    direction: PatchDirection,
}

impl<'a, 'hunk, Line> HunkView<'a, 'hunk, Line> {
    pub fn new(hunk: &'hunk Hunk<'a, Line>, direction: PatchDirection, fuzz: usize) -> Self {
        let fuzz_before = std::cmp::min(hunk.context_before, fuzz);
        let fuzz_after = std::cmp::min(hunk.context_after, fuzz);

        HunkView {
            hunk,
            fuzz,
            fuzz_before,
            fuzz_after,
            direction,
        }
    }

    fn remove_part(&self) -> &HunkPart<Line> {
        match self.direction {
            PatchDirection::Forward => &self.hunk.remove,
            PatchDirection::Revert => &self.hunk.add,
        }
    }

    fn add_part(&self) -> &HunkPart<Line> {
        match self.direction {
            PatchDirection::Forward => &self.hunk.add,
            PatchDirection::Revert => &self.hunk.remove,
        }
    }

    pub fn remove_content(&self) -> &[Line] {
        &self.remove_part().content[self.fuzz_before..(self.remove_part().content.len() - self.fuzz_after)]
    }
    pub fn remove_target_line(&self) -> isize { self.remove_part().target_line }

    pub fn add_content(&self) -> &[Line] {
        &self.add_part().content[self.fuzz_before..(self.add_part().content.len() - self.fuzz_after)]
    }
    pub fn add_target_line(&self) -> isize { self.add_part().target_line }

    pub fn context_before(&self) -> usize { self.hunk.context_before - self.fuzz_before }
    pub fn context_after(&self) -> usize { self.hunk.context_after - self.fuzz_after }

    pub fn position(&self) -> HunkPosition {
        // man patch: "Hunks with less prefix context than suffix context (after applying fuzz) must apply at the
        //             start of the file if their first line  number is 1. Hunks with more prefix context than suffix
        //             context (after applying fuzz) must apply at the end of the file."

        if self.context_before() < self.context_after() && self.add_target_line() == 0 { // Note that we are numbering lines from 0, so this is the "line number 1" the manual talks about.
            return HunkPosition::Start;
        }

        if self.context_before() > self.context_after() {
            return HunkPosition::End;
        }

        HunkPosition::Middle
    }

    pub fn function(&self) -> &'a [u8] { self.hunk.function }

    pub fn fuzz(&self) -> usize { self.fuzz }
}

pub type TextHunkView<'a, 'hunk> = HunkView<'a, 'hunk, &'a [u8]>;
pub type InternedHunkView<'a, 'hunk> = HunkView<'a, 'hunk, LineId>;

impl<'a> TextHunk<'a> {
    /// Consumes this text-based Hunk and produces interned Hunk.
    pub fn intern(self, interner: &mut LineInterner<'a>) -> InternedHunk<'a> {
        Hunk {
            remove: self.remove.intern(interner),
            add: self.add.intern(interner),
            context_before: self.context_before,
            context_after: self.context_after,
            function: self.function,
        }
    }
}

/// Try to apply given `HunkView` of an interned hunk onto the `InternedFile`.
/// This function does not really modify the interned_file, only returns report
/// describing if application is possible and where would it go.
///
/// `hunk`: the `HunkView` to apply
///
/// `my_index`: the index of this hunk in the `FilePatch`
///
/// `interned_file`: the application is tried on this file
///
/// `apply_mode`: whether the patch is being applied or rolled-back . This is different from `direction`. See documentation of `ApplyMode`.
///
/// `last_hunk_offset`: the offset on which the previous hunk applied
///
/// `last_frozen_line`: last line that was modified by previous hunk. We must not edit anything before that line.
fn try_apply_hunk<'a, 'hunk>(
    hunk_view: &InternedHunkView<'a, 'hunk>,
    my_index: usize,
    interned_file: &InternedFile,
    apply_mode: ApplyMode,
    last_hunk_offset: isize,
    last_frozen_line: isize)
    -> HunkApplyReport
{
    // If the file doesn't exist, fail immediatelly
    if interned_file.deleted {
        return HunkApplyReport::Failed(HunkApplyFailureReason::FileWasDeleted);
    }

    // Shortcuts
    let remove_content = hunk_view.remove_content();
    let add_content = hunk_view.add_content();

    // Determine the target line.
    let mut target_line = match apply_mode {
        // In normal mode, pick what is in the hunk
        ApplyMode::Normal => match hunk_view.position() {
            HunkPosition::Start => hunk_view.remove_target_line(),

            // man patch: "With  context  diffs, and to a lesser extent with normal diffs, patch can detect
            //             when the line numbers mentioned in the patch are incorrect, and attempts to find
            //             the correct place to apply each hunk of the patch.  As a first guess, it takes the
            //             line number mentioned for the hunk, plus or minus any offset used in applying the
            //             previous hunk.."
            HunkPosition::Middle => hunk_view.remove_target_line() + last_hunk_offset,

            HunkPosition::End => (interned_file.content.len() as isize - remove_content.len() as isize),
        },

        // In rollback mode, take it from the report
        ApplyMode::Rollback(report) => match report.hunk_reports()[my_index] {
            // If the hunk was applied at specific line, choose that line now.
            HunkApplyReport::Applied { rollback_line, .. } => rollback_line,

            // Nothing else should get here
            _ => unreachable!(),
        }
    };

    // If the hunk tries to remove more than the file has, reject it now.
    // So in the following code we can assume that it is smaller or equal.
    if remove_content.len() > interned_file.content.len() {
        return HunkApplyReport::Failed(HunkApplyFailureReason::NoMatchingLines);
    }

    // Helper function to decide if the needle matches haystack at give offset.
    fn matches(needle: &[LineId], haystack: &[LineId], at: isize) -> bool {
        if at < 0 {
            return false;
        }

        let at = at as usize;
        if needle.len() + at > haystack.len() {
            return false;
        }

        &haystack[at..(at + needle.len())] == needle
    }

    // Check if the part we want to remove is at the originally intended target_line
    if !matches(&remove_content, &interned_file.content, target_line) {
        // It is not on the indended target_line...

        // If we are in rollback mode, we are in big trouble. Fail early.
        if let ApplyMode::Rollback(_) = apply_mode {
            return HunkApplyReport::Failed(HunkApplyFailureReason::NoMatchingLines);
        }

        // Only hunks that are intended for somewhere in the middle of the code
        // can be applied somewhere else based on context. I.e. if the hunk is
        // targeting the start or the end of the file and it did not match, we
        // can not try to find any better offset.
        if hunk_view.position() != HunkPosition::Middle {
            return HunkApplyReport::Failed(HunkApplyFailureReason::NoMatchingLines);
        }

        // man patch (continuation):
        // "If that is not the correct place, patch scans both forwards and
        // backwards for a set of lines matching the context given in the hunk."

        // We'll find every occurence of `remove_content` in the file and pick the one that is closest
        // to the `target_line`
        let mut best_target_line: Option<isize> = None;

        for possible_target_line in Searcher::new(&remove_content).search_in(&interned_file.content) {
            let possible_target_line = possible_target_line as isize;

            // WARNING: The "<=" in the comparison below is important! If a hunk can be placed with two offsets that
            // have the same magnitude, but one positive and the other other negative, patch prefers the positive one!
            if best_target_line.is_none() || (possible_target_line - target_line).abs() <= (best_target_line.unwrap() - target_line).abs() {
                // We found a position that is better (or there was no best position yet), remember it.
                best_target_line = Some(possible_target_line);

                if possible_target_line > target_line {
                    // We found a match on a line that is after the expected target_line.
                    // We can stop the search right now because any future matches will
                    // have bigger offset so have no chance of being selected.
                    break;
                }
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
                return HunkApplyReport::Failed(HunkApplyFailureReason::NoMatchingLines);
            }
        }
    }

    if let ApplyMode::Normal = apply_mode {
        // Check if we are not modifying frozen content
        if target_line + hunk_view.context_before() as isize <= last_frozen_line {
            return HunkApplyReport::Failed(HunkApplyFailureReason::MisorderedHunks);
        }
    }

    assert!(target_line >= 0);

    // Report success
    HunkApplyReport::Applied {
        line: target_line,
        rollback_line: target_line,
        offset: target_line - hunk_view.remove_target_line(),
        line_count_diff: add_content.len() as isize - remove_content.len() as isize,
        fuzz: hunk_view.fuzz(),
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

/// The reason for hunk failure
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HunkApplyFailureReason {
    NoMatchingLines,
    FileWasDeleted,
    CreatingFileThatExists,
    DeletingFileThatDoesNotMatch,
    MisorderedHunks,
}

/// The result of applying a `Hunk`.
#[derive(Debug)]
pub enum HunkApplyReport {
    /// It was applied on given line, with given offset.
    Applied {
        /// Line on which the hunk was applied (in the original file).
        line: isize,

        /// Line at which the hunk is for rollback (in the modified file).
        rollback_line: isize,

        /// The offset from the originally intended line to the line where it
        /// was applied.
        offset: isize,

        /// How many lines were added minus how many were removed
        line_count_diff: isize,

        /// Fuzz with which this specific hunk was applied
        fuzz: usize,
    },

    /// It failed to apply.
    Failed(HunkApplyFailureReason),

    /// It was skipped. Used when rolling back and skipping hunks that
    /// previously failed.
    Skipped,
}

/// The result of applying a `FilePatch`
#[derive(Debug)]
pub struct FilePatchApplyReport {
    any_failed: bool,
    hunk_reports: Vec<HunkApplyReport>,
    direction: PatchDirection,
    fuzz: usize,
    previous_permissions: Option<fs::Permissions>,
}

impl FilePatchApplyReport {
    /// Create a report for given amount of hunks
    fn new_with_capacity(direction: PatchDirection, fuzz: usize, capacity: usize) -> Self {
        FilePatchApplyReport {
            hunk_reports: Vec::with_capacity(capacity),
            any_failed: false,
            direction,
            fuzz,
            previous_permissions: None,
        }
    }

    /// Create a report with single hunk that succeeded
    fn single_hunk_success(line: isize,
                           offset: isize,
                           line_count_diff: isize,
                           direction: PatchDirection,
                           fuzz: usize)
                           -> Self
    {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::Applied {
                line, rollback_line: line, offset, line_count_diff, fuzz,
            }],
            any_failed: false,
            direction,
            fuzz,
            previous_permissions: None,
        }
    }

    /// Create a report with single hunk that failed
    fn single_hunk_failure(reason: HunkApplyFailureReason, direction: PatchDirection, fuzz: usize) -> Self {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::Failed(reason)],
            any_failed: true,
            direction,
            fuzz,
            previous_permissions: None,
        }
    }

    /// Create a report with single hunk that was skipped
    fn single_hunk_skip(direction: PatchDirection, fuzz: usize) -> Self {
        FilePatchApplyReport {
            hunk_reports: vec![HunkApplyReport::Skipped],
            any_failed: false,
            direction,
            fuzz,
            previous_permissions: None,
        }
    }

    /// Add a hunk report
    fn push_hunk_report(&mut self, hunk_report: HunkApplyReport) {
        match hunk_report {
            HunkApplyReport::Failed(..) => {
                self.any_failed = true;
            }
            _ => {}
        }
        self.hunk_reports.push(hunk_report);
    }

    /// Did the applying went ok? All hunks succeeded?
    pub fn ok(&self) -> bool { !self.any_failed }

    /// Did the applying failed? Any hunk failed?
    pub fn failed(&self) -> bool { self.any_failed }

    /// Get the reports for the individual hunks.
    pub fn hunk_reports(&self) -> &[HunkApplyReport] { &self.hunk_reports }

    /// Direction that was used to apply this patch
    pub fn direction(&self) -> PatchDirection {
        self.direction
    }

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
    pub fn apply(&self,
                 interned_file: &mut InternedFile,
                 direction: PatchDirection,
                 fuzz: usize,
                 analyses: &AnalysisSet,
                 fn_analysis_note: &Fn(&dyn Note, &InternedFilePatch))
                 -> FilePatchApplyReport
    {
        self.apply_internal(interned_file, direction, fuzz, ApplyMode::Normal, analyses, fn_analysis_note)
    }

    /// Rollback the application (or the revertion - based on direction) of this patch from the `interned_file`
    /// using the information from the `apply_report`.
    pub fn rollback(&self,
                    interned_file: &mut InternedFile,
                    direction: PatchDirection,
                    apply_report: &FilePatchApplyReport)
    {
        assert!(self.hunks.len() == apply_report.hunk_reports().len());

        let result = self.apply_internal(interned_file, direction.opposite(), 0, ApplyMode::Rollback(apply_report),
                                         &AnalysisSet::default(), &fn_analysis_note_noop);

        // Rollback must apply cleanly. If not, we have a bug somewhere.
        if result.failed() {
            panic!("Rapidquilt attempted to rollback a patch and that failed. This is a bug. Failure report: {:?}", result);
        }
    }

    /// Internal function that does the function of both `apply` and `rollback`.
    fn apply_internal(&self,
                      interned_file: &mut InternedFile,
                      direction: PatchDirection,
                      fuzz: usize,
                      apply_mode: ApplyMode,
                      analyses: &AnalysisSet,
                      fn_analysis_note: &Fn(&dyn Note, &InternedFilePatch))
                      -> FilePatchApplyReport
    {
        // Call the appropriate specialized function
        let mut report = match (self.kind, direction) {
            (FilePatchKind::Modify, _) =>
                self.apply_modify(interned_file, direction, fuzz, apply_mode, analyses, fn_analysis_note),

            (FilePatchKind::Create, PatchDirection::Forward) |
            (FilePatchKind::Delete, PatchDirection::Revert) =>
                self.apply_create(interned_file, direction, fuzz, apply_mode),

            (FilePatchKind::Delete, PatchDirection::Forward) |
            (FilePatchKind::Create, PatchDirection::Revert) =>
                self.apply_delete(interned_file, direction, fuzz, apply_mode),
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
    fn apply_create(&self,
                    interned_file: &mut InternedFile,
                    direction: PatchDirection,
                    fuzz: usize,
                    apply_mode: ApplyMode)
                    -> FilePatchApplyReport
    {
        assert!(self.hunks.len() == 1);

        if let ApplyMode::Rollback(report) = apply_mode {
            if let HunkApplyReport::Failed(..) = report.hunk_reports()[0] {
                return FilePatchApplyReport::single_hunk_skip(direction, fuzz);
            }
        }

        // If we are creating it, it must be empty.
        if !interned_file.content.is_empty() {
            return FilePatchApplyReport::single_hunk_failure(HunkApplyFailureReason::CreatingFileThatExists, direction, fuzz);
        }

        let new_content = match direction {
            PatchDirection::Forward => &self.hunks[0].add.content,
            PatchDirection::Revert => &self.hunks[0].remove.content,
        };

        // Just copy in it the content of our single hunk and we are done.
        interned_file.content = new_content.clone().into_vec();
        interned_file.deleted = false;

        FilePatchApplyReport::single_hunk_success(0, 0, new_content.len() as isize, direction, fuzz)
    }

    /// Apply this `FilePatchKind::Delete` patch on the file.
    fn apply_delete(&self,
                    interned_file: &mut InternedFile,
                    direction: PatchDirection,
                    fuzz: usize,
                    apply_mode: ApplyMode)
                    -> FilePatchApplyReport
    {
        assert!(self.hunks.len() == 1);

        if let ApplyMode::Rollback(report) = apply_mode {
            if let HunkApplyReport::Failed(..) = report.hunk_reports()[0] {
                return FilePatchApplyReport::single_hunk_skip(direction, fuzz);
            }
        }

        let expected_content = match direction {
            PatchDirection::Forward => &self.hunks[0].remove.content,
            PatchDirection::Revert => &self.hunks[0].add.content,
        };

        // If we are deleting it, it must contain exactly what we want to remove.
        if &expected_content[..] != &interned_file.content[..] {
            return FilePatchApplyReport::single_hunk_failure(HunkApplyFailureReason::DeletingFileThatDoesNotMatch, direction, fuzz);
        }

        // Just delete everything and we are done
        interned_file.content.clear();
        interned_file.deleted = true;

        FilePatchApplyReport::single_hunk_success(0, 0, -(expected_content.len() as isize), direction, fuzz)
    }

    /// Apply this `FilePatchKind::Modify` patch on the file.
    fn apply_modify(&self,
                    interned_file: &mut InternedFile,
                    direction: PatchDirection,
                    fuzz: usize,
                    apply_mode: ApplyMode,
                    analyses: &AnalysisSet,
                    fn_analysis_note: &Fn(&dyn Note, &InternedFilePatch))
                    -> FilePatchApplyReport
    {
        let mut report = FilePatchApplyReport::new_with_capacity(direction, fuzz, self.hunks.len());

        let mut last_hunk_offset = 0isize;

        // This adds artificial limitation on ordering of hunks to replicate the behavior of patch.
        // Patch prints the output lines while it is applying hunks, so no hunk can not modify a
        // line before the previous hunk. We don't have this limitation, but lets emulate it so we
        // don't accept more patches than patch. After all, if we accept hunks in arbitrary order,
        // it is not well defined if they should match against the file before or after
        // modifications from the previous hunks.
        let mut last_frozen_line = -1isize;

        // This function is applied on every hunk one by one, either from beginning
        // to end, or the opposite way (depends if we are applying or reverting)
        for (i, hunk) in self.hunks.iter().enumerate() {
            let mut hunk_report = HunkApplyReport::Skipped;

            // Decide which fuzz levels we should try
            let possible_fuzz_levels = match apply_mode {
                // In normal mode consider fuzz 0 up to given maximum fuzz, but no more than what is useable for this hunk
                ApplyMode::Normal =>
                    0..=std::cmp::min(fuzz, hunk.max_useable_fuzz()),

                // In rollback mode use what worked in normal mode
                ApplyMode::Rollback(ref previous_report) => match previous_report.hunk_reports[i] {
                    // If the hunk applied, pick the specific fuzz level
                    HunkApplyReport::Applied { fuzz, .. } =>
                        fuzz..=fuzz,

                    // If the hunk failed to apply, skip it now.
                    HunkApplyReport::Failed(..) |
                    HunkApplyReport::Skipped => {
                        // Skip it
                        report.push_hunk_report(hunk_report);
                        continue;
                    }
                }
            };

            for current_fuzz in possible_fuzz_levels {
                // Attempt to apply the hunk at the right fuzz level...
                let hunk_view = &hunk.view(direction, current_fuzz);

                hunk_report = try_apply_hunk(hunk_view, i, interned_file,
                                             apply_mode, last_hunk_offset,
                                             last_frozen_line);

                // If it succeeded, we are done with this hunk, remember the last_hunk_offset
                // and last_frozen_line, so we can use them for the next hunk and do not try
                // any more fuzz levels.
                if let HunkApplyReport::Applied { line, offset, .. } = hunk_report {
                    last_hunk_offset = offset;
                    last_frozen_line = line + hunk_view.remove_content().len() as isize - hunk_view.context_after() as isize;
                    break;
                }
            }
            report.push_hunk_report(hunk_report);
        }

        analyses.before_modifications(interned_file, self, direction, &report, fn_analysis_note);

        // Now apply all changes on the file.
        // TODO: Do some more efficient than multiple `Vec::splice`s? The problem with multiple
        //       splices is that they move the tail of the file multiple times. Alternative is to
        //       generate new Vec and copy every LineId at most once, but that seems to be even
        //       slower. Ideally we would need some in-place modification that moves every LineId
        //       at most once. But I don't think it is possible in general case.
        {
            let mut modification_offset = 0;
            for (hunk, hunk_report) in self.hunks.iter().zip(report.hunk_reports.iter_mut()) {
                if let HunkApplyReport::Applied { line, ref mut rollback_line, fuzz, line_count_diff, .. } = hunk_report {
                    let hunk_view = hunk.view(direction, *fuzz);
                    let target_line = *line + modification_offset;
                    *rollback_line = target_line;
                    let range = (target_line as usize)..(target_line as usize + hunk_view.remove_content().len());
                    interned_file.content.splice(range.clone(), hunk_view.add_content().to_vec()); // TODO: No to_vec here?

                    modification_offset += *line_count_diff;
                }
            }
        }

        analyses.after_modifications(interned_file, self, direction, &report, fn_analysis_note);

        report
    }
}

/// A single patch file
#[derive(Clone, Debug)]
pub struct Patch<'a, Line> {
    /// All "garbage" lines preceding the first FilePatch.
    /// These lines include the final new line character.
    pub header: Vec<&'a [u8]>,

    /// All FilePatches included in the patch file
    pub file_patches: Vec<FilePatch<'a, Line>>,
}

pub type TextPatch<'a> = Patch<'a, &'a [u8]>;
pub type InternedPatch<'a> = Patch<'a, LineId>;

impl<'a> TextPatch<'a> {
    /// Consumes this text-based Patch and produces interned Patch.
    pub fn intern(mut self, interner: &mut LineInterner<'a>) -> InternedPatch<'a> {
        InternedPatch {
            header: self.header,
            file_patches: self.file_patches.drain(..).map(|file_patch| file_patch.intern(interner)).collect(),
        }
    }
}
