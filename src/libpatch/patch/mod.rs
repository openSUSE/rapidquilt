// Licensed under the MIT license. See LICENSE.md

//! This module defines the structures representing a patch and algorithms for
//! applying them on `ModifiedFile`s.
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
//! Other line representations would be possible, for example one where
//! `Line = String` for a patch that owns its data.
//!
//! Hunks are not represented using remove-lines, add-lines and context-lines,
//! but only using remove-lines and add-lines. Every context-line is used as
//! remove-line and add-line.


use std::borrow::Cow;
use std::cmp::{max, min};
use std::fs;
use std::vec::Vec;
use std::path::Path;

use derive_builder::Builder;
use itertools::Itertools;

use crate::analysis::{Analysis, AnalysisSet, Note};
use crate::modified_file::ModifiedFile;

pub mod unified;


type ContentVec<Line> = Vec<Line>;

/// This is part of hunk representing the lines to be added or removed together
/// with the target line.
#[derive(Clone, Debug)]
pub struct HunkPart<Line> {
    pub content: ContentVec<Line>,

    /// Numbered from zero. Could be usize, but this makes calculating
    /// offsets easier.
    pub target_line: isize,
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
    pub prefix_context: usize,
    /// How many lines at the end of both `remove` and `add` are actually context
    /// lines. (Useful for fuzzy patching.)
    pub suffix_context: usize,

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

            prefix_context: 0,
            suffix_context: 0,

            function,
        }
    }

    /// Return the maximum fuzz that can be applied to this hunk. Applying more
    /// has no effect because there would be no more context lines to ignore.
    pub fn max_useable_fuzz(&self) -> usize {
        max(self.prefix_context, self.suffix_context)
    }

    pub fn view<'hunk>(&'hunk self, direction: PatchDirection, fuzz: usize)
           -> HunkView<'a, 'hunk, Line>
    {
        HunkView::new(self, direction, fuzz)
    }
}

pub type TextHunk<'a> = Hunk<'a, &'a [u8]>;

#[derive(Clone, Debug)]
pub struct HunkView<'a, 'hunk, Line> {
    hunk: &'hunk Hunk<'a, Line>,

    fuzz: usize,
    prefix_fuzz: usize,
    suffix_fuzz: usize,

    direction: PatchDirection,
}

impl<'a, 'hunk, Line> HunkView<'a, 'hunk, Line> {
    pub fn new(hunk: &'hunk Hunk<'a, Line>, direction: PatchDirection, fuzz: usize) -> Self {
        // If the `prefix_context` and `suffix_context` are equal, then `fuzz` needs to be subtracted
        // from both of them equally. So `fuzz` just turns into `prefix_fuzz` and `suffix_fuzz`.
        //
        // If they are not equal, then `fuzz` needs to be subtracted from the bigger one of them and
        // then the smaller one will be shortened only if needed to match the (originally) bigger one.
        //
        // One way to imagine it is that the shorter context actually contains virtual "out-of-file"
        // lines that make him as long as the other context. The fuzz is eating away these virtual
        // lines same as the real in-file lines. If it eats all the "out-of-file" lines, then the
        // hunk is no longer tied to the start/end of file.

        let remaining_context = max(hunk.prefix_context, hunk.suffix_context).saturating_sub(fuzz);
        let prefix_fuzz = hunk.prefix_context.saturating_sub(remaining_context);
        let suffix_fuzz = hunk.suffix_context.saturating_sub(remaining_context);

        HunkView {
            hunk,
            fuzz,
            prefix_fuzz,
            suffix_fuzz,
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
        &self.remove_part().content[self.prefix_fuzz..(self.remove_part().content.len() - self.suffix_fuzz)]
    }
    pub fn remove_target_line(&self) -> isize { self.remove_part().target_line }

    pub fn add_content(&self) -> &[Line] {
        &self.add_part().content[self.prefix_fuzz..(self.add_part().content.len() - self.suffix_fuzz)]
    }
    pub fn add_target_line(&self) -> isize { self.add_part().target_line }

    pub fn prefix_context(&self) -> usize { self.hunk.prefix_context - self.prefix_fuzz }
    pub fn suffix_context(&self) -> usize { self.hunk.suffix_context - self.suffix_fuzz }

    pub fn position(&self) -> HunkPosition {
        // man patch: "Hunks with less prefix context than suffix context (after applying fuzz) must apply at the
        //             start of the file if their first line  number is 1. Hunks with more prefix context than suffix
        //             context (after applying fuzz) must apply at the end of the file."

        if self.prefix_context() < self.suffix_context() &&
           self.add_target_line() == 0 // Note that we are numbering lines from 0, so this is the "line number 1" the manual talks about.
        {
            return HunkPosition::Start;
        }

        if self.prefix_context() > self.suffix_context() {
            return HunkPosition::End;
        }

        HunkPosition::Middle
    }

    pub fn function(&self) -> &'a [u8] { self.hunk.function }

    pub fn fuzz(&self) -> usize { self.fuzz }
}

pub type TextHunkView<'a, 'hunk> = HunkView<'a, 'hunk, &'a [u8]>;


/// Try to apply given `HunkView` onto the `ModifiedFile`.
/// This function does not really modify the modified_file, only returns report
/// describing if application is possible and where would it go.
///
/// `hunk`: the `HunkView` to apply
///
/// `modified_file`: the application is tried on this file
///
/// `apply_mode`: whether the patch is being applied or rolled-back . This is different from `direction`. See documentation of `ApplyMode`.
///
/// `target_line`: line where this hunk would be applied with zero offset
///
/// `min_modify_line`: first line that can be modified by a new hunk, i.e. first that is not modified by a previous hunk.
fn try_apply_hunk<'a, 'hunk>(
    hunk_view: &TextHunkView<'a, 'hunk>,
    modified_file: &ModifiedFile,
    apply_mode: ApplyMode,
    target_line: isize,
    min_modify_line: isize)
    -> HunkApplyReport
{
    // If the file doesn't exist, fail immediatelly
    if modified_file.deleted {
        return HunkApplyReport::Failed(HunkApplyFailureReason::FileDoesNotExist);
    }

    // Shortcuts
    let remove_content = hunk_view.remove_content();
    let add_content = hunk_view.add_content();

    // If the hunk tries to remove more than the file has, reject it now.
    // So in the following code we can assume that it is smaller or equal.
    if remove_content.len() > modified_file.content.len() {
        return HunkApplyReport::Failed(HunkApplyFailureReason::NoMatchingLines);
    }

    // Helper function to decide if the needle matches haystack at give offset.
    fn matches(needle: &[&[u8]], haystack: &[&[u8]], at: isize) -> bool {
        if at < 0 {
            return false;
        }

        let at = at as usize;
        if needle.len() + at > haystack.len() {
            return false;
        }

        &haystack[at..(at + needle.len())] == needle
    }

    // man patch (continuation):
    // "If that is not the correct place, patch scans both forwards and
    // backwards for a set of lines matching the context given in the hunk."
    let mut best_target_line: Option<isize> = None;
    let (min_line, max_line) =
	if let ApplyMode::Rollback(_) = apply_mode {
            // If we are in rollback mode, the hunk must match with zero offset.
	    (target_line, target_line)
	} else if hunk_view.position() != HunkPosition::Middle {
            // Only hunks that are intended for somewhere in the middle of the code
            // can be applied somewhere else based on context. I.e. if the hunk is
            // targeting the start or the end of the file and it did not match, we
            // can not try to find any better offset.
	    (target_line, target_line)
	} else {
	    (0, modified_file.content.len() as isize - remove_content.len() as isize)
	};
    let backward_targets = (min_line..=target_line).rev();
    let forward_targets = (target_line+1)..=max_line;

    // It is important that `backward_targets` go first!
    // The intended target line (zero offset) is part of `backward_targets`,
    // so that a positive offset in `forward_targets` (e.g. +5) is tried
    // before the corresponding negative offsets (e.g. -5).
    for possible_target_line in backward_targets.interleave(forward_targets) {
        if matches(&remove_content, &modified_file.content, possible_target_line) {
            best_target_line = Some(possible_target_line);
            break;
        }
    }

    // Did we find the line or not?
    let target_line = match best_target_line {
        Some(new_target_line) => new_target_line,
        None => {
            return HunkApplyReport::Failed(HunkApplyFailureReason::NoMatchingLines);
        }
    };

    // Check that we are not modifying frozen content
    if target_line + (hunk_view.prefix_context() as isize) < min_modify_line {
        return HunkApplyReport::Failed(HunkApplyFailureReason::MisorderedHunks);
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
    FileDoesNotExist,
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
        if let HunkApplyReport::Failed(..) = hunk_report {
            self.any_failed = true;
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

pub type HunksVec<'a, Line> = Vec<Hunk<'a, Line>>;

/// This represents all changes done to single file.
#[derive(Builder, Clone, Debug)]
#[builder(pattern = "owned")] // The pattern = "owned" is important to prevent clone in the final build function!
pub struct FilePatch<'a, Line> {
    /// Does it create, delete or modify a file?
    kind: FilePatchKind,

    /// The old filename (e.g. after --- line)
    /// It may be a `Path` wrapping a byte slice from the original patch file, or owned `PathBuf` if
    /// byte slice was not possible.
    #[builder(default)]
    old_filename: Option<Cow<'a, Path>>,

    /// The new filename (e.g. after +++ line)
    /// It may be a `Path` wrapping a byte slice from the original patch file, or owned `PathBuf` if
    /// byte slice was not possible.
    #[builder(default)]
    new_filename: Option<Cow<'a, Path>>,

    #[builder(default)]
    is_rename: bool,

    /// The old permissions, if any were mentioned in the patch
    #[builder(default)]
    old_permissions: Option<fs::Permissions>,

    /// The new permissions, if any were mentioned in the patch
    #[builder(default)]
    new_permissions: Option<fs::Permissions>,

    /// The old object hash, if this was a git-style patch
    #[builder(default)]
    old_hash: Option<&'a [u8]>,

    /// The new object hash, if this was a git-style patch
    #[builder(default)]
    new_hash: Option<&'a [u8]>,

    #[builder(default)]
    hunks: HunksVec<'a, Line>,
}

impl<'a, Line> FilePatch<'a, Line> {
    pub fn kind(&self) -> FilePatchKind { self.kind }

    pub fn old_filename(&self) -> Option<&Cow<'a, Path>> { self.old_filename.as_ref() }
    pub fn new_filename(&self) -> Option<&Cow<'a, Path>> { self.new_filename.as_ref() }

    #[allow(dead_code)]
    pub fn is_rename(&self) -> bool { self.is_rename }

    #[allow(dead_code)]
    pub fn old_permissions(&self) -> Option<&fs::Permissions> { self.old_permissions.as_ref() }
    #[allow(dead_code)]
    pub fn new_permissions(&self) -> Option<&fs::Permissions> { self.new_permissions.as_ref() }

    pub fn old_hash(&self) -> Option<&[u8]> { self.old_hash }
    pub fn new_hash(&self) -> Option<&[u8]> { self.new_hash }

    pub fn hunks(&self) -> &[Hunk<'a, Line>] { &self.hunks }

    /// Strip the leading path from the filename and new_filename
    pub fn strip(&mut self, strip: usize) {
        fn strip_path(path: &mut Cow<Path>, strip: usize) {
            match path {
                // TODO: De-duplicate code in those two branches?
                Cow::Owned(pathbuf) => {
                    let mut components = pathbuf.components();
                    for _ in 0..strip { components.next(); }
                    *path = Cow::Owned(components.as_path().to_path_buf());
                }
                Cow::Borrowed(path_ref) => {
                    let mut components = path_ref.components();
                    for _ in 0..strip { components.next(); }
                    *path = Cow::Borrowed(components.as_path());
                }
            }

            // TODO: Handle error if it is too short!
        }

        if let Some(old_filename) = &mut self.old_filename {
            strip_path(old_filename, strip);
        }
        if let Some(new_filename) = &mut self.new_filename {
            strip_path(new_filename, strip);
        }
    }

    /// Return the maximum fuzz that can be applied to this file patch. Applying
    /// more has no effect because there would be no more context lines to ignore.
    pub fn max_useable_fuzz(&self) -> usize {
        self.hunks.iter().map(Hunk::max_useable_fuzz).max().unwrap_or(0)
    }
}

pub type TextFilePatch<'a> = FilePatch<'a, &'a [u8]>;

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

impl<'a> TextFilePatch<'a> {
    /// Apply (or revert - based on `direction`) this patch to the `modified_file` using the given `fuzz`.
    pub fn apply(&self,
                 modified_file: &mut ModifiedFile<'a>,
                 direction: PatchDirection,
                 fuzz: usize,
                 analyses: &AnalysisSet,
                 fn_analysis_note: &dyn Fn(&dyn Note, &TextFilePatch))
                 -> FilePatchApplyReport
    {
        // Call the appropriate specialized function
        let mut report = match (self.kind, direction) {
            (FilePatchKind::Modify, _) =>
                self.apply_modify(modified_file, direction, fuzz, analyses, fn_analysis_note),

            (FilePatchKind::Create, PatchDirection::Forward) |
            (FilePatchKind::Delete, PatchDirection::Revert) =>
                self.apply_create(modified_file, direction, fuzz),

            (FilePatchKind::Delete, PatchDirection::Forward) |
            (FilePatchKind::Create, PatchDirection::Revert) =>
                self.apply_delete(modified_file, direction, fuzz),
        };

        // Determine the new file mode and record the previous one
        let change_permissions_to = match direction {
            PatchDirection::Forward => &self.new_permissions,
            PatchDirection::Revert => &self.old_permissions,
        };
        report.previous_permissions = match change_permissions_to {
            Some(permissions) =>
                modified_file.permissions.replace(permissions.clone()),

            None =>
                modified_file.permissions.clone(),
        };

        report
    }

    /// Apply this `FilePatchKind::Create` patch on the file.
    fn apply_create(&self,
                    modified_file: &mut ModifiedFile<'a>,
                    direction: PatchDirection,
                    fuzz: usize)
                    -> FilePatchApplyReport
    {
        assert!(self.hunks.len() == 1);

        // If we are creating it, it must be empty.
        if !modified_file.content.is_empty() {
            return FilePatchApplyReport::single_hunk_failure(HunkApplyFailureReason::CreatingFileThatExists, direction, fuzz);
        }

        let new_content = match direction {
            PatchDirection::Forward => &self.hunks[0].add.content,
            PatchDirection::Revert => &self.hunks[0].remove.content,
        };

        // Just copy in it the content of our single hunk and we are done.
        modified_file.content = new_content.clone();
        modified_file.deleted = false;

        FilePatchApplyReport::single_hunk_success(0, 0, new_content.len() as isize, direction, fuzz)
    }

    /// Apply this `FilePatchKind::Delete` patch on the file.
    fn apply_delete(&self,
                    modified_file: &mut ModifiedFile,
                    direction: PatchDirection,
                    fuzz: usize)
                    -> FilePatchApplyReport
    {
        assert!(self.hunks.len() == 1);

        let expected_content = match direction {
            PatchDirection::Forward => &self.hunks[0].remove.content,
            PatchDirection::Revert => &self.hunks[0].add.content,
        };

        // If we are deleting it, it must contain exactly what we want to remove.
        if expected_content != &modified_file.content {
            return FilePatchApplyReport::single_hunk_failure(HunkApplyFailureReason::DeletingFileThatDoesNotMatch, direction, fuzz);
        }

        // Just delete everything and we are done
        modified_file.content.clear();
        let target_filename = match direction {
            PatchDirection::Forward => &self.new_filename,
            PatchDirection::Revert => &self.old_filename,
        };
        match target_filename {
            None => modified_file.deleted = true,
            Some(_) => (),
        };

        FilePatchApplyReport::single_hunk_success(0, 0, -(expected_content.len() as isize), direction, fuzz)
    }

    /// Apply this `FilePatchKind::Modify` patch on the file.
    fn apply_modify(&self,
                    modified_file: &mut ModifiedFile<'a>,
                    direction: PatchDirection,
                    fuzz: usize,
                    analyses: &AnalysisSet,
                    fn_analysis_note: &dyn Fn(&dyn Note, &TextFilePatch))
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
        let mut min_modify_line = 0isize;

        // This function is applied on every hunk one by one, either from beginning
        // to end, or the opposite way (depends if we are applying or reverting)
        for hunk in self.hunks.iter() {
            let mut hunk_report = HunkApplyReport::Skipped;

            // Consider fuzz 0 up to given maximum fuzz, but no more than what is useable for this hunk
            for current_fuzz in 0..=min(fuzz, hunk.max_useable_fuzz()) {
                // Attempt to apply the hunk at the right fuzz level...
                let hunk_view = &hunk.view(direction, current_fuzz);

		let remove_content = hunk_view.remove_content();
		let target_line = match hunk_view.position() {
		    HunkPosition::Start => hunk_view.remove_target_line(),

		    // man patch:
		    // "As a first guess, [patch] takes the line number
		    // mentioned for the hunk, plus or minus any offset
		    // used in applying the previous hunk.."
		    HunkPosition::Middle => hunk_view.remove_target_line() + last_hunk_offset,

		    HunkPosition::End => modified_file.content.len() as isize - remove_content.len() as isize,
		};

                hunk_report = try_apply_hunk(hunk_view, modified_file,
                                             ApplyMode::Normal, target_line,
					     min_modify_line);

                // If it succeeded, we are done with this hunk, remember the last_hunk_offset
                // and min_modify_line, so we can use them for the next hunk and do not try
                // any more fuzz levels.
                if let HunkApplyReport::Applied { line, offset, .. } = hunk_report {
                    last_hunk_offset = offset;
                    min_modify_line = line + remove_content.len() as isize - hunk_view.suffix_context() as isize;
                    break;
                }
            }
            report.push_hunk_report(hunk_report);
        }

        analyses.before_modifications(modified_file, self, direction, &report, fn_analysis_note);

        // Now apply all changes on the file.
        // TODO: Do some more efficient than multiple `Vec::splice`s? The problem with multiple
        //       splices is that they move the tail of the file multiple times. Alternative is to
        //       generate new Vec and copy every Line at most once, but that seems to be even
        //       slower. Ideally we would need some in-place modification that moves every Line
        //       at most once. But I don't think it is possible in general case.
        {
            let mut modification_offset = 0;
            for (hunk, hunk_report) in self.hunks.iter().zip(report.hunk_reports.iter_mut()) {
                if let HunkApplyReport::Applied { line, ref mut rollback_line, fuzz, line_count_diff, .. } = hunk_report {
                    let hunk_view = hunk.view(direction, *fuzz);
                    let target_line = *line + modification_offset;
                    *rollback_line = target_line;
		    let prefix_len = hunk_view.prefix_context();
		    let suffix_len = hunk_view.suffix_context();
                    let range = (target_line as usize + prefix_len)..(target_line as usize + hunk_view.remove_content().len() - suffix_len);
                    modified_file.content.splice(range, hunk_view.add_content()[prefix_len..(hunk_view.add_content().len() - suffix_len)].iter().cloned()); // Note: cloned just makes `&[u8]` out of `&&[u8]`, no real cloning here.

                    modification_offset += *line_count_diff;
                }
            }
        }

        analyses.after_modifications(modified_file, self, direction, &report, fn_analysis_note);

        report
    }

    /// Rollback the application (or the revertion - based on direction) of this patch from the `modified_file`
    /// using the information from the `apply_report`.
    pub fn rollback(&self,
                    modified_file: &mut ModifiedFile<'a>,
                    direction: PatchDirection,
                    apply_report: &FilePatchApplyReport)
    {
        assert!(self.hunks.len() == apply_report.hunk_reports().len());

	let direction = direction.opposite();

        // Call the appropriate specialized function
        let mut report = match (self.kind, direction) {
            (FilePatchKind::Modify, _) =>
                self.rollback_modify(modified_file, direction, apply_report),

            (FilePatchKind::Create, PatchDirection::Forward) |
            (FilePatchKind::Delete, PatchDirection::Revert) =>
                self.rollback_create(modified_file, direction, apply_report),

            (FilePatchKind::Delete, PatchDirection::Forward) |
            (FilePatchKind::Create, PatchDirection::Revert) =>
                self.rollback_delete(modified_file, direction, apply_report),
        };

        // Rollback must apply cleanly. If not, we have a bug somewhere.
        if report.failed() {
            panic!("Rapidquilt attempted to rollback a patch and that failed. This is a bug. Failure report: {:?}", report);
        }

        // Determine the new file mode and record the previous one
        let permissions = &apply_report.previous_permissions;
        modified_file.permissions = permissions.clone();
	report.previous_permissions = permissions.clone();
    }

    /// Roll back this `FilePatchKind::Create` patch on the file.
    fn rollback_create(&self,
                    modified_file: &mut ModifiedFile<'a>,
                    direction: PatchDirection,
                    apply_report: &FilePatchApplyReport)
                    -> FilePatchApplyReport
    {
        assert!(self.hunks.len() == 1);

        if let HunkApplyReport::Failed(..) = apply_report.hunk_reports()[0] {
            return FilePatchApplyReport::single_hunk_skip(direction, 0);
	}

        // If we are creating it, it must be empty.
        if !modified_file.content.is_empty() {
            return FilePatchApplyReport::single_hunk_failure(HunkApplyFailureReason::CreatingFileThatExists, direction, 0);
        }

        let new_content = match direction {
            PatchDirection::Forward => &self.hunks[0].add.content,
            PatchDirection::Revert => &self.hunks[0].remove.content,
        };

        // Just copy in it the content of our single hunk and we are done.
        modified_file.content = new_content.clone();
        modified_file.deleted = false;

        FilePatchApplyReport::single_hunk_success(0, 0, new_content.len() as isize, direction, 0)
    }

    /// Roll back this `FilePatchKind::Delete` patch on the file.
    fn rollback_delete(&self,
                    modified_file: &mut ModifiedFile,
                    direction: PatchDirection,
                    apply_report: &FilePatchApplyReport)
                    -> FilePatchApplyReport
    {
        assert!(self.hunks.len() == 1);

        if let HunkApplyReport::Failed(..) = apply_report.hunk_reports()[0] {
            return FilePatchApplyReport::single_hunk_skip(direction, 0);
        }

        let expected_content = match direction {
            PatchDirection::Forward => &self.hunks[0].remove.content,
            PatchDirection::Revert => &self.hunks[0].add.content,
        };

        // If we are deleting it, it must contain exactly what we want to remove.
        if expected_content != &modified_file.content {
            return FilePatchApplyReport::single_hunk_failure(HunkApplyFailureReason::DeletingFileThatDoesNotMatch, direction, 0);
        }

        // Just delete everything and we are done
        modified_file.content.clear();
        let target_filename = match direction {
            PatchDirection::Forward => &self.new_filename,
            PatchDirection::Revert => &self.old_filename,
        };
        match target_filename {
            None => modified_file.deleted = true,
            Some(_) => (),
        };

        FilePatchApplyReport::single_hunk_success(0, 0, -(expected_content.len() as isize), direction, 0)
    }

    /// Roll back this `FilePatchKind::Modify` patch on the file.
    fn rollback_modify(&self,
                    modified_file: &mut ModifiedFile<'a>,
                    direction: PatchDirection,
                    apply_report: &FilePatchApplyReport)
                    -> FilePatchApplyReport
    {
        let mut report = FilePatchApplyReport::new_with_capacity(direction, 0, self.hunks.len());

        // This function is applied on every hunk one by one, either from beginning
        // to end, or the opposite way (depends if we are applying or reverting)
        for (i, hunk) in self.hunks.iter().enumerate() {
            let mut hunk_report = HunkApplyReport::Skipped;

            let (fuzz, rollback_line) =
		match apply_report.hunk_reports[i] {
                    // If the hunk applied, pick the specific fuzz level
                    HunkApplyReport::Applied { fuzz, rollback_line, .. } => (fuzz, rollback_line),

                    // If the hunk failed to apply, skip it now.
                    HunkApplyReport::Failed(..) |
                    HunkApplyReport::Skipped => {
			// Skip it
			report.push_hunk_report(hunk_report);
			continue;
                    }
		};

            // Attempt to apply the hunk at the right fuzz level...
            let hunk_view = &hunk.view(direction, fuzz);

            hunk_report = try_apply_hunk(hunk_view, modified_file,
                                         ApplyMode::Rollback(apply_report),
					 rollback_line, 0);
            report.push_hunk_report(hunk_report);
        }

        // Now apply all changes on the file.
        // TODO: Do some more efficient than multiple `Vec::splice`s? The problem with multiple
        //       splices is that they move the tail of the file multiple times. Alternative is to
        //       generate new Vec and copy every Line at most once, but that seems to be even
        //       slower. Ideally we would need some in-place modification that moves every Line
        //       at most once. But I don't think it is possible in general case.
        {
            let mut modification_offset = 0;
            for (hunk, hunk_report) in self.hunks.iter().zip(report.hunk_reports.iter_mut()) {
                if let HunkApplyReport::Applied { line, ref mut rollback_line, fuzz, line_count_diff, .. } = hunk_report {
                    let hunk_view = hunk.view(direction, *fuzz);
                    let target_line = *line + modification_offset;
                    *rollback_line = target_line;
		    let prefix_len = hunk_view.prefix_context();
		    let suffix_len = hunk_view.suffix_context();
                    let range = (target_line as usize + prefix_len)..(target_line as usize + hunk_view.remove_content().len() - suffix_len);
                    modified_file.content.splice(range, hunk_view.add_content()[prefix_len..(hunk_view.add_content().len() - suffix_len)].iter().cloned()); // Note: cloned just makes `&[u8]` out of `&&[u8]`, no real cloning here.

                    modification_offset += *line_count_diff;
                }
            }
        }

        report
    }
}

/// A single patch file
#[derive(Clone, Debug)]
pub struct Patch<'a, Line> {
    /// All "garbage" lines preceding the first FilePatch.
    /// These lines include the final new line character.
    pub header: &'a [u8],

    /// All FilePatches included in the patch file
    pub file_patches: Vec<FilePatch<'a, Line>>,
}

pub type TextPatch<'a> = Patch<'a, &'a [u8]>;
