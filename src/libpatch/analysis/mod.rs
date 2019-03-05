use std::io::{self, Write};
use std::vec::Vec;

use crate::modified_file::ModifiedFile;
use crate::patch::{
    FilePatchApplyReport,
    TextFilePatch,
    PatchDirection,
};

use std::fmt::Debug;

mod multiapply;
pub use self::multiapply::*;


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NoteSeverity {
    Warning
    // TODO: Add more when needed
}

pub trait Note : Debug {
    /// The hunk this note belongs to, or `None` if it is not tied to a hunk.
    fn hunk(&self) -> Option<usize>;

    /// Clones itself into a `Box`. Use this if you need to type-erase the note for storage.
    fn boxed_clone(&self) -> Box<Note>;

    fn severity(&self) -> NoteSeverity;

    /// Write a diagnostic message to given `Write`
    fn write(&self, out: &mut dyn Write) -> Result<(), io::Error>;
}

pub trait Analysis: Sync {
    fn before_modifications(
        &self,
        _modified_file: &ModifiedFile,
        _file_patch: &TextFilePatch,
        _direction: PatchDirection,
        _report: &FilePatchApplyReport,
        _fn_analysis_note: &Fn(&dyn Note, &TextFilePatch))
        {}

    fn after_modifications(
        &self,
        _modified_file: &ModifiedFile,
        _file_patch: &TextFilePatch,
        _direction: PatchDirection,
        _report: &FilePatchApplyReport,
        _fn_analysis_note: &Fn(&dyn Note, &TextFilePatch))
        {}

    // TODO: Add more check points if needed.
}

#[derive(Default)]
pub struct AnalysisSet {
    analyses: Vec<Box<Analysis>>,
}

impl AnalysisSet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add(&mut self, analysis: Box<Analysis>) {
        self.analyses.push(analysis);
    }

    pub fn add_default<T: Analysis + Default + 'static>(&mut self) {
        self.add(Box::<T>::default())
    }
}

impl Analysis for AnalysisSet {
    fn before_modifications(
        &self,
        modified_file: &ModifiedFile,
        file_patch: &TextFilePatch,
        direction: PatchDirection,
        report: &FilePatchApplyReport,
        fn_analysis_note: &Fn(&dyn Note, &TextFilePatch))
    {
        for analysis in &self.analyses {
            analysis.before_modifications(
                modified_file, file_patch, direction, report,
                fn_analysis_note
            )
        }
    }

    fn after_modifications(
        &self,
        modified_file: &ModifiedFile,
        file_patch: &TextFilePatch,
        direction: PatchDirection,
        report: &FilePatchApplyReport,
        fn_analysis_note: &Fn(&dyn Note, &TextFilePatch))
    {
        for analysis in &self.analyses {
            analysis.after_modifications(
                modified_file, file_patch, direction, report,
                fn_analysis_note
            );
        }
    }
}

/// NOOP analysis function. Use this if you don't want any analysis printed out.
pub fn fn_analysis_note_noop(_note: &Note, _modified_filepatch: &TextFilePatch) {
}
