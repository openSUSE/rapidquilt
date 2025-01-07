// Licensed under the MIT license. See LICENSE.md

use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub mod sequential;
pub mod parallel;
mod common;
mod diagnostics;

pub use self::sequential::apply_patches;
pub use self::parallel::apply_patches as apply_patches_parallel;



#[derive(Debug, PartialEq)]
pub enum ApplyConfigDoBackups {
    Always,
    OnFail,
    Never,
}

#[derive(Debug, PartialEq)]
pub enum ApplyConfigBackupCount {
    All,
    Last(usize),
}

impl fmt::Display for ApplyConfigBackupCount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ApplyConfigBackupCount::All => write!(f, "all"),
            ApplyConfigBackupCount::Last(n) => write!(f, "last {}", n),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    // Ordered from most silent to most verbose
    Quiet,
    Normal,
    Verbose,
    ExtraVerbose,
}

#[derive(Debug)]
pub struct SeriesPatch {
    pub filename: PathBuf,
    pub strip: usize,
    pub reverse: bool,
}

#[derive(Debug)]
pub struct ApplyConfig<'a> {
    pub base_dir: &'a Path,
    pub series_patches: &'a [SeriesPatch],
    pub patches_path: &'a Path,
    pub fuzz: usize,
    pub do_backups: ApplyConfigDoBackups,
    pub backup_count: ApplyConfigBackupCount,
    pub dry_run: bool,
    pub stats: bool,
    pub verbosity: Verbosity,
}

#[derive(Debug)]
pub struct ApplyResult {
    pub applied_patches: usize,
    pub skipped_patches: usize,
}

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("Failed to load patch {patch_filename:?}")]
    PatchLoad { patch_filename: PathBuf },

    #[error("Failed to load file for patching: {filename:?}")]
    LoadFileToPatch { filename: PathBuf },

    #[error("Failed to save modified file: {filename:?}")]
    SaveModifiedFile { filename: PathBuf },

    #[error("Failed to save rejects file: {filename:?}")]
    SaveRejectFile { filename: PathBuf },

    #[error("Failed to save quilt backup file: {filename:?}")]
    SaveQuiltBackupFile { filename: PathBuf },
}
