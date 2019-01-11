// Licensed under the MIT license. See LICENSE.md

use std::fmt;
use std::path::{Path, PathBuf};

pub mod sequential;
pub mod parallel;
mod common;

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

#[derive(Debug)]
pub struct ApplyConfig<'a> {
    pub patch_filenames: &'a [PathBuf],
    pub patches_path: &'a Path,
    pub strip: usize,
    pub fuzz: usize,
    pub do_backups: ApplyConfigDoBackups,
    pub backup_count: ApplyConfigBackupCount,
    pub stats: bool,
}

#[derive(Debug)]
pub struct ApplyResult<'a> {
    pub applied_patches: &'a [PathBuf],
    pub skipped_patches: &'a [PathBuf],
}

#[derive(Debug, Fail)]
pub enum ApplyError {
    #[fail(display = "Failed to load patch {:?}", patch_filename)]
    PatchLoad { patch_filename: PathBuf },

    #[fail(display = "Failed to load file for patching: {:?}", filename)]
    LoadFileToPatch { filename: PathBuf },

    #[fail(display = "Failed to save modified file: {:?}", filename)]
    SaveModifiedFile { filename: PathBuf },

    #[fail(display = "Failed to save rejects file: {:?}", filename)]
    SaveRejectFile { filename: PathBuf },

    #[fail(display = "Failed to save quilt backup file: {:?}", filename)]
    SaveQuiltBackupFile { filename: PathBuf },
}
