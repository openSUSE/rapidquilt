// Licensed under the MIT license. See LICENSE.md

use std::path::{Path, PathBuf};

mod sequential;
mod parallel;
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

#[derive(Debug)]
pub struct ApplyConfig<'a> {
    pub patch_filenames: &'a [PathBuf],
    pub patches_path: &'a Path,
    pub strip: usize,
    pub do_backups: ApplyConfigDoBackups,
    pub backup_count: ApplyConfigBackupCount,
}

#[derive(Debug)]
pub struct ApplyResult<'a> {
    pub applied_patches: &'a [PathBuf],
    pub skipped_patches: &'a [PathBuf],
}
