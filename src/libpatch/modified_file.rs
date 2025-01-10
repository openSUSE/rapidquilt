// Licensed under the MIT license. See LICENSE.md

use std::fs::Permissions;
use std::io::{self, BufWriter, Write};

use crate::util::split_lines_with_endings;


/// This represents a file that have been modified by some patches.
/// Additionally it keeps information on whether the file originally existed
/// on disk and whether it was deleted.
#[derive(Clone, Debug)]
pub struct ModifiedFile<'a> {
    pub content: Vec<&'a [u8]>,

    /// Did the file originally existed on disk? This captures the original state on the disk, it
    /// is not changed by any patches.
    pub existed: bool,

    /// Was this file deleted? Also true if the file was not present since beginning. This can be
    /// changed by patches.
    pub deleted: bool,

    /// This tracks the permissions set by patches. It is `None` if no patch
    /// set any permissions. Note that the "patch" command does not check if
    /// the old permissions matched, so neither do we, therefore we don't have
    /// to query the permissions of the original file.
    pub permissions: Option<Permissions>,
}

const AVG_LINE_LENGTH: usize = 30; // Heuristics, for initial estimation of line count.

impl<'arena> ModifiedFile<'arena> {
    /// Create new `ModifiedFile` with lines from given `bytes`.
    pub fn new(bytes: &'arena [u8], existed: bool, permissions: Option<Permissions>) -> Self {
        let mut content = Vec::with_capacity(bytes.len() / AVG_LINE_LENGTH);

        content.extend(
            split_lines_with_endings(bytes)
        );

        Self {
            content,
            deleted: false,
            existed,
            permissions,
        }
    }

    /// Create new empty `ModifiedFile`
    pub fn new_non_existent() -> Self {
        Self {
            content: Vec::new(),
            deleted: true,
            existed: false,
            permissions: None,
        }
    }

    /// Intended to be used when renaming files.
    /// This ModifiedFile must stay as a record that the original was deleted,
    /// but the content is taken away.
    pub fn move_out(&mut self) -> Self {
        let mut out_content = Vec::new();
        std::mem::swap(&mut self.content, &mut out_content);

        self.deleted = true;
        // self.existed remains as it was

        Self {
            content: out_content,
            deleted: false,
            existed: false,
            permissions: self.permissions.take(),
        }
    }

    /// Intended to be used when renaming files.
    /// The content of this modified file is replaced by the `other` one, but
    /// only if this one was empty. Otherwise false is returned.
    pub fn move_in(&mut self, other: &mut ModifiedFile<'arena>) -> bool {
        if !self.content.is_empty() && !self.deleted {
            return false;
        }

        std::mem::swap(&mut self.content, &mut other.content);
        other.deleted = true;
        self.deleted = false;
        // self.existed remains at it was

        self.permissions = other.permissions.take();

        true
    }

    /// Write this file into given `writer`.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        // Note: Even self.deleted files can be saved - quilt backup file for a file
        //       that did not exist is an empty file.

        let mut writer = BufWriter::new(writer);

        for line in &self.content {
            writer.write_all(line)?;
        }

        Ok(())
    }
}
