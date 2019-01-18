// Licensed under the MIT license. See LICENSE.md

use std::fs::Permissions;
use std::io::{self, BufWriter, Write};

use crate::line::Line;
use crate::util::split_lines_with_endings;


/// This represents a file that was modified by some patches. It keeps the
/// lines from the file and information on whether the file originally existed
/// on disk and whether it was deleted.
#[derive(Clone, Debug)]
pub struct ModifiedFile<L> {
    pub content: Vec<L>,
    pub existed: bool,
    pub deleted: bool,

    /// This tracks the permissions set by patches. It is `None` if no patch
    /// set any permissions. Note that the "patch" command does not check if
    /// the old permissions matched, so neither do we, therefore we don't have
    /// to query the permissions of the original file.
    pub permissions: Option<Permissions>,
}

const AVG_LINE_LENGTH: usize = 30; // Heuristics, for initial estimation of line count.

impl<'a, L: Line<'a>> ModifiedFile<L> {
    /// Create new `ModifiedFile` from given `bytes`
    pub fn new<'b: 'a>(bytes: &'b [u8], existed: bool) -> Self {
        let mut content = Vec::with_capacity(bytes.len() / AVG_LINE_LENGTH);

        content.extend(
            split_lines_with_endings(bytes)
            .map(|bytes| L::from(bytes))
        );

        ModifiedFile {
            content,
            deleted: false,
            existed,
            permissions: None,
        }
    }

    /// Create new empty `ModifiedFile`
    pub fn new_non_existent() -> Self {
        ModifiedFile {
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

        ModifiedFile {
            content: out_content,
            deleted: false,
            existed: false,
            permissions: self.permissions.take(),
        }
    }

    /// Intended to be used when renaming files.
    /// The content of this modified file is replaced by the `other` one, but
    /// only if this one was empty. Otherwise false is returned.
    pub fn move_in(&mut self, other: &mut Self) -> bool {
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
            writer.write_all((*line).into())?;
        }

        Ok(())
    }
}
