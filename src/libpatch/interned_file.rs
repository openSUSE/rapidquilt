// Licensed under the MIT license. See LICENSE.md

use std::fs::Permissions;
use std::io::{self, BufWriter, Write};

use crate::line_interner::{LineId, LineInterner};
use crate::util::split_lines_with_endings;


/// This represents a file that had lines interned by an interner.
/// Additionally it keeps information on whether the file originally existed
/// on disk and whether it was deleted.
#[derive(Clone, Debug)]
pub struct InternedFile {
    pub content: Vec<LineId>,

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

impl InternedFile {
    /// Create new `InternedFile` by interning given `bytes` using the `interner`.
    pub fn new<'a, 'b: 'a>(interner: &mut LineInterner<'a>, bytes: &'b [u8], existed: bool) -> Self {
        let mut content = Vec::with_capacity(bytes.len() / AVG_LINE_LENGTH);

        content.extend(
            split_lines_with_endings(bytes)
            .map(|line| interner.add(line))
        );

        InternedFile {
            content,
            deleted: false,
            existed,
            permissions: None,
        }
    }

    /// Create new empty `InternedFile`
    pub fn new_non_existent() -> Self {
        InternedFile {
            content: Vec::new(),
            deleted: true,
            existed: false,
            permissions: None,
        }
    }

    /// Intended to be used when renaming files.
    /// This InternedFile must stay as a record that the original was deleted,
    /// but the content is taken away.
    pub fn move_out(&mut self) -> Self {
        let mut out_content = Vec::new();
        std::mem::swap(&mut self.content, &mut out_content);

        self.deleted = true;
        // self.existed remains as it was

        InternedFile {
            content: out_content,
            deleted: false,
            existed: false,
            permissions: self.permissions.take(),
        }
    }

    /// Intended to be used when renaming files.
    /// The content of this interned file is replaced by the `other` one, but
    /// only if this one was empty. Otherwise false is returned.
    pub fn move_in(&mut self, other: &mut InternedFile) -> bool {
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

    /// Write this file into given `writer` using lines from the `interner`.
    ///
    /// # Panic
    ///
    /// Panics if the interner is not the one originally used for creating
    /// this file.
    pub fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error> {
        // Note: Even self.deleted files can be saved - quilt backup file for a file
        //       that did not exist is an empty file.

        let mut writer = BufWriter::new(writer);

        for line_id in &self.content {
            writer.write_all(interner.get(*line_id).unwrap())?; // NOTE(unwrap): It must be in the interner, otherwise we panick
        }

        Ok(())
    }
}
