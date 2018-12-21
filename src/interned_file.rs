// Licensed under the MIT license. See LICENSE.md

use std::io::{BufWriter, Write};

use failure::Error;

use crate::line_interner::{LineId, LineInterner};


#[derive(Clone, Debug)]
pub struct InternedFile {
    pub content: Vec<LineId>,
    pub existed: bool,
    pub deleted: bool,
}

const AVG_LINE_LENGTH: usize = 30; // Heuristics, for initial estimation of line count.

impl InternedFile {
    pub fn new<'a, 'b: 'a>(interner: &mut LineInterner<'a>, bytes: &'b [u8], existed: bool) -> Self {
        let mut content = Vec::with_capacity(bytes.len() / AVG_LINE_LENGTH);

        content.extend(
            bytes
            .split(|c| *c == b'\n')
            .map(|line| interner.add(line))
        );

        InternedFile {
            content,
            deleted: false,
            existed,
        }
    }

    pub fn new_non_existent() -> Self {
        InternedFile {
            content: Vec::new(),
            deleted: true,
            existed: false,
        }
    }

    /// Intended to be used when renaming files.
    /// This InternedFile must stay as record that the original was deleted,
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
        }
    }

    /// Intended to be used when renaming files.
    /// The content of this interned file is replaced by the `other` one, but
    /// only if this one was empty. Otherwise false is returned.
    pub fn move_in(&mut self, other: &mut InternedFile) -> bool {
        if self.content.len() > 0 && !self.deleted {
            return false;
        }

        std::mem::swap(&mut self.content, &mut other.content);
        other.deleted = true;
        self.deleted = false;
        // self.existed remains at it was

        true
    }

    pub fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), Error> {
        // Note: Even self.deleted files can be saved - quilt backup file for a file
        //       that did not exist is an empty file.

        let mut writer = BufWriter::new(writer);

        let mut line_ids = self.content.iter().peekable();
        while let Some(line_id) = line_ids.next() {
            writer.write(interner.get(*line_id).unwrap())?;
            if line_ids.peek().is_some() {
                writer.write(b"\n")?;
            }
        }
        Ok(())
    }
}
