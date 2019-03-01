// Licensed under the MIT license. See LICENSE.md

use std::cell::{Ref, RefCell};
use std::fs::Permissions;
use std::io::{self, BufWriter, Write};
use std::ops::Range;

use memchr::{memchr, memchr_iter};

use crate::line::LineId;
use crate::line_interner::LineInterner;
use crate::util::HayStack;
use std::ops::RangeFull;
use std::ops::RangeBounds;


// TODO: IDEA: Just keep simple (original_before, modified_interned, original_after)


#[derive(Clone, Debug)]
pub struct InternedFileContent<'arena: 'interner, 'interner> {
    /// Slice of the full content of the original file stored in Arena. This is used for lines that
    /// are in `LineOffset` form. It may happen that all lines get converted to `LineId` form and
    /// this becomes irrelevant.
    bytes: &'arena [u8],

    interner: &'interner RefCell<LineInterner<'arena>>,

    lines: RefCell<Vec<LineId>>,
}

impl<'arena: 'interner, 'interner> InternedFileContent<'arena, 'interner> {
    pub fn new(bytes: &'arena [u8], interner: &'interner RefCell<LineInterner<'arena>>) -> Self {
        let mut lines = Vec::with_capacity(bytes.len() / AVG_LINE_LENGTH);

        lines.push(LineId::from_offset(0));
        lines.extend(
            memchr_iter(b'\n', bytes)
            .map(|offset| {
                LineId::from_offset(offset as u64 + 1)
            })
        );

        if lines.last() == Some(&LineId::from_offset(bytes.len() as u64)) {
            lines.pop();
        }

        InternedFileContent {
            bytes,
            interner,
            lines: RefCell::new(lines),
        }
    }

    pub fn new_empty(interner: &'interner RefCell<LineInterner<'arena>>) -> Self {
        Self::new(&[], interner)
    }

    pub fn len(&self) -> usize {
        self.lines.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&mut self) {
        self.lines.borrow_mut().clear();
    }

    pub fn replace_all_lines(&mut self, lines: Vec<LineId>) {
        self.lines.replace(lines);
    }

    pub fn replace_lines<R>(&mut self, range: R, replace_with: Vec<LineId>)
    where R: RangeBounds<usize>
    {
        self.lines.borrow_mut().splice(range, replace_with);
    }

    fn line_known_as_offset_line(&self, index: usize) -> &'arena [u8] {
        let borrowed_lines = self.lines.borrow();

        let line_offset: usize = borrowed_lines[index].as_offset() as usize;
        let next_line_offset: usize = if index + 1 < borrowed_lines.len() {
            // ... this is not the last line, so there is a next line, check if it was already interned or not ...
            let next_line = borrowed_lines[index + 1];
            if next_line.is_offset() {
                // ... it wasn't interned yet, we can take its offset
                next_line.as_offset() as usize
            } else {
                // ... it was already interned, we must search for '\n' ourselves
                line_offset + 1 + memchr(b'\n', &self.bytes[line_offset..]).unwrap() // NOTE(unwrap): We know there must be one more '\n' because we know there is one more line
            }
        } else {
            // ... this is the last line, so we just take the end of the file as offset of the next line
            self.bytes.len()
        };

        &self.bytes[line_offset..next_line_offset]
    }

    pub fn line(&self, index: usize) -> &'arena [u8] {
        // Get the line. This will panic if it is out of bounds
        let line_id = self.lines.borrow()[index];

        // If it is interned, get the line from interner
        if line_id.is_line_id() {
            return self.interner.borrow().get(line_id).unwrap(); // NOTE(unwrap): It must be there, we placed it in there.
        }

        self.line_known_as_offset_line(index)
    }
}

impl<'arena: 'interner, 'interner> HayStack<LineId> for InternedFileContent<'arena, 'interner> {
    fn len(&self) -> usize {
        self.len()
    }

    fn get(&self, index: usize) -> LineId {
        // If it is already in line_id form, return it
        let line_id = self.lines.borrow()[index];
        if line_id.is_line_id() {
            return line_id;
        }

        // Otherwise it is in offset form and we must intern it
        let line = self.line_known_as_offset_line(index);
//        println!("Adding index {} line {:?}", index, line);
        let line_id = self.interner.borrow_mut().add(line);

        // Remember it for future
        self.lines.borrow_mut()[index] = line_id;

        // And return it
        line_id
    }

    fn slice(&self, range: Range<usize>) -> Ref<[LineId]> {
        for i in range.clone() {
            self.get(i);
        }

        Ref::map(self.lines.borrow(), |lines| &lines[range])
    }

    fn full_slice(&self) -> Ref<[LineId]> {
        for i in 0..self.len() {
            self.get(i);
        }

        Ref::map(self.lines.borrow(), |lines| &lines[..])
    }
}


/// This represents a file that had lines interned by an interner.
/// Additionally it keeps information on whether the file originally existed
/// on disk and whether it was deleted.
#[derive(Clone, Debug)]
pub struct InternedFile<'arena: 'interner, 'interner> {
    pub content: InternedFileContent<'arena, 'interner>,

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

impl<'arena: 'interner, 'interner> InternedFile<'arena, 'interner> {
    /// Create new `InternedFile` by interning given `bytes` using the `interner`.
    pub fn new(interner: &'interner RefCell<LineInterner<'arena>>, bytes: &'arena [u8], existed: bool) -> Self {
        let content = InternedFileContent::new(bytes, interner);

//        content.extend(
//            split_lines_with_endings(bytes)
//            .map(|line| interner.add(line))
//        );

        InternedFile {
            content,
            deleted: false,
            existed,
            permissions: None,
        }
    }

    /// Create new empty `InternedFile`
    pub fn new_non_existent(interner: &'interner RefCell<LineInterner<'arena>>) -> Self {
        let content = InternedFileContent::new_empty(interner);

        InternedFile {
            content,
            deleted: true,
            existed: false,
            permissions: None,
        }
    }

    /// Intended to be used when renaming files.
    /// This InternedFile must stay as a record that the original was deleted,
    /// but the content is taken away.
    pub fn move_out(&mut self) -> Self {
        let mut out_content = InternedFileContent::new_empty(self.content.interner);
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
    pub fn move_in(&mut self, other: &mut InternedFile<'arena, 'interner>) -> bool {
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

        // TODO: Use unchanged range for start and end!

        for i in 0..self.content.len() {
            writer.write_all(self.content.line(i))?;
        }

//        for line_id in &self.content {
//            writer.write_all(interner.get(*line_id).unwrap())?; // NOTE(unwrap): It must be in the interner, otherwise we panick
//        }

        Ok(())
    }
}
