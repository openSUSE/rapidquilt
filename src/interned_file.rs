use std::io::Write;

use failure::Error;

use crate::line_interner::{LineId, LineInterner};


#[derive(Clone, Debug)]
pub struct InternedFile {
    pub content: Vec<LineId>
}

const AVG_LINE_LENGTH: usize = 30; // Heuristics, for initial estimation of line count.

impl InternedFile {
    pub fn new<'a, 'b: 'a>(interner: &mut LineInterner<'a>, bytes: &'b [u8]) -> Self {
        let mut content = Vec::with_capacity(bytes.len() / AVG_LINE_LENGTH);

        content.extend(
            bytes
            .split(|c| *c == b'\n')
            .map(|line| interner.add(line))
        );

        InternedFile {
            content
        }
    }

    pub fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), Error> {
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
