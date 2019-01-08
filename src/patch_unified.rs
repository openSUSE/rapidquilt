    static ref MINUS_FILENAME: Regex = Regex::new(r"^--- ([^\t]+)(\t[^\n]*)?\n$").unwrap();
    static ref PLUS_FILENAME: Regex = Regex::new(r"^\+\+\+ ([^\t]+)(\t[^\n]*)?\n$").unwrap();
pub trait UnifiedPatchHunkWriter {
    fn write_header_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error>;
    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error>;
}

impl<'a> UnifiedPatchHunkWriter for Hunk<'a, LineId> {
    fn write_header_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(self.place_name)?;

        Ok(())
    }

    fn write_to<W: Write>(&self, interner: &LineInterner, writer: &mut W) -> Result<(), io::Error> {
        self.write_header_to(writer)?;

        writer.write_all(b"\n")?;
            writer.write_all(&[c])?;
            writer.write_all(line)?;
                writer.write_all(b"\n")?;
                writer.write_all(NO_NEW_LINE_TAG)?;
        writer.write_all(b"--- ")?;
        writer.write_all(&NULL_FILENAME)?;
        writer.write_all(b"\n")?;
        writer.write_all(b"+++ ")?;
        writer.write_all(&NULL_FILENAME)?;
        writer.write_all(b"\n")?;