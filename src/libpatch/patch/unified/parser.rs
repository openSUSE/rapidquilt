// Licensed under the MIT license. See LICENSE.md

use std::fs::Permissions;
use std::path::PathBuf;
use std::str::FromStr;
use std::vec::Vec;

use failure::{Error, Fail};

use nom::*;
use nom::types::CompleteByteSlice;

use crate::patch::*;
use crate::patch::unified::*;



#[derive(Debug, Fail, PartialEq)]
pub enum ParseError {
    #[fail(display = "Unsupported metadata: \"{}\"", line)]
    UnsupportedMetadata { line: String },

    #[fail(display = "Could not figure out the filename for hunk \"{}\"", hunk_line)]
    MissingFilenameForHunk { hunk_line: String },

    #[fail(display = "Unexpected end of file")]
    UnexpectedEndOfFile,

    #[fail(display = "Unexpected line in the middle of hunk: \"{}\"", line)]
    BadLineInHunk { line: String },

    #[fail(display = "Number too big: \"{}\"", number_str)]
    NumberTooBig { number_str: String },

    #[fail(display = "Invalid mode: \"{}\"", mode_str)]
    BadMode { mode_str: String },

    #[fail(display = "Unknown parse failure: \"{:?}\" on line \"{}\"", inner, line)]
    Unknown { line: String, inner: nom::ErrorKind<u32> },
}

// XXX: This doesn't feel very rusty, but it seems to be the expected way to
// do things in nom?
#[repr(u32)]
#[derive(Debug)]
enum ParseErrorCode {
    UnsupportedMetadata,
    MissingFilenameForHunk,
    UnexpectedEndOfFile,
    BadLineInHunk,
    NumberTooBig,
    BadMode,
}

impl<'a> From<nom::Err<CompleteByteSlice<'a>>> for ParseError {
    fn from(err: nom::Err<CompleteByteSlice<'a>>) -> ParseError {
        let context = match err {
            nom::Err::Incomplete(_) => unreachable!(), // We always work with complete data.
            nom::Err::Error(context) | nom::Err::Failure(context) => context,
        };

        let (place, err_kind) = match context {
            nom::Context::Code(place, err_kind) => (place, err_kind),
        };

        let place_as_string = String::from_utf8_lossy(
            &take_until_newline(place).map(|a| a.1).unwrap_or(CompleteByteSlice(b"?"))
        ).to_string();

        let code = match err_kind {
            nom::ErrorKind::Custom(code) => code,
            _ => { return ParseError::Unknown { line: place_as_string, inner: err_kind }; }
        };

        match code {
            c if c == ParseErrorCode::UnsupportedMetadata as u32 => {
                ParseError::UnsupportedMetadata { line: place_as_string }
            }
            c if c == ParseErrorCode::MissingFilenameForHunk as u32 => {
                ParseError::MissingFilenameForHunk { hunk_line: place_as_string }
            }
            c if c == ParseErrorCode::UnexpectedEndOfFile as u32 => {
                ParseError::UnexpectedEndOfFile
            }
            c if c == ParseErrorCode::BadLineInHunk as u32 => {
                ParseError::BadLineInHunk { line: place_as_string }
            }
            c if c == ParseErrorCode::NumberTooBig as u32 => {
                ParseError::NumberTooBig { number_str: place_as_string }
            }
            c if c == ParseErrorCode::BadMode as u32 => {
                ParseError::BadMode { mode_str: place_as_string }
            }
            _ => {
                ParseError::Unknown { line: place_as_string, inner: err_kind }
            }
        }
    }
}

#[cfg(test)]
macro_rules! assert_parsed {
    ( $parse_func:ident, $input:expr, $result:expr ) => {
        {
            let ret = $parse_func(CompleteByteSlice($input));
            let ret = ret.map(|tuple| tuple.1); // We only care about the second item. This lets
                                                // allows us use assert_eq to check for Ok/Err and
                                                // the first value at once. That gives us good
                                                // failure messages.
            assert_eq!(ret.as_ref(), Ok(&$result));
        }
    };
}

#[cfg(test)]
macro_rules! assert_parse_error_code {
    ( $parse_func:ident, $input:expr, $err_code:expr ) => {
        {
            let ret = $parse_func(CompleteByteSlice($input));
            match ret {
                Err(nom::Err::Error(  nom::Context::Code(_, nom::ErrorKind::Custom(error_code)))) |
                Err(nom::Err::Failure(nom::Context::Code(_, nom::ErrorKind::Custom(error_code)))) => {
                    assert_eq!(error_code, $err_code);
                }

                _ => {
                    panic!("Parsing {:?}, got unexpected return: {:?}", $input, ret);
                }
            }
        }
    };
}

/// Shortcut to make slice from byte string literal
macro_rules! s { ( $byte_string:expr ) => { &$byte_string[..] } }

/// Shortcut to make single-element slice from byte
macro_rules! c { ( $byte:expr ) => { &[$byte][..] } }

fn is_space(c: u8) -> bool {
    c == b' ' ||
    c == b'\t'
}

fn is_whitespace(c: u8) -> bool {
    c == b' ' ||
    c == b'\n' ||
    c == b'\r' ||
    c == b'\t'
}

// The nom::newline is for &[u8], we need CompleteByteSlice
named!(newline<CompleteByteSlice, CompleteByteSlice>, tag!(c!(b'\n')));

named!(take_until_newline<CompleteByteSlice, CompleteByteSlice>, take_until!(c!(b'\n')));
named!(take_until_newline_incl<CompleteByteSlice, CompleteByteSlice>,
    // TODO: Better way?
    recognize!(pair!(call!(take_until_newline), take!(1)))
);

named!(parse_filename_direct<CompleteByteSlice, CompleteByteSlice>,
    take_till1!(is_whitespace)
);

/// Similar to `parse_c_string` function in patch.
named!(parse_filename_quoted<CompleteByteSlice, Vec<u8>>,
    do_parse!(
        tag!(c!(b'\"')) >>

        vec: escaped_transform!(
            take_while1!(|c| c != b'\"' && c != b'\n' && c != b'\\'),
            b'\\',
            alt!(
                tag!(c!(b'a'))  => { |_| vec![0x7_u8] }
              | tag!(c!(b'b'))  => { |_| vec![0x8_u8] }
              | tag!(c!(b'f'))  => { |_| vec![0xc_u8] }
              | tag!(c!(b'n'))  => { |_| vec![b'\n'] }
              | tag!(c!(b'r'))  => { |_| vec![b'\r'] }
              | tag!(c!(b't'))  => { |_| vec![b'\t'] }
              | tag!(c!(b'v'))  => { |_| vec![0xb_u8] }
              | tag!(c!(b'\\')) => { |_| vec![b'\\'] }
              | tag!(c!(b'\"')) => { |_| vec![b'\"'] }
              | do_parse!(
                  digit_0: one_of!(s!(b"0123")) >>
                  digit_1: one_of!(s!(b"0123456789")) >>
                  digit_2: one_of!(s!(b"0123456789")) >>

                  (((digit_0 as u8 - b'0') << 6) + ((digit_1 as u8 - b'0') << 3) + (digit_2 as u8 - b'0'))
                ) => { |c| vec![c] }
            )
        ) >>

        tag!(c!(b'\"')) >>

        (vec)
    )
);

#[derive(Debug, PartialEq)]
enum Filename {
    Real(PathBuf),
    DevNull,
}

#[cfg(unix)]
fn bytes_to_pathbuf(bytes: &[u8]) -> PathBuf {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    PathBuf::from(OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn bytes_to_pathbuf(bytes: &[u8]) -> PathBuf {
    // XXX: This may not work in case of some really weird paths (control characters
    //      and what not). But I guess those can not be legaly saved in patch files
    //      anyway.

    PathBuf::from(String::from_utf8_lossy(bytes).as_ref())
}


/// Parses a filename.
///
/// Either written directly without any whitespace or inside quotation marks.
///
/// Similar to `parse_name` function in patch.
named!(parse_filename<CompleteByteSlice, Filename>,
    do_parse!(
        take_while!(is_space) >>
        filename: alt!(
            // This looks like the same function is applied on both branches,
            // but one works with Vec, other with CompleteByteSlice...
            map!(parse_filename_quoted, |f| {
                if &f[..] == NULL_FILENAME {
                    Filename::DevNull
                } else {
                    Filename::Real(bytes_to_pathbuf(&f[..]))
                }
            }) |
            map!(parse_filename_direct, |f| {
                if &f[..] == NULL_FILENAME {
                    Filename::DevNull
                } else {
                    Filename::Real(bytes_to_pathbuf(&f[..]))
                }
            })
        ) >>
        (filename)
    )
);

#[cfg(test)]
#[test]
fn test_parse_filename() {
    fn assert_path(input: &[u8], result: &str) {
        assert_parsed!(parse_filename, input, Filename::Real(PathBuf::from(result)));
    }

    assert_path(b"aaa", "aaa");
    assert_path(b"      aaa", "aaa");
    assert_path(b"aaa\nbbb", "aaa");
    assert_path(b"aaa time", "aaa");

    assert_path(b"\"aaa\"", "aaa");
    assert_path(b"      \"aaa\"", "aaa");
    assert_path(b"\"aa aa\"", "aa aa");
    assert_path(b"\"aa\\\"aa\"", "aa\"aa");
    assert_path(b"\"aa\\\\aa\"", "aa\\aa");
    assert_path(b"\"aa\\naa\"", "aa\naa");

    assert_path(b"\"aa\\142aa\"", "aabaa");

    assert_parsed!(parse_filename, b"/dev/null", Filename::DevNull);
    assert_parsed!(parse_filename, b"\"/dev/null\"", Filename::DevNull);
}

/// Similar to `fetchmode` function in patch.
fn parse_mode(input: CompleteByteSlice) -> IResult<CompleteByteSlice, u32> {
    let (input, _) = take_while!(input, is_space)?;
    let (input, digits) = take_while1!(input, is_oct_digit)?;

    if digits.len() != 6 { // This is what patch requires, but otherwise it fallbacks to 0, so maybe we should too?
        return Err(nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::BadMode as u32))));
    }

    let mode_str = std::str::from_utf8(&digits).unwrap(); // NOTE(unwrap): We know it is just digits 0-7, so it is guaranteed to be valid UTF8.
    match u32::from_str_radix(mode_str, 8) {
        Ok(number) => Ok((input, number)),
        Err(_) => Err(nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::BadMode as u32)))),
    }
}

#[cfg(test)]
#[test]
fn test_parse_mode() {
    assert_parsed!(parse_mode, b"123456", 0o123456);
    assert_parsed!(parse_mode, b"012345", 0o12345);
    assert_parsed!(parse_mode, b"   123456", 0o123456);
    assert_parsed!(parse_mode, b"   012345", 0o12345);

    assert_parsed!(parse_mode, b"100755", 0o100755);
    assert_parsed!(parse_mode, b"100644", 0o100644);

    assert_parse_error_code!(parse_mode, b"100aaa", ParseErrorCode::BadMode as u32);
    assert_parse_error_code!(parse_mode, b"1", ParseErrorCode::BadMode as u32);
    assert_parse_error_code!(parse_mode, b"10000000", ParseErrorCode::BadMode as u32);
    assert_parse_error_code!(parse_mode, b"1000000000000000000000000000", ParseErrorCode::BadMode as u32);
}

#[derive(Debug, PartialEq)]
enum MetadataLine {
    GitDiffSeparator(Filename, Filename),

    MinusFilename(Filename),
    PlusFilename(Filename),

    OldMode(u32),
    NewMode(u32),
    DeleteFileMode(u32),
    NewFileMode(u32),

    RenameFrom,
    RenameTo,

    CopyFrom,
    CopyTo,

    GitBinaryPatch,

    // ...?
}

named!(parse_metadata_line<CompleteByteSlice, MetadataLine>,
    alt!(
        do_parse!(tag!(s!(b"diff --git ")) >> old_filename: parse_filename >> new_filename: parse_filename >> take_until_newline_incl >> (MetadataLine::GitDiffSeparator(old_filename, new_filename))) |

        do_parse!(tag!(s!(b"--- ")) >> filename: parse_filename >> take_until_newline_incl >> (MetadataLine::MinusFilename(filename))) |
        do_parse!(tag!(s!(b"+++ ")) >> filename: parse_filename >> take_until_newline_incl >> (MetadataLine::PlusFilename(filename))) |

        // The filename behind "rename to" and "rename from" is ignored by patch, so we ignore it too.
        do_parse!(tag!(s!(b"rename from ")) >> take_until_newline_incl >> (MetadataLine::RenameFrom)) |
        do_parse!(tag!(s!(b"rename to "))   >> take_until_newline_incl >> (MetadataLine::RenameTo)) |

        do_parse!(tag!(s!(b"copy from ")) >> take_until_newline_incl >> (MetadataLine::CopyFrom)) |
        do_parse!(tag!(s!(b"copy to "))   >> take_until_newline_incl >> (MetadataLine::CopyTo)) |

        do_parse!(tag!(s!(b"GIT binary patch")) >> take_until_newline_incl >> (MetadataLine::GitBinaryPatch)) |

        do_parse!(tag!(s!(b"old mode "))         >> mode: parse_mode >> newline >> (MetadataLine::OldMode(mode))) |
        do_parse!(tag!(s!(b"new mode "))         >> mode: parse_mode >> newline >> (MetadataLine::NewMode(mode))) |
        do_parse!(tag!(s!(b"delete file mode ")) >> mode: parse_mode >> newline >> (MetadataLine::DeleteFileMode(mode))) |
        do_parse!(tag!(s!(b"new file mode "))    >> mode: parse_mode >> newline >> (MetadataLine::NewFileMode(mode)))
    )
);

#[cfg(test)]
#[test]
fn test_parse_metadata_line() {
    use self::MetadataLine::*;

    // All of them in basic form
    assert_parsed!(parse_metadata_line, b"diff --git aaa bbb\n", GitDiffSeparator(Filename::Real(PathBuf::from("aaa")), Filename::Real(PathBuf::from("bbb"))));

    assert_parsed!(parse_metadata_line, b"--- aaa\n", MinusFilename(Filename::Real(PathBuf::from("aaa"))));
    assert_parsed!(parse_metadata_line, b"+++ aaa\n", PlusFilename(Filename::Real(PathBuf::from("aaa"))));

    assert_parsed!(parse_metadata_line, b"old mode 100644\n",         OldMode(0o100644));
    assert_parsed!(parse_metadata_line, b"new mode 100644\n",         NewMode(0o100644));
    assert_parsed!(parse_metadata_line, b"delete file mode 100644\n", DeleteFileMode(0o100644));
    assert_parsed!(parse_metadata_line, b"new file mode 100644\n",    NewFileMode(0o100644));

    assert_parsed!(parse_metadata_line, b"rename from blabla\n", RenameFrom);
    assert_parsed!(parse_metadata_line, b"rename to blabla\n", RenameTo);

    assert_parsed!(parse_metadata_line, b"copy from blabla\n", CopyFrom);
    assert_parsed!(parse_metadata_line, b"copy to blabla\n", CopyTo);

    assert_parsed!(parse_metadata_line, b"GIT binary patch ???\n", GitBinaryPatch);

    // Filename with date
    assert_parsed!(parse_metadata_line, b"--- a/bla/ble.c	2013-09-23 18:41:09.000000000 -0400\n", MinusFilename(Filename::Real(PathBuf::from("a/bla/ble.c"))));

}

#[derive(Debug, PartialEq)]
enum PatchLine {
    Garbage,
    Metadata(MetadataLine),
    StartOfHunk,
    EndOfPatch,
}

named!(parse_patch_line<CompleteByteSlice, PatchLine>,
    alt!(
        map!(parse_metadata_line, PatchLine::Metadata) |
        value!(PatchLine::StartOfHunk, peek!(parse_hunk_header)) |
        value!(PatchLine::Garbage, take_until_newline_incl) |
        value!(PatchLine::EndOfPatch, eof!())
    )
);

#[cfg(test)]
#[test]
fn test_parse_patch_line() {
    use self::PatchLine::*;
    use self::MetadataLine::*;

    assert_parsed!(parse_patch_line, b"diff --git aaa bbb\n", Metadata(GitDiffSeparator(Filename::Real(PathBuf::from("aaa")), Filename::Real(PathBuf::from("bbb")))));
    assert_parsed!(parse_patch_line, b"--- aaa\n", Metadata(MinusFilename(Filename::Real(PathBuf::from("aaa")))));

    assert_parsed!(parse_patch_line, b"@@ -1 +1 @@\n", StartOfHunk);

    assert_parsed!(parse_patch_line, b"Bla ble bli.\n", Garbage);
}

fn parse_number_usize(input: CompleteByteSlice) -> IResult<CompleteByteSlice, usize> {
    let (input_, digits) = take_while1!(input, is_digit)?;
    let str = std::str::from_utf8(&digits).unwrap(); // NOTE(unwrap): We know it is just digits 0-9, so it is guaranteed to be valid UTF8.
    match usize::from_str(str) {
        Ok(number) => Ok((input_, number)),
        Err(_) => Err(nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::NumberTooBig as u32)))),
    }
}

#[cfg(test)]
#[test]
fn test_parse_number_usize() {
    assert_parsed!(parse_number_usize, b"0", 0);
    assert_parsed!(parse_number_usize, b"1", 1);
    assert_parsed!(parse_number_usize, b"123", 123);

    assert_parse_error_code!(parse_number_usize, b"123456789012345678901234567890", ParseErrorCode::NumberTooBig as u32);
}

/// Parses line and count like "3,4" or just "3"
named!(parse_hunk_line_and_count<CompleteByteSlice, (usize, usize)>,
    do_parse!(
        line: parse_number_usize >>
        count: alt!(
            do_parse!(
                tag!(c!(b',')) >>
                n: parse_number_usize >>
                (n)
            ) |
            value!(1) // If there is no ",123" part, then the line count is 1.
        ) >>
        ((line, count))
    )
);

#[cfg(test)]
#[test]
fn test_parse_hunk_line_and_count() {
    assert_parsed!(parse_hunk_line_and_count, b"2", (2, 1));
    assert_parsed!(parse_hunk_line_and_count, b"2,3", (2, 3));
    assert_parsed!(parse_hunk_line_and_count, b"123,456", (123, 456));
}

#[derive(Debug, PartialEq)]
struct HunkHeader<'a> {
    pub add_line: usize,
    pub add_count: usize,
    pub remove_line: usize,
    pub remove_count: usize,

    pub function: &'a [u8],
}

/// Parses the line like "@@ -3,4 +5,6 @@ function\n"
named!(parse_hunk_header<CompleteByteSlice, HunkHeader>,
    do_parse!(
        tag!(s!(b"@@ -")) >>
        remove_line_and_count: parse_hunk_line_and_count >>

        tag!(s!(b" +")) >>
        add_line_and_count: parse_hunk_line_and_count >>

        tag!(s!(b" @")) >>
        opt!(tag!(c!(b'@'))) >> // The second "@" is optional. At least that's what patch accepts.

        opt!(tag!(c!(b' '))) >>
        function: take_until_newline >>

        newline >>

        (HunkHeader {
            add_line: add_line_and_count.0,
            add_count: add_line_and_count.1,
            remove_line: remove_line_and_count.0,
            remove_count: remove_line_and_count.1,

            function: &function
        })
    )
);

#[cfg(test)]
#[test]
fn test_parse_hunk_header() {
    let h1 = HunkHeader {
        add_line: 3,
        add_count: 4,
        remove_line: 1,
        remove_count: 2,

        function: &b""[..],
    };

    assert_parsed!(parse_hunk_header, b"@@ -1,2 +3,4 @@\n", h1);
    assert_parsed!(parse_hunk_header, b"@@ -1,2 +3,4 @\n", h1);

    let h2 = HunkHeader {
        add_line: 6,
        add_count: 1,
        remove_line: 5,
        remove_count: 1,

        function: &b""[..],
    };

    assert_parsed!(parse_hunk_header, b"@@ -5 +6 @@\n", h2);
    assert_parsed!(parse_hunk_header, b"@@ -5 +6 @\n", h2);

    let h3 = HunkHeader {
        add_line: 3,
        add_count: 4,
        remove_line: 1,
        remove_count: 2,

        function: s!(b"function name"),
    };

    assert_parsed!(parse_hunk_header, b"@@ -1,2 +3,4 @@ function name\n", h3);
    assert_parsed!(parse_hunk_header, b"@@ -1,2 +3,4 @ function name\n", h3);
}

#[derive(Debug, PartialEq)]
enum HunkLineType {
    Add,
    Remove,
    Context,
}

named!(parse_hunk_line<CompleteByteSlice, (HunkLineType, &[u8])>,
    map!(
        pair!(
            return_error!(
                add_return_error!(ErrorKind::Custom(ParseErrorCode::BadLineInHunk as u32),
                    alt!(
                        do_parse!(tag!(c!(b'+')) >> line: take_until_newline_incl >> ((HunkLineType::Add, &line[..]))) |
                        do_parse!(tag!(c!(b'-')) >> line: take_until_newline_incl >> ((HunkLineType::Remove, &line[..]))) |
                        do_parse!(tag!(c!(b' ')) >> line: take_until_newline_incl >> ((HunkLineType::Context, &line[..]))) |

                        // XXX: patch allows context lines starting with TAB character. That TAB is then part of the line.
                        do_parse!(peek!(tag!(c!(b'\t'))) >> line: take_until_newline_incl >> ((HunkLineType::Context, &line[..]))) |

                        // XXX: patch allows completely empty line as an empty context line.
                        value!((HunkLineType::Context, c!(b'\n')), newline)
                    )
                )
            ),

            opt!(tag!(s!(NO_NEW_LINE_TAG)))
        ),
    |((line_type, line), no_newline_tag)| {
        // Was there "No newline..." tag?
        if no_newline_tag.is_none() {
            // There wasn't, return what we have.
            (line_type, line)
        } else {
            // There was, remove the newline at the end
            (line_type, &line[0..(line.len() - 1)])
        }
    })
);

#[cfg(test)]
#[test]
fn test_parse_hunk_line() {
    // Adding
    assert_parsed!(parse_hunk_line, b"+\n",                 (HunkLineType::Add, s!(b"\n")));
    assert_parsed!(parse_hunk_line, b"+aaa\n",              (HunkLineType::Add, s!(b"aaa\n")));
    assert_parsed!(parse_hunk_line, b"+    bla ble bli;\n", (HunkLineType::Add, s!(b"    bla ble bli;\n")));

    // Removing
    assert_parsed!(parse_hunk_line, b"-\n",                 (HunkLineType::Remove, s!(b"\n")));
    assert_parsed!(parse_hunk_line, b"-aaa\n",              (HunkLineType::Remove, s!(b"aaa\n")));
    assert_parsed!(parse_hunk_line, b"-    bla ble bli;\n", (HunkLineType::Remove, s!(b"    bla ble bli;\n")));

    // Context
    assert_parsed!(parse_hunk_line, b" \n",                 (HunkLineType::Context, s!(b"\n")));
    assert_parsed!(parse_hunk_line, b" aaa\n",              (HunkLineType::Context, s!(b"aaa\n")));
    assert_parsed!(parse_hunk_line, b"     bla ble bli;\n", (HunkLineType::Context, s!(b"    bla ble bli;\n")));

    // No newline...
    assert_parsed!(parse_hunk_line, b"+    bla ble bli;\n\\ No newline at end of file\n", (HunkLineType::Add,     s!(b"    bla ble bli;")));
    assert_parsed!(parse_hunk_line, b"-    bla ble bli;\n\\ No newline at end of file\n", (HunkLineType::Remove,  s!(b"    bla ble bli;")));
    assert_parsed!(parse_hunk_line, b"     bla ble bli;\n\\ No newline at end of file\n", (HunkLineType::Context, s!(b"    bla ble bli;")));

    // XXX: patch specialty: See comment in `hunk_line`.
    assert_parsed!(parse_hunk_line, b"\t\n",                 (HunkLineType::Context, s!(b"\t\n")));
    assert_parsed!(parse_hunk_line, b"\taaa\n",              (HunkLineType::Context, s!(b"\taaa\n")));
    assert_parsed!(parse_hunk_line, b"\t\tbla ble bli;\n",   (HunkLineType::Context, s!(b"\t\tbla ble bli;\n")));

    // XXX: patch specialty: See comment in `hunk_line`.
    assert_parsed!(parse_hunk_line, b"\n", (HunkLineType::Context, s!(b"\n")));

    // Bad line
    assert_parse_error_code!(parse_hunk_line, b"wtf is this\n", ParseErrorCode::BadLineInHunk as u32);
    assert_parse_error_code!(parse_hunk_line, b"wtf", ParseErrorCode::BadLineInHunk as u32);
}

fn parse_hunk<'a>(input: CompleteByteSlice<'a>) -> IResult<CompleteByteSlice, TextHunk<'a>> {
    let (mut input, mut header) = parse_hunk_header(input)?;

    let mut hunk = Hunk::new(
        std::cmp::max(header.remove_line as isize - 1, 0),
        std::cmp::max(header.add_line as isize - 1, 0),
        header.function
    );

    hunk.add.content.reserve(header.add_count);
    hunk.remove.content.reserve(header.remove_count);

    let mut there_was_a_non_context_line = false;

    while header.add_count > 0 || header.remove_count > 0 {
        let (input_, (line_type, line)) = match parse_hunk_line(input) {
            Ok(ok) => ok,
            Err(err @ nom::Err::Failure(_)) => return Err(err),
            Err(nom::Err::Incomplete(_)) => unreachable!(),
            Err(nom::Err::Error(_)) => return Err(nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::UnexpectedEndOfFile as u32)))),
        };

        input = input_;

        match line_type {
            HunkLineType::Add => {
                if header.add_count == 0 {
                    return Err(nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::BadLineInHunk as u32))));
                }

                hunk.add.content.push(line);
                header.add_count -= 1;

                there_was_a_non_context_line = true;
                hunk.context_after = 0;
            }
            HunkLineType::Remove => {
                if header.remove_count == 0 {
                    return Err(nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::BadLineInHunk as u32))));
                }

                hunk.remove.content.push(line);
                header.remove_count -= 1;

                there_was_a_non_context_line = true;
                hunk.context_after = 0;
            }
            HunkLineType::Context => {
                if header.remove_count == 0 || header.add_count == 0 {
                    return Err(nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::BadLineInHunk as u32))));
                }

                hunk.add.content.push(line);
                hunk.remove.content.push(line);
                header.add_count -= 1;
                header.remove_count -= 1;

                if !there_was_a_non_context_line {
                    hunk.context_before += 1;
                } else {
                    hunk.context_after += 1;
                }
            }
        }
    }

    // man patch: "Hunks with less prefix context than suffix context (after applying fuzz) must apply at the
    //             start of the file if their first line  number is 1. Hunks with more prefix context than suffix
    //             context (after applying fuzz) must apply at the end of the file."
    if hunk.context_before < hunk.context_after && header.add_line == 1 {
        hunk.position = HunkPosition::Start;
    } else if hunk.context_before > hunk.context_after {
        hunk.position = HunkPosition::End;
    }

    Ok((input, hunk))
}

#[cfg(test)]
#[test]
fn test_parse_hunk() {
    // Ok hunk
    let hunk_txt = br#"@@ -100,6 +110,7 @@ place
 aaa
 bbb
 ccc
-ddd
+eee
+fff
 ggg
 hhh
"#;

    let h = parse_hunk(CompleteByteSlice(hunk_txt)).unwrap().1;
    assert_eq!(h.remove.target_line, 99);
    assert_eq!(h.add.target_line, 109);

    assert_eq!(&h.add.content[..], [b"aaa\n", b"bbb\n", b"ccc\n", b"eee\n", b"fff\n", b"ggg\n", b"hhh\n"]);
    assert_eq!(&h.remove.content[..], [b"aaa\n", b"bbb\n", b"ccc\n", b"ddd\n", b"ggg\n", b"hhh\n"]);

    assert_eq!(h.context_before, 3);
    assert_eq!(h.context_after, 2);

    assert_eq!(h.function, b"place");


    // Too short hunk
    let hunk_txt = br#"@@ -100,6 +110,7 @@ place
 aaa
 bbb
 ccc
"#;
    assert_parse_error_code!(parse_hunk, s!(hunk_txt), ParseErrorCode::BadLineInHunk as u32);


    // Bad line in hunk (nonsense)
    let hunk_txt = br#"@@ -100,6 +110,7 @@ place
 aaa
 bbb
 ccc
xxxxx
"#;
    assert_parse_error_code!(parse_hunk, s!(hunk_txt), ParseErrorCode::BadLineInHunk as u32);


    // Bad line in hunk (unexpected '+', '-' or ' ')
    let hunk_txt = br#"@@ -100,3 +110,2 @@ place
 aaa
-bbb
-ccc
 ddd
"#;
    assert_parse_error_code!(parse_hunk, s!(hunk_txt), ParseErrorCode::BadLineInHunk as u32);
}

// named!(parse_hunks<CompleteByteSlice, SmallVec<[TextHunk; 4]>>, many1!(parse_hunk)); // FIXME: many1 will hide even nom::Err::Failure errors, so any failure from inside is not propagated up. :-(

fn parse_hunks(mut input: CompleteByteSlice) -> IResult<CompleteByteSlice, HunksVec<&[u8]>> {
    let mut hunks = HunksVec::<&[u8]>::new();
    loop {
        match parse_hunk(input) {
            Ok((input_, hunk)) => {
                hunks.push(hunk);
                input = input_;
            }
            Err(nom::Err::Incomplete(_)) => {
                unreachable!();
            }
            Err(nom::Err::Error(nom::Context::Code(input_, _))) => {
                // TODO: Do anything for the case of not even one hunk?
                return Ok((input_, hunks));
            }
            Err(err @ nom::Err::Failure(_)) => {
                return Err(err);
            }
        }
    }
}

#[cfg(test)]
#[test]
fn test_parse_hunks() {
    let hunks_txt = br#"@@ -100,3 +110,3 @@ place1
 aaa
-bbb
+ccc
 ddd
@@ -200,3 +210,3 @@ place2
 mmm
-nnn
+ooo
 ppp
Some other line...
Other content.
"#;

    let hs = parse_hunks(CompleteByteSlice(hunks_txt)).unwrap().1;
    assert_eq!(hs.len(), 2);

    assert_eq!(hs[0].remove.target_line, 99);
    assert_eq!(hs[1].remove.target_line, 199);

    assert_eq!(hs[0].function, b"place1");
    assert_eq!(hs[1].function, b"place2");
}

#[derive(Debug, Default)]
struct FilePatchMetadata {
    old_filename: Option<Filename>,
    new_filename: Option<Filename>,
    rename_from: bool,
    rename_to: bool,
    old_permissions: Option<Permissions>,
    new_permissions: Option<Permissions>,
}

enum FilePatchMetadataBuildError {
    MissingFilenames(FilePatchMetadata),
}

impl FilePatchMetadata {
    pub fn recognize_kind(&self, hunks: &[TextHunk]) -> FilePatchKind {
        // First check the filenames
        if self.old_filename.as_ref() == Some(&Filename::DevNull) {
            return FilePatchKind::Create;
        }
        if self.new_filename.as_ref() == Some(&Filename::DevNull) {
            return FilePatchKind::Delete;
        }

        // XXX: There are patches that do not use /dev/null but are creating or deleting files,
        //      recognize them here.
        if hunks.len() == 1 {
            let only_hunk = &hunks[0];

            if only_hunk.context_after == 0 && only_hunk.context_before == 0 {
                if only_hunk.add.content.is_empty() &&
                  !only_hunk.remove.content.is_empty()
                {
                    return FilePatchKind::Delete;
                }

                if !only_hunk.add.content.is_empty() &&
                  only_hunk.remove.content.is_empty()
                {
                    return FilePatchKind::Create;
                }
            }
        }

        // Then it is modifying type
        FilePatchKind::Modify
    }

    /// This function will return `None` if some necessary metadata is missing
    pub fn build_filepatch<'a>(self, hunks: HunksVec<'a, &'a [u8]>) -> Result<TextFilePatch<'a>, FilePatchMetadataBuildError> {
        let mut builder = FilePatchBuilder::<&[u8]>::default();

        // Set the kind
        builder.kind(self.recognize_kind(&hunks));

        // Set the filenames
        let has_old_filename = match self.old_filename {
            Some(Filename::Real(_)) => true,
            _ => false,
        };
        let has_new_filename = match self.new_filename {
            Some(Filename::Real(_)) => true,
            _ => false,
        };

        if self.rename_from && self.rename_to {
            // If it is renaming patch, we must have both filenames
            if !has_old_filename || !has_new_filename {
                return Err(FilePatchMetadataBuildError::MissingFilenames(self));
            }

            builder.is_rename(true);
        } else {
            // If it is non-renaming patch, we must have at least one filename
            if !has_old_filename && !has_new_filename {
                return Err(FilePatchMetadataBuildError::MissingFilenames(self));
            }
        }

        // Move out the filenames
        let old_filename = match self.old_filename {
            Some(Filename::Real(old_filename)) => Some(old_filename),
            _ => None,
        };
        let new_filename = match self.new_filename {
            Some(Filename::Real(new_filename)) => Some(new_filename),
            _ => None,
        };

        builder.old_filename(old_filename);
        builder.new_filename(new_filename);

        // Set the permissions
        builder.old_permissions(self.old_permissions);
        builder.new_permissions(self.new_permissions);

        // Set the hunks
        builder.hunks(hunks);

        // Build
        Ok(builder.build().unwrap()) // NOTE(unwrap): It would be our bug if we didn't provide all necessary values.
    }

    /// This function will return `None` if some necessary metadata is missing
    pub fn build_hunkless_filepatch<'a>(self) -> Result<TextFilePatch<'a>, FilePatchMetadataBuildError> {
        self.build_filepatch(HunksVec::new())
    }
}

#[cfg(unix)]
fn permissions_from_mode(mode: u32) -> Option<Permissions> {
    use std::os::unix::fs::PermissionsExt;
    Some(Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn permissions_from_mode(mode: u32) -> Option<Permissions> {
    static WARN_ONCE: std::sync::Once = std::sync::Once::new();

    WARN_ONCE.call_once(|| {
        eprintln!("Permissions are ignored on non-unix systems!");
    });

    None
}

fn parse_filepatch<'a>(mut input: CompleteByteSlice<'a>) -> IResult<CompleteByteSlice, TextFilePatch<'a>> {
    let mut metadata = FilePatchMetadata::default();

    // First we read metadata lines or garbage and wait until we find a first hunk.
    loop {
        let (input_, patch_line) = parse_patch_line(input)?;

        use self::PatchLine::*;
        use self::MetadataLine::*;

        match patch_line {
            Garbage => { input = input_; continue; }
            StartOfHunk => { input = input_; break; }

            EndOfPatch | Metadata(MetadataLine::GitDiffSeparator(..)) => {
                // We reached end of file or separator and have no hunks. It
                // could be still valid patch that only renames a file or
                // changes permissions... So lets check for that.
                match metadata.build_hunkless_filepatch() {
                    Ok(filepatch) => {
                        // It was possible to have hunkless filepatch, great!

                        // Note that in this case we don't set `input = input_`, because we don't want to consume the GitDiffSeparator

                        return Ok((input, filepatch));
                    }
                    Err(FilePatchMetadataBuildError::MissingFilenames(incomplete_metadata)) => {
                        // Otherwise it just means that everything that may have
                        // looked like metadata until now was just garbage.

                        // Return if we are at the end of patch
                        if patch_line == EndOfPatch {
                            // Note: This is Error, not Failure, because it could be just because there are no more filepatches at the end of file. Not a fatal error.
                            return Err(nom::Err::Error(nom::Context::Code(input, nom::ErrorKind::Custom(ParseErrorCode::UnexpectedEndOfFile as u32))));
                        }

                        // Reset metadata if it was separator
                        if let Metadata(MetadataLine::GitDiffSeparator(old_filename, new_filename)) = patch_line {
                            metadata = FilePatchMetadata::default();
                            metadata.old_filename = Some(old_filename);
                            metadata.new_filename = Some(new_filename);
                        } else {
                            metadata = incomplete_metadata;
                        }
                    }
                }
            }
            Metadata(PlusFilename(filename)) => {
                metadata.new_filename = Some(filename);
            }
            Metadata(MinusFilename(filename)) => {
                metadata.old_filename = Some(filename);
            }

            Metadata(RenameFrom) => {
                metadata.rename_from = true;
            }
            Metadata(RenameTo) => {
                metadata.rename_to = true;
            }

            Metadata(OldMode(mode)) |
            Metadata(DeleteFileMode(mode)) => {
                metadata.old_permissions = permissions_from_mode(mode);
            }
            Metadata(NewMode(mode)) |
            Metadata(NewFileMode(mode)) => {
                metadata.new_permissions = permissions_from_mode(mode);
            }

            Metadata(GitBinaryPatch) => {
                return Err(nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::UnsupportedMetadata as u32))));
            }

            Metadata(_) => {
                // Other metadata lines are ignored for now.
                // TODO: Implement some of them...
            }
        }

        input = input_; // Move to the next line.
    }

    // Read the hunks!
    let (input_, hunks) = parse_hunks(input)?;
    input = input_;

    // We can make our filepatch
    let filepatch = metadata.build_filepatch(hunks).map_err(
        |error| match error {
             FilePatchMetadataBuildError::MissingFilenames(_) =>
                nom::Err::Failure(error_position!(input, nom::ErrorKind::Custom(ParseErrorCode::MissingFilenameForHunk as u32)))
        }
    )?;

    Ok((input, filepatch))
}

#[cfg(test)]
#[test]
fn test_parse_filepatch() {
    // Regular filepatch
    let filepatch_txt = br#"garbage1
garbage2
garbage3
--- filename1
+++ filename1
@@ -200,3 +210,3 @@ place2
 mmm
-nnn
+ooo
 ppp
Some other line...
Other content.
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);
    assert_eq!(file_patch.hunks[0].add.content[0], s!(b"mmm\n"));


    // Creating filepatch
    let filepatch_txt = br#"garbage1
garbage2
garbage3
--- /dev/null
+++ filename1
@@ -0,0 +1,3 @@ place2
+aaa
+bbb
+ccc
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Create);
    assert_eq!(file_patch.old_filename(), None);
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);
    assert_eq!(&file_patch.hunks[0].add.content[..], [s!(b"aaa\n"), s!(b"bbb\n"), s!(b"ccc\n")]);


    // Creating filepatch without /dev/null
    let filepatch_txt = br#"garbage1
garbage2
garbage3
--- filename1
+++ filename1
@@ -0,0 +1,3 @@ place2
+aaa
+bbb
+ccc
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Create);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);
    assert_eq!(&file_patch.hunks[0].add.content[..], [s!(b"aaa\n"), s!(b"bbb\n"), s!(b"ccc\n")]);


    // Deleting filepatch
    let filepatch_txt = br#"garbage1
garbage2
garbage3
--- filename1
+++ /dev/null
@@ -1,3 +0,0 @@ place2
-aaa
-bbb
-ccc
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Delete);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), None);
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);
    assert_eq!(&file_patch.hunks[0].remove.content[..], [s!(b"aaa\n"), s!(b"bbb\n"), s!(b"ccc\n")]);


    // Deleting filepatch without /dev/null
    let filepatch_txt = br#"garbage1
garbage2
garbage3
--- filename1
+++ filename1
@@ -1,3 +0,0 @@ place2
-aaa
-bbb
-ccc
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Delete);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);
    assert_eq!(&file_patch.hunks[0].remove.content[..], [s!(b"aaa\n"), s!(b"bbb\n"), s!(b"ccc\n")]);


    // Renaming filepatch
    let filepatch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename2
rename from filename1
rename to filename2
--- filename1
+++ filename2
diff --git bla ble
--- bla
--- ble
@@ -200,3 +210,3 @@ place2
 mmm
-nnn
+ooo
 ppp
Some other line...
Other content.
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename2")));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 0);


    // Renaming filepatch at the end of file
    let filepatch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename2
rename from filename1
rename to filename2
--- filename1
+++ filename2
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename2")));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 0);


    // Renaming filepatch without +++ ---, with hunk
    let filepatch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename2
rename from filename1
rename to filename2
@@ -200,3 +210,3 @@ place2
 aaa
-bbb
+ccc
 ddd
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename2")));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);


    // Unsupported metadata
    let filepatch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename2
GIT binary patch
???
"#;
        assert_parse_error_code!(parse_filepatch, s!(filepatch_txt), ParseErrorCode::UnsupportedMetadata as u32);
}

#[cfg(unix)]
#[cfg(test)]
#[test]
fn test_parse_filepatch_unix() {
    use std::os::unix::fs::PermissionsExt;

    // Mode changing filepatch
    let filepatch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename1
old mode 100644
new mode 100755
@@ -200,3 +210,3 @@ place2
 aaa
-bbb
+ccc
 ddd
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.old_permissions(), Some(&Permissions::from_mode(0o100644)));
    assert_eq!(file_patch.new_permissions(), Some(&Permissions::from_mode(0o100755)));
    assert_eq!(file_patch.hunks.len(), 1);


    // Mode changing filepatch without hunks
    let filepatch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename1
old mode 100644
new mode 100755
diff --git filename2 filename2
--- filename2
+++ filename2
@@ -200,3 +210,3 @@ place2
 aaa
-bbb
+ccc
 ddd
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.old_permissions(), Some(&Permissions::from_mode(0o100644)));
    assert_eq!(file_patch.new_permissions(), Some(&Permissions::from_mode(0o100755)));
    assert_eq!(file_patch.hunks.len(), 0);


    // Mode changing filepatch without hunks at the end of file
    let filepatch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename1
old mode 100644
new mode 100755
"#;

    let file_patch = parse_filepatch(CompleteByteSlice(filepatch_txt)).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.new_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patch.old_permissions(), Some(&Permissions::from_mode(0o100644)));
    assert_eq!(file_patch.new_permissions(), Some(&Permissions::from_mode(0o100755)));
    assert_eq!(file_patch.hunks.len(), 0);
}

pub fn parse_patch<'a>(bytes: &'a [u8], strip: usize) -> Result<Vec<TextFilePatch<'a>>, Error> {
    let mut input = CompleteByteSlice(bytes);

    let mut filepatches = Vec::<TextFilePatch>::new();

    loop {
        let (_input, mut filepatch) = match parse_filepatch(input) {
            // We got one
            Ok(filepatch) => filepatch,

            // No more filepatches...
            Err(nom::Err::Error(_)) => break,

            // Actual error
            Err(err @ nom::Err::Failure(_)) => { return Err(ParseError::from(err).into()); }

            // No way this could happen
            Err(nom::Err::Incomplete(_)) => unreachable!(),
        };
        input = _input;

        filepatch.strip(strip);
        filepatches.push(filepatch);
    }

    Ok(filepatches)
}

#[cfg(test)]
#[test]
fn test_parse_patch() {
    let patch_txt = br#"garbage1
garbage2
garbage3
--- filename1
+++ filename1
@@ -200,3 +210,3 @@ place2
 mmm
-nnn
+ooo
 ppp
--- filename2
+++ filename2
@@ -200,3 +210,3 @@ place2
 aaa
-bbb
+ccc
 ddd
garbage4
garbage5
"#;

    let file_patches = parse_patch(patch_txt, 0).unwrap();

    assert_eq!(file_patches.len(), 2);

    assert_eq!(file_patches[0].old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patches[0].new_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patches[0].hunks.len(), 1);
    assert_eq!(file_patches[0].hunks[0].add.content[0], s!(b"mmm\n"));

    assert_eq!(file_patches[1].old_filename(), Some(&PathBuf::from("filename2")));
    assert_eq!(file_patches[1].new_filename(), Some(&PathBuf::from("filename2")));
    assert_eq!(file_patches[1].hunks.len(), 1);
    assert_eq!(file_patches[1].hunks[0].add.content[0], s!(b"aaa\n"));


    // Renaming filepatches, no +++ ---
    let patch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename2
rename from filename1
rename to filename2
diff --git filename3 filename4
rename from filename3
rename to filename4
diff --git filename5 filename6
rename from filename5
rename to filename6
@@ -200,3 +210,3 @@ place2
 aaa
-bbb
+ccc
 ddd
diff --git filename7 filename8
rename from filename7
rename to filename7
"#;

    let file_patches = parse_patch(patch_txt, 0).unwrap();

    assert_eq!(file_patches.len(), 4);

    assert_eq!(file_patches[0].old_filename(), Some(&PathBuf::from("filename1")));
    assert_eq!(file_patches[0].new_filename(), Some(&PathBuf::from("filename2")));
    assert_eq!(file_patches[0].hunks.len(), 0);

    assert_eq!(file_patches[1].old_filename(), Some(&PathBuf::from("filename3")));
    assert_eq!(file_patches[1].new_filename(), Some(&PathBuf::from("filename4")));
    assert_eq!(file_patches[1].hunks.len(), 0);

    assert_eq!(file_patches[2].old_filename(), Some(&PathBuf::from("filename5")));
    assert_eq!(file_patches[2].new_filename(), Some(&PathBuf::from("filename6")));
    assert_eq!(file_patches[2].hunks.len(), 1);

    assert_eq!(file_patches[3].old_filename(), Some(&PathBuf::from("filename7")));
    assert_eq!(file_patches[3].new_filename(), Some(&PathBuf::from("filename8")));
    assert_eq!(file_patches[3].hunks.len(), 0);
}

#[cfg(test)]
#[cfg(feature = "bencher")]
mod tests {
    use super::*;
    use test::{Bencher, black_box};

    #[bench]
    fn bench_parse_big_patch(b: &mut Bencher) {
        let data = include_bytes!("../../../../testdata/big.patch");

        b.iter(|| {
            black_box(parse_patch(data, 1).unwrap());
        });
    }
}
