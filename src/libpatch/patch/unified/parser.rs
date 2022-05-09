// Licensed under the MIT license. See LICENSE.md

use std::borrow::Cow;
use std::fs::Permissions;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::vec::Vec;

use failure::{Error, Fail};

use nom::{
    branch::alt,
    bytes::complete::{tag, take_till1, take_while, take_while1},
    character::{is_digit, is_hex_digit, is_oct_digit},
    combinator::{cond, eof, not, opt, map, success},
    error::ErrorKind,
    sequence::{delimited, pair, preceded, tuple},
    IResult,
};

use crate::patch::*;
use crate::patch::unified::*;


#[derive(Debug, PartialEq)]
pub enum ParseError<'a> {
    UnsupportedMetadata(&'a [u8]),
    MissingFilenameForHunk(&'a [u8]),
    UnexpectedEndOfFile,
    BadLineInHunk(&'a [u8]),
    NumberTooBig(&'a [u8]),
    BadMode(&'a [u8]),
    BadSequence(&'a [u8]),
    Unknown(&'a [u8], ErrorKind),
}

impl<'a> nom::error::ParseError<&'a [u8]> for ParseError<'a> {
    fn from_error_kind(input: &'a [u8], kind: ErrorKind) -> Self {
        Self::Unknown(input, kind)
    }

    fn append(_: &[u8], _: ErrorKind, other: Self) -> Self {
        other
    }
}

#[derive(Debug, Fail, PartialEq)]
pub enum StaticParseError {
    #[fail(display = "Unsupported metadata: \"{}\"", 0)]
    UnsupportedMetadata(String),

    #[fail(display = "Could not figure out the filename for hunk \"{}\"", 0)]
    MissingFilenameForHunk(String),

    #[fail(display = "Unexpected end of file")]
    UnexpectedEndOfFile,

    #[fail(display = "Unexpected line in the middle of hunk: \"{}\"", 0)]
    BadLineInHunk(String),

    #[fail(display = "Number too big: \"{}\"", 0)]
    NumberTooBig(String),

    #[fail(display = "Invalid mode: \"{}\"", 0)]
    BadMode(String),

    #[fail(display = "Invalid escape sequence: \"{}\"", 0)]
    BadSequence(String),

    #[fail(display = "Unknown parse failure: \"{:?}\" on line \"{}\"", 1, 0)]
    Unknown(String, ErrorKind),
}

impl<'a> From<ParseError<'a>> for StaticParseError {
    fn from(err: ParseError) -> Self {
        use ParseError::*;
        match err {
            UnsupportedMetadata(input) =>
                Self::UnsupportedMetadata(String::from_utf8_lossy(error_line(input)).to_string()),
            MissingFilenameForHunk(input) =>
                Self::MissingFilenameForHunk(String::from_utf8_lossy(error_line(input)).to_string()),

            UnexpectedEndOfFile =>
                Self::UnexpectedEndOfFile,

            BadLineInHunk(input) =>
                Self::BadLineInHunk(String::from_utf8_lossy(error_line(input)).to_string()),

            NumberTooBig(number_str) =>
                Self::NumberTooBig(String::from_utf8_lossy(number_str).to_string()),

            BadMode(input) =>
                Self::BadMode(String::from_utf8_lossy(error_word(input)).to_string()),

            BadSequence(input) =>
                Self::BadSequence(String::from_utf8_lossy(error_sequence(input)).to_string()),

            Unknown(input, inner) =>
                Self::Unknown(String::from_utf8_lossy(error_line(input)).to_string(), inner),
        }
    }
}

#[cfg(test)]
macro_rules! assert_parsed {
    ( $parse_func:ident, $input:expr, $result:expr ) => {
        assert_parsed!($parse_func, $input, $result, b"")
    };
    ( $parse_func:ident, $input:expr, $result:expr, $remain:expr ) => {
        {
            let ret = $parse_func($input);
            let remain = ret.as_ref().map(|tuple| tuple.0);
            let result = ret.as_ref().map(|tuple| &tuple.1);
            assert_eq!(result, Ok(&$result), "parse result mismatch");
            assert_eq!(remain, Ok(&$remain[..]), "parse remainder mismatch");
        }
    };
}

#[cfg(test)]
macro_rules! assert_parse_error {
    ( $parse_func:ident, $input:expr, $error:expr ) => {
        {
            let ret = $parse_func($input);
            match ret {
                Err(nom::Err::Error(error)) |
                Err(nom::Err::Failure(error)) => {
                    assert_eq!(StaticParseError::from(error), $error);
                }

                _ => {
                    panic!("Parsing {:?}, got unexpected return: {:?}", $input, ret);
                }
            }
        }
    };
}

#[cfg(test)]
macro_rules! assert_lines_eq {
    ( $input:expr, $lines:expr ) => {
        {
            for (line, expect) in $input.split(|&c| c == b'\n').zip($lines) {
                assert_eq!(line, expect.as_bytes());
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

// nom::character::complete::newline is for characters, we need &[u8]
fn newline(input: &[u8]) -> IResult<&[u8], &[u8], ParseError> {
    tag(c!(b'\n'))(input)
}

fn take_until_newline(input: &[u8]) -> IResult<&[u8], &[u8], ParseError> {
    match memchr::memchr(b'\n', input) {
        Some(index) => Ok((&input[index..], &input[..index])),
        None => Err(nom::Err::Error(ParseError::UnexpectedEndOfFile)),
    }
}

fn take_until_newline_incl(input: &[u8]) -> IResult<&[u8], &[u8], ParseError> {
    match memchr::memchr(b'\n', input) {
        Some(index) => Ok((&input[index+1..], &input[..index+1])),
        None => Err(nom::Err::Error(ParseError::UnexpectedEndOfFile)),
    }
}

fn error_line(input: &[u8]) -> &[u8] {
    match memchr::memchr(b'\n', input) {
        Some(index) => &input[..index],
        None => &input[..],
    }
}

fn error_word(input: &[u8]) -> &[u8] {
    match input.iter().position(|c|
                                !(b'0'..b'9').contains(c) &&
                                !(b'A'..b'Z').contains(c) &&
                                !(b'a'..b'z').contains(c)) {
        Some(index) => &input[..index],
        None => &input[..],
    }
}

fn error_sequence(input: &[u8]) -> &[u8] {
    let index = match input.get(1) {
        None => 1,
        Some(c) => if !(b'0'..b'3').contains(c) { 2 } else {
            match input.get(2) {
                None => 2,
                Some(c) => if !(b'0'..b'7').contains(c) { 3 } else { 4 }
            }
        }
    };
    input.get(..index).unwrap_or(&input[..])
}

// Parses filename as-is included in the patch, delimited by first whitespace. Returns byte slice
// of the path as-is in the input data.
fn parse_filename_direct(input: &[u8]) -> IResult<&[u8], &[u8], ParseError> {
    take_till1(is_whitespace)(input)
}

/// Parses an octal triplet. Returns the parsed number as an option
/// and the number of bytes that could be successfully parsed
/// from `input`.
///
/// Requires exactly three octal digits that represent a number between
/// 0 and 0o377. On failure, `None` is returned together with the number
/// of bytes required to demonstrate the error.
fn parse_oct3(input: &[u8]) -> Option<u8> {
    if input.len() >= 3 &&
        (b'0'..=b'3').contains(&input[0]) &&
        (b'0'..=b'7').contains(&input[1]) &&
        (b'0'..=b'7').contains(&input[2])
    {
        Some(((input[0] - b'0') << 6) |
             ((input[1] - b'0') << 3) |
             ((input[2] - b'0')))
    } else { None }
}

#[cfg(test)]
#[test]
fn test_parse_oct3() {
    // Valid numbers
    assert_eq!(parse_oct3(b"123"), Some(0o123));
    assert_eq!(parse_oct3(b"3456"), Some(0o345));

    // Various invalid sequences
    assert_eq!(parse_oct3(b""), None);
    assert_eq!(parse_oct3(b"4"), None);
    assert_eq!(parse_oct3(b"x"), None);
    assert_eq!(parse_oct3(b"1"), None);
    assert_eq!(parse_oct3(b"18"), None);
    assert_eq!(parse_oct3(b"1x"), None);
    assert_eq!(parse_oct3(b"12"), None);
    assert_eq!(parse_oct3(b"128"), None);
    assert_eq!(parse_oct3(b"12x"), None);
}

/// Parses a C-style string. The implementation very closely mimics the
/// GNU patch function of the same name.
fn parse_c_string(input: &[u8]) -> Result<(&[u8], Vec<u8>), ParseError> {
    let mut index = 0;
    let mut res = Vec::new();
    while let Some(&c) = input.get(index) {
        match c {
            b'\\' => {
                index += 1;
                let c = match input.get(index) {
                    Some(b'a') => b'\x07',
                    Some(b'b') => b'\x08',
                    Some(b'f') => b'\x0c',
                    Some(b'n') => b'\n',
                    Some(b'r') => b'\r',
                    Some(b't') => b'\t',
                    Some(b'v') => b'\x0b',
                    Some(b'\\') => b'\\',
                    Some(b'\"') => b'\"',
                    _ => {
                        match parse_oct3(&input[index..]) {
                            Some(val) => {
                                index += 2; // difference from a one-letter sequence
                                val
                            }
                            None => {
                                return Err(ParseError::BadSequence(&input[index-1..]));
                            }
                        }
                    }
                };
                res.push(c);
            }
            b'\"' | b'\n' => return Ok((&input[index..], res)),
            other => res.push(other),
        }
        index += 1;
    }
    Ok((&input[index..], res))
}

#[cfg(test)]
#[test]
fn test_parse_c_string() {
    macro_rules! assert_bad_sequence {
        ($input:expr, $sequence:expr) => {
            assert_eq!(parse_c_string($input)
                       .map_err(|err| StaticParseError::from(err)),
                       Err(StaticParseError::BadSequence($sequence.to_string())));
        }
    }

    // Valid escapes
    assert_parsed!(parse_c_string, b"BEL: \\a", b"BEL: \x07".to_vec());
    assert_parsed!(parse_c_string, b"BS: \\b", b"BS: \x08".to_vec());
    assert_parsed!(parse_c_string, b"HT: \\t", b"HT: \x09".to_vec());
    assert_parsed!(parse_c_string, b"LF: \\n", b"LF: \x0a".to_vec());
    assert_parsed!(parse_c_string, b"VT: \\v", b"VT: \x0b".to_vec());
    assert_parsed!(parse_c_string, b"FF: \\f", b"FF: \x0c".to_vec());
    assert_parsed!(parse_c_string, b"CR: \\r", b"CR: \x0d".to_vec());
    assert_parsed!(parse_c_string, b"\\\\ (backslash)", b"\\ (backslash)".to_vec());
    assert_parsed!(parse_c_string, b"\\\" (quote)", b"\" (quote)".to_vec());

    assert_parsed!(parse_c_string, b"\\141\\142\\143", b"abc".to_vec());
    assert_parsed!(parse_c_string, b"\\201", b"\x81".to_vec());

    // The terminating quote should not be consumed
    assert_parsed!(parse_c_string, b"terminated\"", b"terminated".to_vec(), b"\"");

    // Invalid escapes
    assert_bad_sequence!(b"Unknown \\! escape", "\\!");
    assert_bad_sequence!(b"Unterminated \\", "\\");
    assert_bad_sequence!(b"One-digit octal: \\1.", "\\1.");
    assert_bad_sequence!(b"One-digit octal at end: \\1", "\\1");
    assert_bad_sequence!(b"Two-digit octal: \\12.", "\\12.");
    assert_bad_sequence!(b"Two-digit octal at end: \\12", "\\12");
    assert_bad_sequence!(b"Too big octal: \\666.", "\\6");
}

// Parses a quoted filename that may contain escaped characters. Returns owned buffer with the
// unescaped filename.
// Similar to `parse_c_string` function in patch.
fn parse_filename_quoted(input: &[u8]) -> IResult<&[u8], Vec<u8>, ParseError> {
    delimited(
        tag(b"\""),
        |input| parse_c_string(input).map_err(|error| nom::Err::Error(error)),
        tag(b"\"")
    )(input)
}

#[derive(Debug, PartialEq)]
enum Filename<'a> {
    /// Actual filename, either as byte slice of the patch file or owned buffer.
    Real(Cow<'a, Path>),

    /// The special "/dev/null" filename.
    DevNull,
}

// Parses a filename.
//
// Either written directly without any whitespace or inside quotation marks.
//
// Similar to `parse_name` function in patch.
fn parse_filename(input: &[u8]) -> IResult<&[u8], Filename, ParseError> {
    preceded(
        take_while(is_space),
        alt((
            // First attempt to parse it as quoted filename. This will reject it quickly if it does
            // not start with '"' character
            map(parse_filename_quoted, |filename_vec| {
                if &filename_vec[..] == NULL_FILENAME {
                    Filename::DevNull
                } else {
                    let pathbuf = match () {
                        #[cfg(unix)]
                        () => {
                            // We have owned buffer, so we must turn it into allocated `PathBuf`, but
                            // no conversion of encoding is necessary on unix systems.

                            use std::ffi::OsString;
                            use std::os::unix::ffi::OsStringExt;
                            PathBuf::from(OsString::from_vec(filename_vec))
                        }

                        #[cfg(not(unix))]
                        () => {
                            // In non-unix systems, we don't know how is `Path` represented, so we can
                            // not just take the byte slice and use it as `Path`. For example on Windows
                            // paths are a form of UTF-16, while the content of patch file has undefined
                            // encoding and we assume UTF-8. So conversion has to happen.

                            PathBuf::from(String::from_utf8_lossy(bytes).owned())
                        }
                    };

                    Filename::Real(Cow::Owned(pathbuf))
                }
            }),
            // Then attempt to parse it as direct filename (without quotes, spaces or escapes)
            map(parse_filename_direct, |filename| {
                if &filename[..] == NULL_FILENAME {
                    Filename::DevNull
                } else {
                    let path = match () {
                        #[cfg(unix)]
                        () => {
                            // We have a byte slice, which we can wrap into `Path` and use it without
                            // any heap allocation.

                            use std::ffi::OsStr;
                            use std::os::unix::ffi::OsStrExt;
                            Cow::Borrowed(Path::new(OsStr::from_bytes(filename)))
                        }

                        #[cfg(not(unix))]
                        () => {
                            // In non-unix systems, we don't know how is `Path` represented, so we can
                            // not just take the byte slice and use it as `Path`. For example on Windows
                            // paths are a form of UTF-16, while the content of patch file has undefined
                            // encoding and we assume UTF-8. So conversion has to happen.

                            Cow::Owned(PathBuf::from(String::from_utf8_lossy(bytes).owned()))
                        }
                    };

                    Filename::Real(path)
                }
            }),
        ))
    )(input)
}

#[cfg(test)]
#[test]
fn test_parse_filename() {
    macro_rules! assert_path {
        ($input:expr, $result:expr) => {
            assert_path!($input, $result, b"");
        };
        ($input:expr, $result:expr, $remain:expr) => {
            assert_parsed!(parse_filename, $input, Filename::Real(Cow::Owned(PathBuf::from($result))), $remain);
        };
    }

    assert_path!(b"aaa", "aaa");
    assert_path!(b"      aaa", "aaa");
    assert_path!(b"aaa\nbbb", "aaa", b"\nbbb");
    assert_path!(b"aaa time", "aaa", b" time");

    assert_path!(b"\"aaa\"", "aaa");
    assert_path!(b"      \"aaa\"", "aaa");
    assert_path!(b"\"aa aa\"", "aa aa");
    assert_path!(b"\"aa\\\"aa\"", "aa\"aa");
    assert_path!(b"\"aa\\\\aa\"", "aa\\aa");
    assert_path!(b"\"aa\\naa\"", "aa\naa");

    assert_path!(b"\"aa\\142aa\"", "aabaa");

    assert_parsed!(parse_filename, b"/dev/null", Filename::DevNull);
    assert_parsed!(parse_filename, b"\"/dev/null\"", Filename::DevNull);
}

/// Similar to `fetchmode` function in patch.
fn parse_mode(input: &[u8]) -> IResult<&[u8], u32, ParseError> {
    let (input, _) = take_while(is_space)(input)?;
    let (input_, digits) = take_while1(is_oct_digit)(input)?;

    if digits.len() != 6 { // This is what patch requires, but otherwise it fallbacks to 0, so maybe we should too?
        return Err(nom::Err::Failure(ParseError::BadMode(input)));
    }

    let mode_str = std::str::from_utf8(&digits).unwrap(); // NOTE(unwrap): We know it is just digits 0-7, so it is guaranteed to be valid UTF8.
    match u32::from_str_radix(mode_str, 8) {
        Ok(number) => Ok((input_, number)),
        Err(_) => Err(nom::Err::Failure(ParseError::BadMode(input))),
    }
}

#[cfg(test)]
#[test]
fn test_parse_mode() {
    macro_rules! assert_bad_mode(
        ($mode:expr) => {
            let mode = $mode;
            assert_parse_error!(
                parse_mode, mode.as_bytes(),
                StaticParseError::BadMode(mode.to_string()));
        };
    );

    assert_parsed!(parse_mode, b"123456", 0o123456);
    assert_parsed!(parse_mode, b"012345", 0o12345);
    assert_parsed!(parse_mode, b"   123456", 0o123456);
    assert_parsed!(parse_mode, b"   012345", 0o12345);

    assert_parsed!(parse_mode, b"100755", 0o100755);
    assert_parsed!(parse_mode, b"100644", 0o100644);

    assert_bad_mode!("100aaa");
    assert_bad_mode!("1");
    assert_bad_mode!("10000000");
    assert_bad_mode!("1000000000000000000000000000");

    // Report only the mode, not the rest of the line
    assert_parse_error!(
        parse_mode, b"100abc, more input here",
                StaticParseError::BadMode("100abc".to_string()));
}

#[derive(Debug, PartialEq)]
enum MetadataLine<'a> {
    GitDiffSeparator(Filename<'a>, Filename<'a>),

    MinusFilename(Filename<'a>),
    PlusFilename(Filename<'a>),

    // ...?
}

fn parse_metadata_line(input: &[u8]) -> IResult<&[u8], MetadataLine, ParseError> {
    alt((
        map(delimited(tag(s!(b"diff --git ")),
                      pair(parse_filename, parse_filename),
                      take_until_newline_incl),
            |(old_filename, new_filename)| MetadataLine::GitDiffSeparator(old_filename, new_filename)),

        map(delimited(tag(s!(b"--- ")),
                      parse_filename,
                      take_until_newline_incl),
            |filename| MetadataLine::MinusFilename(filename)),
        map(delimited(tag(s!(b"+++ ")),
                      parse_filename,
                      take_until_newline_incl),
            |filename| MetadataLine::PlusFilename(filename))
    ))(input)
}

#[cfg(test)]
#[test]
fn test_parse_metadata_line() {
    use self::MetadataLine::*;

    // All of them in basic form
    assert_parsed!(parse_metadata_line, b"diff --git aaa bbb\n", GitDiffSeparator(Filename::Real(Cow::Owned(PathBuf::from("aaa"))), Filename::Real(Cow::Owned(PathBuf::from("bbb")))));

    assert_parsed!(parse_metadata_line, b"--- aaa\n", MinusFilename(Filename::Real(Cow::Owned(PathBuf::from("aaa")))));
    assert_parsed!(parse_metadata_line, b"+++ aaa\n", PlusFilename(Filename::Real(Cow::Owned(PathBuf::from("aaa")))));

    // Filename with date
    assert_parsed!(parse_metadata_line, b"--- a/bla/ble.c	2013-09-23 18:41:09.000000000 -0400\n", MinusFilename(Filename::Real(Cow::Owned(PathBuf::from("a/bla/ble.c")))));

}

/// Parses a git object hash.
///
/// Git diff produces an abbreviated OID (max 40 lowercase hex digits).
/// Git apply acccepts uppercase, but rejects hashes longer than 40 digits.
/// GNU patch does not check hash length, but rejects uppercase hex.
///
/// This function permits both uppercase and long hashes.
/// Rationale: If git switches to a different hash algorithm, there is
/// some chance that our code will not have to change.
fn parse_git_hash(input: &[u8]) -> IResult<&[u8], &[u8], ParseError> {
    preceded(take_while(is_space),
             take_while1(is_hex_digit))(input)
}

#[cfg(test)]
#[test]
fn test_parse_git_hash() {
    // A shortened SHA1
    let hash = b"3505ee3";
    assert_parsed!(parse_git_hash, hash, s!(hash));

    // A full SHA1 (of an empty file)
    let hash = b"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
    assert_parsed!(parse_git_hash, hash, s!(hash));

    // An oversized SHA1 (GNU patch does not check maximum length)
    let hash = b"0123456789abcdef0123456789abcdef0123456789abcdef";
    assert_parsed!(parse_git_hash, hash, s!(hash));

    // An SHA1 preceded by whitespace
    assert_parsed!(parse_git_hash, b" \t 123456", s!(b"123456"));

    // An HASH terminated by a non-hex character
    assert_parsed!(parse_git_hash, b"123456:other", s!(b"123456"), s!(b":other"));

    // Invalid sequences
    assert_parse_error!(parse_git_hash, b"", StaticParseError::Unknown(
        "".to_string(),
        ErrorKind::TakeWhile1
    ));
    assert_parse_error!(parse_git_hash, b"non-hex", StaticParseError::Unknown(
        "non-hex".to_string(),
        ErrorKind::TakeWhile1
    ));
}

#[derive(Debug, PartialEq)]
enum GitMetadataLine<'a> {
    Index(&'a [u8], &'a[u8], Option<u32>),

    OldMode(u32),
    NewMode(u32),
    DeletedFileMode(u32),
    NewFileMode(u32),

    RenameFrom,
    RenameTo,

    CopyFrom,
    CopyTo,

    GitBinaryPatch,
}

fn parse_git_metadata_line(input: &[u8]) -> IResult<&[u8], GitMetadataLine, ParseError> {
    alt((
        map(delimited(tag(s!(b"index ")),
                      tuple((
                          parse_git_hash,
                          preceded(tag(s!(b"..")), parse_git_hash),
                          opt(parse_mode),
                      )),
                      newline),
            |(old_hash, new_hash, mode)| GitMetadataLine::Index(old_hash, new_hash, mode)),

        // The filename behind "rename to" and "rename from" is ignored by patch, so we ignore it too.
        map(delimited(tag(s!(b"rename from ")),
                      take_until_newline,
                      newline),
            |_| GitMetadataLine::RenameFrom),
        map(delimited(tag(s!(b"rename to ")),
                      take_until_newline,
                      newline),
            |_| GitMetadataLine::RenameTo),

        map(delimited(tag(s!(b"copy from ")),
                      take_until_newline,
                      newline),
            |_| GitMetadataLine::CopyFrom),
        map(delimited(tag(s!(b"copy to ")),
                      take_until_newline,
                      newline),
            |_| GitMetadataLine::CopyTo),

        map(delimited(tag(s!(b"GIT binary patch")),
                      take_until_newline,
                      newline),
            |_| GitMetadataLine::GitBinaryPatch),

        map(delimited(tag(s!(b"old mode ")),
                      parse_mode,
                      newline),
            |mode| GitMetadataLine::OldMode(mode)),
        map(delimited(tag(s!(b"new mode ")),
                      parse_mode,
                      newline),
            |mode| GitMetadataLine::NewMode(mode)),
        map(delimited(tag(s!(b"deleted file mode ")),
                      parse_mode,
                      newline),
            |mode| GitMetadataLine::DeletedFileMode(mode)),
        map(delimited(tag(s!(b"new file mode ")),
                      parse_mode,
                      newline),
            |mode| GitMetadataLine::NewFileMode(mode)),
    ))(input)
}

#[cfg(test)]
#[test]
fn test_parse_git_metadata_line() {
    use self::GitMetadataLine::*;

    // All of them in basic form
    assert_parsed!(parse_git_metadata_line, b"index 123456789ab..fecdba98765\n", Index(b"123456789ab", b"fecdba98765", None));
    assert_parsed!(parse_git_metadata_line, b"index 123456789ab..fecdba98765 100644\n", Index(b"123456789ab", b"fecdba98765", Some(0o100644)));

    assert_parsed!(parse_git_metadata_line, b"old mode 100644\n",         OldMode(0o100644));
    assert_parsed!(parse_git_metadata_line, b"new mode 100644\n",         NewMode(0o100644));
    assert_parsed!(parse_git_metadata_line, b"deleted file mode 100644\n", DeletedFileMode(0o100644));
    assert_parsed!(parse_git_metadata_line, b"new file mode 100644\n",    NewFileMode(0o100644));

    assert_parsed!(parse_git_metadata_line, b"rename from blabla\n", RenameFrom);
    assert_parsed!(parse_git_metadata_line, b"rename to blabla\n", RenameTo);

    assert_parsed!(parse_git_metadata_line, b"copy from blabla\n", CopyFrom);
    assert_parsed!(parse_git_metadata_line, b"copy to blabla\n", CopyTo);

    assert_parsed!(parse_git_metadata_line, b"GIT binary patch ???\n", GitBinaryPatch);
}

#[derive(Debug, PartialEq)]
enum PatchLine<'a> {
    Garbage(&'a [u8]),
    Metadata(MetadataLine<'a>),
    GitMetadata(GitMetadataLine<'a>),
    EndOfPatch,
}

fn parse_patch_line(input: &[u8]) -> IResult<&[u8], PatchLine, ParseError> {
    alt((
        map(parse_metadata_line, |line| PatchLine::Metadata(line)),
        map(take_until_newline_incl, |line| PatchLine::Garbage(line)),
        map(eof, |_| PatchLine::EndOfPatch),
    ))(input)
}

#[cfg(test)]
#[test]
fn test_parse_patch_line() {
    use self::PatchLine::*;
    use self::MetadataLine::*;

    assert_parsed!(parse_patch_line, b"diff --git aaa bbb\n", Metadata(GitDiffSeparator(Filename::Real(Cow::Owned(PathBuf::from("aaa"))), Filename::Real(Cow::Owned(PathBuf::from("bbb"))))));
    assert_parsed!(parse_patch_line, b"--- aaa\n", Metadata(MinusFilename(Filename::Real(Cow::Owned(PathBuf::from("aaa"))))));
    assert_parsed!(parse_patch_line, b"+++ bbb\n", Metadata(PlusFilename(Filename::Real(Cow::Owned(PathBuf::from("bbb"))))));

    assert_parsed!(parse_patch_line, b"Bla ble bli.\n", Garbage(b"Bla ble bli.\n"));

    assert_parsed!(parse_patch_line, b"index 0123456789a..fedcba98765 100644\n", Garbage(b"index 0123456789a..fedcba98765 100644\n"));

    assert_parsed!(parse_patch_line, b"old mode 100644\n", Garbage(b"old mode 100644\n"));
    assert_parsed!(parse_patch_line, b"new mode 100755\n", Garbage(b"new mode 100755\n"));
    assert_parsed!(parse_patch_line, b"deleted file mode 100644\n", Garbage(b"deleted file mode 100644\n"));
    assert_parsed!(parse_patch_line, b"new file mode 100644\n", Garbage(b"new file mode 100644\n"));

    assert_parsed!(parse_patch_line, b"rename from oldname\n", Garbage(b"rename from oldname\n"));
    assert_parsed!(parse_patch_line, b"rename to newname\n", Garbage(b"rename to newname\n"));
    assert_parsed!(parse_patch_line, b"copy from oldname\n", Garbage(b"copy from oldname\n"));
    assert_parsed!(parse_patch_line, b"copy to newname\n", Garbage(b"copy to newname\n"));
    assert_parsed!(parse_patch_line, b"GIT binary patch\n", Garbage(b"GIT binary patch\n"));
}

fn parse_git_patch_line(input: &[u8]) -> IResult<&[u8], PatchLine, ParseError> {
    alt((
        map(parse_metadata_line, |line| PatchLine::Metadata(line)),
        map(parse_git_metadata_line, |line| PatchLine::GitMetadata(line)),
        map(take_until_newline_incl, |line| PatchLine::Garbage(line)),
        map(eof, |_| PatchLine::EndOfPatch),
    ))(input)
}

#[cfg(test)]
#[test]
fn test_parse_git_patch_line() {
    use self::PatchLine::*;
    use self::MetadataLine::*;
    use self::GitMetadataLine::*;

    assert_parsed!(parse_git_patch_line, b"diff --git aaa bbb\n", Metadata(GitDiffSeparator(Filename::Real(Cow::Owned(PathBuf::from("aaa"))), Filename::Real(Cow::Owned(PathBuf::from("bbb"))))));
    assert_parsed!(parse_git_patch_line, b"--- aaa\n", Metadata(MinusFilename(Filename::Real(Cow::Owned(PathBuf::from("aaa"))))));

    assert_parsed!(parse_git_patch_line, b"Bla ble bli.\n", Garbage(b"Bla ble bli.\n"));

    assert_parsed!(parse_git_patch_line, b"index 0123456789a..fedcba98765 100644\n", GitMetadata(Index(b"0123456789a", b"fedcba98765", Some(0o100644))));

    assert_parsed!(parse_git_patch_line, b"old mode 100644\n",          GitMetadata(OldMode(0o100644)));
    assert_parsed!(parse_git_patch_line, b"new mode 100755\n",          GitMetadata(NewMode(0o100755)));
    assert_parsed!(parse_git_patch_line, b"deleted file mode 100644\n", GitMetadata(DeletedFileMode(0o100644)));
    assert_parsed!(parse_git_patch_line, b"new file mode 100644\n",     GitMetadata(NewFileMode(0o100644)));

    assert_parsed!(parse_git_patch_line, b"rename from oldname\n", GitMetadata(RenameFrom));
    assert_parsed!(parse_git_patch_line, b"rename to newname\n", GitMetadata(RenameTo));
    assert_parsed!(parse_git_patch_line, b"copy from oldname\n", GitMetadata(CopyFrom));
    assert_parsed!(parse_git_patch_line, b"copy to newname\n", GitMetadata(CopyTo));
    assert_parsed!(parse_git_patch_line, b"GIT binary patch\n", GitMetadata(GitBinaryPatch));
}

fn parse_number_usize(input: &[u8]) -> IResult<&[u8], usize, ParseError> {
    let (input_, digits) = take_while1(is_digit)(input)?;
    let str = std::str::from_utf8(&digits).unwrap(); // NOTE(unwrap): We know it is just digits 0-9, so it is guaranteed to be valid UTF8.
    match usize::from_str(str) {
        Ok(number) => Ok((input_, number)),
        Err(_) => Err(nom::Err::Failure(ParseError::NumberTooBig(digits))),
    }
}

#[cfg(test)]
#[test]
fn test_parse_number_usize() {
    assert_parsed!(parse_number_usize, b"0", 0);
    assert_parsed!(parse_number_usize, b"1", 1);
    assert_parsed!(parse_number_usize, b"123", 123);

    let num = "123456789012345678901234567890";
    assert_parse_error!(parse_number_usize, num.as_bytes(),
                        StaticParseError::NumberTooBig(num.to_string()));
}

// Parses line and count like "3,4" or just "3"
fn parse_hunk_line_and_count(input: &[u8]) -> IResult<&[u8], (usize, usize), ParseError> {
    pair(
        parse_number_usize,
        alt((
            preceded(
                tag(c!(b',')),
                parse_number_usize
            ),
            success(1) // If there is no ",123" part, then the line count is 1.
        ))
    )(input)
}

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

// Parses the line like "@@ -3,4 +5,6 @@ function\n"
fn parse_hunk_header(input: &[u8]) -> IResult<&[u8], HunkHeader, ParseError> {
    map(
        tuple((
            preceded(
                tag(s!(b"@@ -")),
                parse_hunk_line_and_count,
            ),

            preceded(
                tag(s!(b" +")),
                parse_hunk_line_and_count,
            ),

            delimited(
                tuple((
                    tag(s!(b" @")),
                    // The second "@" is optional. At least that's what patch accepts.
                    opt(tag(c!(b'@'))),
                    opt(tag(c!(b' '))),
                )),
                take_until_newline,
                newline,
            )
        )),
        |(remove_line_and_count, add_line_and_count, function)|
        HunkHeader {
            add_line: add_line_and_count.0,
            add_count: add_line_and_count.1,
            remove_line: remove_line_and_count.0,
            remove_count: remove_line_and_count.1,

            function: &function
        }
    )(input)
}

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

fn parse_hunk_line(input: &[u8]) -> IResult<&[u8], (HunkLineType, &[u8]), ParseError> {
    let (hunk_line_type, (input, line)) = match input.get(0) {
        Some(b'+') =>
            (HunkLineType::Add, take_until_newline_incl(&input[1..])?),
        Some(b'-') =>
            (HunkLineType::Remove, take_until_newline_incl(&input[1..])?),
        Some(b' ') =>
            (HunkLineType::Context, take_until_newline_incl(&input[1..])?),
        // XXX: patch allows context lines starting with TAB character. That TAB is then part of the line.
        Some(b'\t') =>
            (HunkLineType::Context, take_until_newline_incl(input)?),
        // XXX: patch allows completely empty line as an empty context line.
        Some(b'\n') =>
            (HunkLineType::Context, Ok((&input[1..], &input[0..1]))?),
        Some(_) => {
            return Err(nom::Err::Failure(ParseError::BadLineInHunk(input)));
        }
        None => {
            return Err(nom::Err::Error(ParseError::UnexpectedEndOfFile));
        }
    };
    // Was there "No newline..." tag?
    match input.get(0) {
        // There was, remove the newline at the end
        Some(&c) if c == NO_NEW_LINE_TAG[0] =>
            Ok((take_until_newline_incl(input)?.0, (hunk_line_type, &line[..line.len() - 1]))),
        // There wasn't, return what we have.
        _ => Ok((input, (hunk_line_type, line))),
    }
}

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

    // Localized newline...
    assert_parsed!(parse_hunk_line, "     bla ble bli;\n\\ Chybí znak konce řádku na konci souboru\n".as_bytes(), (HunkLineType::Context, s!(b"    bla ble bli;")));

    // XXX: patch specialty: See comment in `hunk_line`.
    assert_parsed!(parse_hunk_line, b"\t\n",                 (HunkLineType::Context, s!(b"\t\n")));
    assert_parsed!(parse_hunk_line, b"\taaa\n",              (HunkLineType::Context, s!(b"\taaa\n")));
    assert_parsed!(parse_hunk_line, b"\t\tbla ble bli;\n",   (HunkLineType::Context, s!(b"\t\tbla ble bli;\n")));

    // XXX: patch specialty: See comment in `hunk_line`.
    assert_parsed!(parse_hunk_line, b"\n", (HunkLineType::Context, s!(b"\n")));

    // Bad line
    assert_parse_error!(parse_hunk_line, b"wtf is this\n",
                        StaticParseError::BadLineInHunk("wtf is this".to_string()));
    assert_parse_error!(parse_hunk_line, b"wtf",
                        StaticParseError::BadLineInHunk("wtf".to_string()));
}

fn parse_hunk<'a>(input: &'a [u8]) -> IResult<&[u8], TextHunk<'a>, ParseError> {
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
        let (input_, (line_type, line)) = parse_hunk_line(input)?;

        match line_type {
            HunkLineType::Add => {
                if header.add_count == 0 {
                    return Err(nom::Err::Failure(ParseError::BadLineInHunk(input)));
                }

                hunk.add.content.push(line);
                header.add_count -= 1;

                there_was_a_non_context_line = true;
                hunk.suffix_context = 0;
            }
            HunkLineType::Remove => {
                if header.remove_count == 0 {
                    return Err(nom::Err::Failure(ParseError::BadLineInHunk(input)));
                }

                hunk.remove.content.push(line);
                header.remove_count -= 1;

                there_was_a_non_context_line = true;
                hunk.suffix_context = 0;
            }
            HunkLineType::Context => {
                if header.remove_count == 0 || header.add_count == 0 {
                    return Err(nom::Err::Failure(ParseError::BadLineInHunk(input)));
                }

                hunk.add.content.push(line);
                hunk.remove.content.push(line);
                header.add_count -= 1;
                header.remove_count -= 1;

                if !there_was_a_non_context_line {
                    hunk.prefix_context += 1;
                } else {
                    hunk.suffix_context += 1;
                }
            }
        }

        input = input_;
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

    let h = parse_hunk(hunk_txt).unwrap().1;
    assert_eq!(h.remove.target_line, 99);
    assert_eq!(h.add.target_line, 109);

    assert_eq!(&h.add.content[..], [b"aaa\n", b"bbb\n", b"ccc\n", b"eee\n", b"fff\n", b"ggg\n", b"hhh\n"]);
    assert_eq!(&h.remove.content[..], [b"aaa\n", b"bbb\n", b"ccc\n", b"ddd\n", b"ggg\n", b"hhh\n"]);

    assert_eq!(h.prefix_context, 3);
    assert_eq!(h.suffix_context, 2);

    assert_eq!(h.function, b"place");


    // Too short hunk
    let hunk_txt = br#"@@ -100,6 +110,7 @@ place
 aaa
 bbb
 ccc
"#;
    assert_parse_error!(parse_hunk, s!(hunk_txt),
                        StaticParseError::UnexpectedEndOfFile);


    // Bad line in hunk (nonsense)
    let hunk_txt = br#"@@ -100,6 +110,7 @@ place
 aaa
 bbb
 ccc
xxxxx
"#;
    assert_parse_error!(parse_hunk, s!(hunk_txt),
                        StaticParseError::BadLineInHunk("xxxxx".to_string()));


    // Bad line in hunk (unexpected '+', '-' or ' ')
    let hunk_txt = br#"@@ -100,3 +110,2 @@ place
 aaa
-bbb
-ccc
 ddd
"#;
    assert_parse_error!(parse_hunk, s!(hunk_txt),
                        StaticParseError::BadLineInHunk(" ddd".to_string()));
}

// We use hand-written function instead of just `named!` with `many1!` combinator, because `many1!`
// hides `nom::Err::Failure` errors, so they were not propagated up.
fn parse_hunks(mut input: &[u8]) -> IResult<&[u8], HunksVec<&[u8]>, ParseError> {
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
            Err(nom::Err::Error(ParseError::Unknown( .. ))) => {
                // TODO: Do anything for the case of not even one hunk?
                return Ok((input, hunks));
            }
            Err(err @ nom::Err::Failure(_)) |
            Err(err @ nom::Err::Error(_)) => {
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

    let hs = parse_hunks(hunks_txt).unwrap().1;
    assert_eq!(hs.len(), 2);

    assert_eq!(hs[0].remove.target_line, 99);
    assert_eq!(hs[1].remove.target_line, 199);

    assert_eq!(hs[0].function, b"place1");
    assert_eq!(hs[1].function, b"place2");
}

#[derive(Debug, Default)]
struct FilePatchMetadata<'a> {
    old_filename: Option<Filename<'a>>,
    new_filename: Option<Filename<'a>>,
    rename_from: bool,
    rename_to: bool,
    old_permissions: Option<Permissions>,
    new_permissions: Option<Permissions>,
    old_hash: Option<&'a [u8]>,
    new_hash: Option<&'a [u8]>,
}

impl<'a> FilePatchMetadata<'a> {
    pub fn have_filename(&self) -> bool {
        self.old_filename.is_some() || self.new_filename.is_some()
    }

    pub fn recognize_kind(&self, hunks: &[TextHunk]) -> FilePatchKind {
        // Check if the patch source or target is a zero-length file.
        if hunks.len() == 1 {
            let only_hunk = &hunks[0];

            if only_hunk.suffix_context == 0 && only_hunk.prefix_context == 0 {
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
    pub fn build_filepatch(self, hunks: HunksVec<'a, &'a [u8]>) -> Option<TextFilePatch<'a>> {
        let builder = FilePatchBuilder::<&[u8]>::default();

        // Set the kind
        let builder = builder.kind(self.recognize_kind(&hunks));

        // Set the filenames
        let has_old_filename = match self.old_filename {
            Some(Filename::Real(_)) => true,
            _ => false,
        };
        let has_new_filename = match self.new_filename {
            Some(Filename::Real(_)) => true,
            _ => false,
        };

        let builder = if self.rename_from && self.rename_to {
            // If it is renaming patch, we must have both filenames
            if !has_old_filename || !has_new_filename {
                return None;
            }

            builder.is_rename(true)
        } else {
            // If it is non-renaming patch, we must have at least one filename
            if !has_old_filename && !has_new_filename {
                return None;
            }

            builder
        };

        // Move out the filenames
        let old_filename = match self.old_filename {
            Some(Filename::Real(old_filename)) => Some(old_filename),
            _ => None,
        };
        let new_filename = match self.new_filename {
            Some(Filename::Real(new_filename)) => Some(new_filename),
            _ => None,
        };

        let builder = builder
            .old_filename(old_filename)
            .new_filename(new_filename)

            // Set the permissions
            .old_permissions(self.old_permissions)
            .new_permissions(self.new_permissions)

            // Set file hashes
            .old_hash(self.old_hash)
            .new_hash(self.new_hash)

            // Set the hunks
            .hunks(hunks);

        // Build
        Some(builder.build().unwrap()) // NOTE(unwrap): It would be our bug if we didn't provide all necessary values.
    }

    /// This function will return `None` if some necessary metadata is missing
    pub fn build_hunkless_filepatch(self) -> Option<TextFilePatch<'a>> {
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

#[derive(Debug, PartialEq)]
enum MetadataState {
    Normal,
    GitDiff,
}

fn offsetof<T>(container: &[T], slice: &[T]) -> usize
{
    (slice.as_ptr() as usize) - (container.as_ptr() as usize)
}

fn parse_filepatch<'a>(bytes: &'a [u8], mut want_header: bool)
    -> IResult<&[u8], (&'a [u8], TextFilePatch<'a>), ParseError>
{
    let mut input = bytes.clone();
    let mut header = &bytes[..0];
    let mut state = MetadataState::Normal;
    let mut extended_headers = false;

    let mut metadata = FilePatchMetadata::default();

    // First we read metadata lines or garbage and wait until we find a first hunk.
    while cond(metadata.have_filename(),
               not(parse_hunk_header))(input).is_ok() {
        let (input_, patch_line) = match state {
            MetadataState::Normal => parse_patch_line(input)?,
            MetadataState::GitDiff => parse_git_patch_line(input)?,
        };

        use self::PatchLine::*;
        use self::MetadataLine::*;
        use self::GitMetadataLine::*;

        if let GitMetadata(_) = patch_line {
            extended_headers = true;
        }

        match patch_line {
            Garbage(_) => {
                if want_header {
                    header = &bytes[..offsetof(bytes, input_)];
                }
            }

            EndOfPatch => {
                // We have reached end of file without any hunks. It
                // could be still valid patch that only renames a file or
                // changes permissions... So lets check for that.
                return if extended_headers {
                    metadata.build_hunkless_filepatch().ok_or(
                        nom::Err::Failure(ParseError::MissingFilenameForHunk(input)))
                        .map(|filepatch| (input, (header, filepatch)))
                } else {
                    Err(nom::Err::Error(ParseError::UnexpectedEndOfFile))
                };
            }

            Metadata(MetadataLine::GitDiffSeparator(old_filename, new_filename)) => {
                // No more header lines after the first non-garbage line
                want_header = false;

                // Check if it is a valid patch (see above).
                if extended_headers {
                    if let Some(filepatch) = metadata.build_hunkless_filepatch() {
                        // Note that in this case we don't set `input = input_`, because we don't want to consume the GitDiffSeparator
                        return Ok((input, (header, filepatch)));
                    }
                }

                // Otherwise it just means that everything that may have
                // looked like metadata until now was just garbage.
                header = &bytes[..offsetof(bytes, input)];

                // Reset metadata.
                metadata = FilePatchMetadata::default();
                metadata.old_filename = Some(old_filename);
                metadata.new_filename = Some(new_filename);
                state = MetadataState::GitDiff;
            }
            Metadata(PlusFilename(filename)) => {
                metadata.new_filename = Some(filename);
            }
            Metadata(MinusFilename(filename)) => {
                metadata.old_filename = Some(filename);
            }

            GitMetadata(Index(old_hash, new_hash, _)) => {
                metadata.old_hash = Some(old_hash);
                metadata.new_hash = Some(new_hash);
            }

            GitMetadata(RenameFrom) => {
                metadata.rename_from = true;
            }
            GitMetadata(RenameTo) => {
                metadata.rename_to = true;
            }

            GitMetadata(OldMode(mode)) |
            GitMetadata(DeletedFileMode(mode)) => {
                metadata.old_permissions = permissions_from_mode(mode);
            }
            GitMetadata(NewMode(mode)) |
            GitMetadata(NewFileMode(mode)) => {
                metadata.new_permissions = permissions_from_mode(mode);
            }

            GitMetadata(GitBinaryPatch) => {
                return Err(nom::Err::Failure(ParseError::UnsupportedMetadata(input)));
            }

            GitMetadata(_) => {
                // Other metadata lines are ignored for now.
                // TODO: Implement some of them...
            }
        }

        input = input_; // Move to the next line.
    }

    // Read the hunks!
    let (input_, hunks) = parse_hunks(input)?;

    // We can make our filepatch
    let filepatch = metadata.build_filepatch(hunks).ok_or(
        nom::Err::Failure(ParseError::MissingFilenameForHunk(input))
    )?;

    input = input_;
    Ok((input, (header, filepatch)))
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

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);
    assert_eq!(file_patch.hunks[0].add.content[0], s!(b"mmm\n"));

    // Regular filepatch with a funny new name
    let filepatch_txt = br#"garbage1
garbage2
garbage3
--- filename1
+++ /dev/null
@@ -200,3 +210,3 @@ place2
 mmm
-nnn
+ooo
 ppp
Some other line...
Other content.
"#;

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), None);
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

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Create);
    assert_eq!(file_patch.old_filename(), None);
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
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

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Create);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
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

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Delete);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
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

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Delete);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
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

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename2"))));
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

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename2"))));
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

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename2"))));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);


    // Garbage that looks like metadata
    let filepatch_txt = br#"garbage1
+++ garbage2
garbage3
--- filename1
+++ filename1
@@ -200,3 +210,3 @@ place2
 mmm
-nnn
+ooo
 ppp
"#;

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "+++ garbage2",
        "garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);
    assert_eq!(file_patch.hunks[0].add.content[0], s!(b"mmm\n"));


    // Garbage that looks like metadata just before a diff --git line
    let filepatch_txt = br#"garbage1
garbage2
+++ garbage3
diff --git filename1 filename1
--- filename1
+++ filename1
@@ -200,3 +210,3 @@ place2
 mmm
-nnn
+ooo
 ppp
"#;

    let (header, file_patch) = parse_filepatch(filepatch_txt, true).unwrap().1;

    assert_lines_eq!(header, [
        "garbage1",
        "garbage2",
        "+++ garbage3"]);

    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.old_permissions(), None);
    assert_eq!(file_patch.new_permissions(), None);
    assert_eq!(file_patch.hunks.len(), 1);
    assert_eq!(file_patch.hunks[0].add.content[0], s!(b"mmm\n"));


    // Unsupported metadata
    let filepatch_txt = br#"garbage1
garbage2
garbage3
diff --git filename1 filename2
GIT binary patch
???
"#;

    let ret = parse_filepatch(filepatch_txt, false);
    match ret {
        Err(nom::Err::Error(error)) |
        Err(nom::Err::Failure(error)) => {
            assert_eq!(StaticParseError::from(error),
                       StaticParseError::UnsupportedMetadata(
                           "GIT binary patch".to_string()
                       ));
        }

        _ => {
            panic!("Got unexpected success when parsing patch with unsupported metadata!");
        }
    }

    // Missing filename
    let filepatch_txt = br#"garbage1
garbage2
garbage3
--- /dev/null
+++ /dev/null
@@ -200,3 +210,3 @@ place2
 mmm
-nnn
+ooo
 ppp
"#;

    let ret = parse_filepatch(filepatch_txt, false);
    match ret {
        Err(nom::Err::Failure(error)) |
        Err(nom::Err::Error(error)) => {
            assert_eq!(StaticParseError::from(error),
                       StaticParseError::MissingFilenameForHunk(
                           "@@ -200,3 +210,3 @@ place2".to_string()
                       ));
        }

        _ => {
            panic!("Got unexpected success when parsing patch with missing filenames!");
        }
    }
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

    let (_header, file_patch) = parse_filepatch(filepatch_txt, false).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
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

    let (_header, file_patch) = parse_filepatch(filepatch_txt, false).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
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

    let (_header, file_patch) = parse_filepatch(filepatch_txt, false).unwrap().1;
    assert_eq!(file_patch.kind(), FilePatchKind::Modify);
    assert_eq!(file_patch.old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patch.old_permissions(), Some(&Permissions::from_mode(0o100644)));
    assert_eq!(file_patch.new_permissions(), Some(&Permissions::from_mode(0o100755)));
    assert_eq!(file_patch.hunks.len(), 0);
}

pub fn parse_patch(bytes: &[u8], strip: usize, mut wants_header: bool) -> Result<TextPatch, Error> {
    let mut input = bytes.clone();

    let mut header = &bytes[..0];
    let mut file_patches = Vec::<TextFilePatch>::new();

    loop {
        // Parse one filepatch at time. If it is the first one, ask it to give us its header as well.
        let (_input, (filepatch_header, mut filepatch)) = match parse_filepatch(input, wants_header) {
            // We got one
            Ok(header_and_filepatch) => header_and_filepatch,

            // No more filepatches...
            Err(nom::Err::Error(_)) => break,

            // Actual error
            Err(nom::Err::Failure(err)) => {
                return Err(failure::Error::from(StaticParseError::from(err)));
            }

            // No way this could happen
            Err(nom::Err::Incomplete(_)) => unreachable!(),
        };

        if wants_header {
            // We take header from the first FilePatch and then we don't want any more
            header = filepatch_header;
            wants_header = false;
        }

        input = _input;

        filepatch.strip(strip);
        file_patches.push(filepatch);
    }

    Ok(TextPatch {
        header,
        file_patches,
    })
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
garbage4
garbage5
--- filename2
+++ filename2
@@ -200,3 +210,3 @@ place2
 aaa
-bbb
+ccc
 ddd
garbage6
garbage7
"#;

    let patch = parse_patch(patch_txt, 0, true).unwrap();

    assert_lines_eq!(patch.header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    let file_patches = patch.file_patches;

    assert_eq!(file_patches.len(), 2);

    assert_eq!(file_patches[0].old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patches[0].new_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patches[0].hunks.len(), 1);
    assert_eq!(file_patches[0].hunks[0].add.content[0], s!(b"mmm\n"));

    assert_eq!(file_patches[1].old_filename(), Some(&Cow::Owned(PathBuf::from("filename2"))));
    assert_eq!(file_patches[1].new_filename(), Some(&Cow::Owned(PathBuf::from("filename2"))));
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

    let patch = parse_patch(patch_txt, 0, true).unwrap();

    assert_lines_eq!(patch.header, [
        "garbage1",
        "garbage2",
        "garbage3"]);

    let file_patches = patch.file_patches;

    assert_eq!(file_patches.len(), 4);

    assert_eq!(file_patches[0].old_filename(), Some(&Cow::Owned(PathBuf::from("filename1"))));
    assert_eq!(file_patches[0].new_filename(), Some(&Cow::Owned(PathBuf::from("filename2"))));
    assert_eq!(file_patches[0].hunks.len(), 0);

    assert_eq!(file_patches[1].old_filename(), Some(&Cow::Owned(PathBuf::from("filename3"))));
    assert_eq!(file_patches[1].new_filename(), Some(&Cow::Owned(PathBuf::from("filename4"))));
    assert_eq!(file_patches[1].hunks.len(), 0);

    assert_eq!(file_patches[2].old_filename(), Some(&Cow::Owned(PathBuf::from("filename5"))));
    assert_eq!(file_patches[2].new_filename(), Some(&Cow::Owned(PathBuf::from("filename6"))));
    assert_eq!(file_patches[2].hunks.len(), 1);

    assert_eq!(file_patches[3].old_filename(), Some(&Cow::Owned(PathBuf::from("filename7"))));
    assert_eq!(file_patches[3].new_filename(), Some(&Cow::Owned(PathBuf::from("filename8"))));
    assert_eq!(file_patches[3].hunks.len(), 0);

    let patch_txt = br#"Looks like git diff extended headers:
rename from old name is just garbage, no git
--- filename
+++ filename
@@ -100,2 +100,3 @@ place2
 aaa
+bbb
 ccc
"#;

    let patch = parse_patch(patch_txt, 0, true).unwrap();

    assert_lines_eq!(patch.header, [
        "Looks like git diff extended headers:",
        "rename from old name is just garbage, no git"]);

    let file_patches = patch.file_patches;

    assert_eq!(file_patches.len(), 1);

    assert_eq!(file_patches[0].old_filename(), Some(&Cow::Owned(PathBuf::from("filename"))));
    assert_eq!(file_patches[0].new_filename(), Some(&Cow::Owned(PathBuf::from("filename"))));
    assert_eq!(file_patches[0].hunks.len(), 1);
    assert_eq!(file_patches[0].hunks[0].add.content[0], s!(b"aaa\n"));
    assert_eq!(file_patches[0].hunks[0].add.content[1], s!(b"bbb\n"));
    assert_eq!(file_patches[0].hunks[0].add.content[2], s!(b"ccc\n"));

    // Misleading garbage line
    let patch_txt = br#"The following is not a patch:
8<---
@@ -465,6 +465,9 @@ static int foo(void)
 		if (aaa)
 			continue;

+		if (bbb)
+			continue;
+
 		ccc(4);
 		ddd(5);

8<---

diff --git a/filename.c b/filename.c
index 0123456789ab..cdefedcba987 100644
--- a/filename.c
+++ b/filename.c
@@ -1879,7 +1879,11 @@ static int foo(void)
 	} else
 		ok = false;
 
-	bar(&err);
+	if (ok)
+		ok = bar(&err);
+
+	if (!ok)
+		return -err;
 
 	return 0;
 }
"#;

    let patch = parse_patch(patch_txt, 0, true).unwrap();

    assert_eq!(patch.header.iter().filter(|&&c| c == b'\n').count(), 14);
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
            black_box(parse_patch(data, 1, false).unwrap());
        });
    }
}
