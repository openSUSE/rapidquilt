// Licensed under the MIT license. See LICENSE.md

use std::borrow::Cow;
use std::fs::Permissions;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::vec::Vec;

use thiserror::Error;

use crate::patch::*;
use crate::patch::unified::*;


#[derive(Debug, PartialEq)]
enum ErrorBuilder<'a> {
    NoMatch,
    UnsupportedMetadata(&'a [u8]),
    MissingFilenameForHunk(&'a [u8]),
    UnexpectedEndOfLine(&'a [u8]),
    UnexpectedEndOfFile,
    BadHunkHeader(&'a [u8]),
    BadLineInHunk(&'a [u8]),
    NumberTooBig(&'a [u8]),
    BadNumber(&'a [u8]),
    BadMode(&'a [u8]),
    BadSequence(&'a [u8]),
    BadHash(&'a [u8]),
}

fn delimited_error<F>(input: &[u8], delim: F) -> String
where
    F: FnMut(&u8) -> bool,
{
    let index = input.iter().position(delim).unwrap_or(input.len());
    String::from_utf8_lossy(&input[..index]).into()
}

fn error_line(input: &[u8]) -> String {
    delimited_error(input, |&c| c == b'\n')
}

fn error_word(input: &[u8]) -> String {
    delimited_error(input, |c|
                    !(b'0'..=b'9').contains(c) &&
                    !(b'A'..=b'Z').contains(c) &&
                    !(b'a'..=b'z').contains(c))
}

fn error_sequence(input: &[u8]) -> String {
    let index = match input.get(1) {
        None => 1,
        Some(c) => if !(b'0'..=b'3').contains(c) { 2 } else {
            match input.get(2) {
                None => 2,
                Some(c) => if !(b'0'..=b'7').contains(c) { 3 } else { 4 }
            }
        }
    };
    String::from_utf8_lossy(input.get(..index).unwrap_or(&input[..])).into()
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("Unsupported metadata: \"{0}\"")]
    UnsupportedMetadata(String),

    #[error("Could not figure out the filename for hunk \"{0}\"")]
    MissingFilenameForHunk(String),

    #[error("Unexpected end of line: {0}")]
    UnexpectedEndOfLine(String),

    #[error("Unexpected end of file")]
    UnexpectedEndOfFile,

    #[error("Malformed hunk header: \"{0}\"")]
    BadHunkHeader(String),

    #[error("Unexpected line in the middle of hunk: \"{0}\"")]
    BadLineInHunk(String),

    #[error("Number too big: \"{0}\"")]
    NumberTooBig(String),

    #[error("Invalid number: \"{0}\"")]
    BadNumber(String),

    #[error("Invalid mode: \"{0}\"")]
    BadMode(String),

    #[error("Invalid escape sequence: \"{0}\"")]
    BadSequence(String),

    #[error("Invalid object hash: \"{0}\"")]
    BadHash(String),
}

impl<'a> From<ErrorBuilder<'a>> for ParseError {
    fn from(err: ErrorBuilder) -> Self {
        use ErrorBuilder::*;
        match err {
            NoMatch =>
                unreachable!("NoMatch must be handled by the parser itself"),

            UnsupportedMetadata(input) =>
                Self::UnsupportedMetadata(error_line(input)),

            MissingFilenameForHunk(input) =>
                Self::MissingFilenameForHunk(error_line(input)),

            UnexpectedEndOfLine(input) =>
                Self::UnexpectedEndOfLine(error_line(input)),

            UnexpectedEndOfFile =>
                Self::UnexpectedEndOfFile,

            BadHunkHeader(input) =>
                Self::BadHunkHeader(error_line(input)),

            BadLineInHunk(input) =>
                Self::BadLineInHunk(error_line(input)),

            NumberTooBig(number_str) =>
                Self::NumberTooBig(String::from_utf8_lossy(number_str).to_string()),

            BadMode(input) =>
                Self::BadMode(error_word(input)),

            BadNumber(input) =>
                Self::BadNumber(error_word(input)),

            BadSequence(input) =>
                Self::BadSequence(error_sequence(input)),

            BadHash(input) =>
                Self::BadHash(error_word(input)),
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
            let ret = $parse_func($input.as_ref());
            let remain = ret.as_ref().map(|tuple| tuple.0);
            let result = ret.as_ref().map(|tuple| &tuple.1);
            assert_eq!(result, Ok(&$result), "parse result mismatch");
            assert_eq!(remain, Ok(&$remain[..]), "parse remainder mismatch");
        }
    };
}

#[cfg(test)]
macro_rules! assert_garbage {
    ( $parse_func:ident, $input:expr) => {
	assert_parsed!($parse_func, $input, Garbage($input))
    };
}

#[cfg(test)]
macro_rules! assert_parse_error {
    ( $parse_func:ident, $input:expr, $error:expr ) => {
        {
            let ret = $parse_func($input);
            match ret {
                Err(error) => {
                    assert_eq!(ParseError::from(error), $error);
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
#[cfg(test)]
macro_rules! s { ( $byte_string:expr ) => { &$byte_string[..] } }

/// Tests if `c` is an ASCII space or TAB.
fn is_space(c: u8) -> bool {
    c == b' ' ||
    c == b'\t'
}

/// Tests if `c` is a POSIX white-space character.
fn is_whitespace(c: u8) -> bool {
    c == b' ' ||
    c == 0xc ||
    c == b'\n' ||
    c == b'\r' ||
    c == b'\t' ||
    c == 0xb
}

/// Tests if `c` is an ASCII decimal digit.
fn is_digit(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}

/// Tests if `c` is an ASCII octal digit.
fn is_oct_digit(c: u8) -> bool {
    c >= b'0' && c <= b'7'
}

/// Tests if `c` is an ASCII hexadecimal digit.
fn is_hex_digit(c: u8) -> bool {
    (c >= b'0' && c <= b'9') ||
    (c >= b'a' && c <= b'f') ||
    (c >= b'A' && c <= b'F')
}

fn newline(input: &[u8]) -> Result<(&[u8], &[u8]), ErrorBuilder> {
    match input.first() {
        Some(&c) if c == b'\n' => Ok((&input[1..], &input[0..1])),
        Some(_) => Err(ErrorBuilder::NoMatch),
        None => Err(ErrorBuilder::UnexpectedEndOfFile),
    }
}

/// Takes a line from input. The newline byte is skipped but is not part
/// of the parsed line.
fn take_line_skip(input: &[u8]) -> Result<(&[u8], &[u8]), ErrorBuilder> {
    match memchr::memchr(b'\n', input) {
        Some(index) => Ok((&input[index+1..], &input[..index])),
        None => Err(ErrorBuilder::UnexpectedEndOfFile),
    }
}

/// Takes a line from input including the newline byte.
fn take_line_incl(input: &[u8]) -> Result<(&[u8], &[u8]), ErrorBuilder> {
    match memchr::memchr(b'\n', input) {
        Some(index) => Ok((&input[index+1..], &input[..index+1])),
        None => Err(ErrorBuilder::UnexpectedEndOfFile),
    }
}

/// Takes a line from input including the newline byte if present.
/// It is OK if there is no newline.
fn take_line_or_eof(input: &[u8]) -> (&[u8], &[u8]) {
    match memchr::memchr(b'\n', input) {
	Some(index) => (&input[index+1..], &input[..index+1]),
	None => (&b""[..], &input[..]),
    }
}

fn map_parsed<I, T1, T2, E, F>(parsed: Result<(I, T1), E>, f: F) -> Result<(I, T2), E>
where
    F: FnOnce(T1) -> T2,
{
    parsed.map(|(remain, value)| (remain, f(value)))
}

/// Divides a slice into two at first element that matches `pred`.
///
/// The first slice will contain the initial part of `input` where `pred`
/// returns `false`. The second part is the rest of the slice starting
/// with the first element for which `pred` returns `true`.
///
/// If `pred` is `true` for the first element of `input`, the first
/// slice will be empty, and the second slice is equal to `input`.
/// If `pred` is `false` for all elements of `input`, the second slice
/// will be empty, and the first slice is equal to `input`.
fn split_at_cond<'a, T, P>(input: &'a [T], pred: P) -> (&'a [T], &'a [T])
where
    T: Copy,
    P: Fn(T) -> bool,
{
    input.split_at(input.iter().position(|c| pred(*c)).unwrap_or(input.len()))
}

// Parses filename as-is included in the patch, delimited by first whitespace. Returns byte slice
// of the path as-is in the input data.
fn parse_filename_direct(input: &[u8]) -> Result<(&[u8], &[u8]), ErrorBuilder> {
    match split_at_cond(input, is_whitespace) {
        (name, _) if name.is_empty()
            => Err(ErrorBuilder::NoMatch),
        (name, rest)
            => Ok((rest, name)),
    }
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
fn parse_c_string(input: &[u8]) -> Result<(&[u8], Vec<u8>), ErrorBuilder> {
    if input.first() != Some(&b'\"') {
        return Err(ErrorBuilder::NoMatch);
    }
    let mut index = 1;
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
                                return Err(ErrorBuilder::BadSequence(&input[index-1..]));
                            }
                        }
                    }
                };
                res.push(c);
            }
            b'\"' => return Ok((&input[index+1..], res)),
            b'\n' => return Err(ErrorBuilder::UnexpectedEndOfLine(input)),
            other => res.push(other),
        }
        index += 1;
    }
    Err(ErrorBuilder::UnexpectedEndOfFile)
}

#[cfg(test)]
#[test]
fn test_parse_c_string() {
    macro_rules! assert_bad_sequence {
        ($input:expr, $sequence:expr) => {
            assert_eq!(parse_c_string($input)
                       .map_err(|err| ParseError::from(err)),
                       Err(ParseError::BadSequence($sequence.to_string())));
        }
    }

    // Valid escapes
    assert_parsed!(parse_c_string, b"\"BEL: \\a\"", b"BEL: \x07".to_vec());
    assert_parsed!(parse_c_string, b"\"BS: \\b\"", b"BS: \x08".to_vec());
    assert_parsed!(parse_c_string, b"\"HT: \\t\"", b"HT: \x09".to_vec());
    assert_parsed!(parse_c_string, b"\"LF: \\n\"", b"LF: \x0a".to_vec());
    assert_parsed!(parse_c_string, b"\"VT: \\v\"", b"VT: \x0b".to_vec());
    assert_parsed!(parse_c_string, b"\"FF: \\f\"", b"FF: \x0c".to_vec());
    assert_parsed!(parse_c_string, b"\"CR: \\r\"", b"CR: \x0d".to_vec());
    assert_parsed!(parse_c_string, b"\"\\\\ (backslash)\"", b"\\ (backslash)".to_vec());
    assert_parsed!(parse_c_string, b"\"\\\" (quote)\"", b"\" (quote)".to_vec());

    assert_parsed!(parse_c_string, b"\"\\141\\142\\143\"", b"abc".to_vec());
    assert_parsed!(parse_c_string, b"\"\\201\"", b"\x81".to_vec());

    // Invalid escapes
    assert_bad_sequence!(b"\"Unknown \\! escape\"", "\\!");
    assert_bad_sequence!(b"\"Unterminated \\", "\\");
    assert_bad_sequence!(b"\"One-digit octal: \\1.\"", "\\1.");
    assert_bad_sequence!(b"\"One-digit octal at end: \\1", "\\1");
    assert_bad_sequence!(b"\"Two-digit octal: \\12.\"", "\\12.");
    assert_bad_sequence!(b"\"Two-digit octal at end: \\12", "\\12");
    assert_bad_sequence!(b"\"Too big octal: \\666.\"", "\\6");

    // Unterminated strings
    let text = b"\"Sudden newline\n";
    assert_eq!(parse_c_string(text),
               Err(ErrorBuilder::UnexpectedEndOfLine(text)));

    assert_eq!(parse_c_string(b"\"End of file"),
               Err(ErrorBuilder::UnexpectedEndOfFile));

    // Unquoted string
    assert_eq!(parse_c_string(b"no quote at the beginning"),
               Err(ErrorBuilder::NoMatch))
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
fn parse_filename(input: &[u8]) -> Result<(&[u8], Filename), ErrorBuilder> {
    let (_, input) = split_at_cond(input, |c| !is_space(c));

    // First attempt to parse it as quoted filename. This will reject it
    // quickly if it does not start with a '"' character.
    if let Ok((remain, filename_vec)) = parse_c_string(input) {
        if &filename_vec[..] == NULL_FILENAME {
            Ok((remain, Filename::DevNull))
        } else {
            let pathbuf = match () {
                #[cfg(unix)]
                () => {
                    // We have an owned buffer, which must be turned into
                    // an allocated `PathBuf`, but no conversion of encoding
                    // is necessary on unix systems.

                    use std::ffi::OsString;
                    use std::os::unix::ffi::OsStringExt;
                    PathBuf::from(OsString::from_vec(filename_vec))
                }

                #[cfg(not(unix))]
                () => {
                    // In non-unix systems, we don't know how `Path` is
                    // represented, so we can not just take the byte slice
                    // and use it as `Path`. For example on Windows
                    // paths are a form of UTF-16, while the content of
                    // patch file has undefined encoding and we assume
                    // UTF-8. So, conversion must happen.

                    PathBuf::from(String::from_utf8_lossy(bytes).owned())
                }
            };

            Ok((remain, Filename::Real(Cow::Owned(pathbuf))))
        }
    } else {
        // Then attempt to parse it as direct filename (without quotes, spaces or escapes)
        let (remain, filename) = parse_filename_direct(input)?;
        if &filename[..] == NULL_FILENAME {
            Ok((remain, Filename::DevNull))
        } else {
            let path = match () {
                #[cfg(unix)]
                () => {
                    // We have a byte slice, which can be wraped into
                    // a `Path` and used without any heap allocation.

                    use std::ffi::OsStr;
                    use std::os::unix::ffi::OsStrExt;
                    Cow::Borrowed(Path::new(OsStr::from_bytes(filename)))
                }

                #[cfg(not(unix))]
                () => {
                    // In non-unix systems, conversion must happen.
                    // See above.

                    Cow::Owned(PathBuf::from(String::from_utf8_lossy(bytes).owned()))
                }
            };

            Ok((remain, Filename::Real(path)))
        }
    }
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

    // Invalid quoted filenames
    assert_path!(b"\"Unterminated quotes", "\"Unterminated", b" quotes");
    assert_path!(b"\"Sudden newline\n", "\"Sudden", b" newline\n");
    assert_path!(b"\"\\999 (quoted)\"", "\"\\999", b" (quoted)\"");

    assert_parsed!(parse_filename, b"/dev/null", Filename::DevNull);
    assert_parsed!(parse_filename, b"\"/dev/null\"", Filename::DevNull);

    assert_eq!(parse_filename(b"  \n"), Err(ErrorBuilder::NoMatch));
}

/// Similar to `fetchmode` function in patch.
fn parse_mode(input: &[u8]) -> Result<(&[u8], u32), ErrorBuilder> {
    let (_, input) = split_at_cond(input, |c| !is_space(c));
    let (digits, input_) = split_at_cond(input, |c| !is_oct_digit(c));

    if digits.is_empty() {
        return Err(ErrorBuilder::NoMatch);
    }
    if digits.len() != 6 { // This is what patch requires, but otherwise it fallbacks to 0, so maybe we should too?
        return Err(ErrorBuilder::BadMode(input));
    }

    let mode_str = std::str::from_utf8(&digits).unwrap(); // NOTE(unwrap): We know it is just digits 0-7, so it is guaranteed to be valid UTF8.
    match u32::from_str_radix(mode_str, 8) {
        Ok(number) => Ok((input_, number)),
        Err(_) => Err(ErrorBuilder::BadMode(input)),
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
                ParseError::BadMode(mode.to_string()));
        };
    );

    assert_parsed!(parse_mode, b"123456", 0o123456);
    assert_parsed!(parse_mode, b"012345", 0o12345);
    assert_parsed!(parse_mode, b"   123456", 0o123456);
    assert_parsed!(parse_mode, b"   012345", 0o12345);

    assert_parsed!(parse_mode, b"100755", 0o100755);
    assert_parsed!(parse_mode, b"100644", 0o100644);

    assert_eq!(parse_mode(b""), Err(ErrorBuilder::NoMatch));
    assert_eq!(parse_mode(b"x"), Err(ErrorBuilder::NoMatch));

    assert_bad_mode!("100aaa");
    assert_bad_mode!("1");
    assert_bad_mode!("10000000");
    assert_bad_mode!("1000000000000000000000000000");

    // Report only the mode, not the rest of the line
    assert_parse_error!(
        parse_mode, b"100abc, more input here",
                ParseError::BadMode("100abc".to_string()));
}

#[derive(Debug, PartialEq)]
enum MetadataLine<'a> {
    GitDiffSeparator(Filename<'a>, Filename<'a>),

    MinusFilename(Filename<'a>),
    PlusFilename(Filename<'a>),

    // ...?
}

fn parse_metadata_line(input: &[u8]) -> Result<(&[u8], MetadataLine), ErrorBuilder> {
    match input.first().ok_or(ErrorBuilder::NoMatch)? {
        b'd' => {
            if let Some(input) = input.strip_prefix(b"diff --git ") {
                let (input, old_filename) = parse_filename(input)?;
                let (input, new_filename) = parse_filename(input)?;
                let (input, _) = take_line_incl(input)?;
                return Ok((input, MetadataLine::GitDiffSeparator(old_filename, new_filename)))
            }
        }
        b'-' => {
            if let Some(input) = input.strip_prefix(b"--- ") {
                let (input, filename) = parse_filename(input)?;
                let (input, _) = take_line_incl(input)?;
                return Ok((input, MetadataLine::MinusFilename(filename)));
            }
        }
        b'+' => {
            if let Some(input) = input.strip_prefix(b"+++ ") {
                let (input, filename) = parse_filename(input)?;
                let (input, _) = take_line_incl(input)?;
                return Ok((input, MetadataLine::PlusFilename(filename)));
            }
        }
        _ => {}
    }
    Err(ErrorBuilder::NoMatch)
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
fn parse_git_hash(input: &[u8]) -> Result<(&[u8], &[u8]), ErrorBuilder> {
    match split_at_cond(input, |c| !is_hex_digit(c)) {
        (name, _) if name.is_empty()
            => Err(ErrorBuilder::BadHash(input)),
        (name, rest)
            => Ok((rest, name)),
    }
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

    // An HASH terminated by a non-hex character
    assert_parsed!(parse_git_hash, b"123456:other", s!(b"123456"), s!(b":other"));

    // Invalid sequences
    assert_parse_error!(parse_git_hash, b"",
                        ParseError::BadHash("".to_string()));

    assert_parse_error!(parse_git_hash, b" \t 123456",
                        ParseError::BadHash("".to_string()));

    assert_parse_error!(parse_git_hash, b"non-hex",
                        ParseError::BadHash("non".to_string()));
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

fn parse_git_metadata_line(input: &[u8]) -> Result<(&[u8], GitMetadataLine), ErrorBuilder> {
    match input.first().ok_or(ErrorBuilder::NoMatch)? {
        b'i' => {
            if let Some(input) = input.strip_prefix(b"index ") {
                let (input, old_hash) = parse_git_hash(input)?;
                let input = input.strip_prefix(b"..")
                    .ok_or(ErrorBuilder::NoMatch)?;
                let (input, new_hash) = parse_git_hash(input)?;
                let (input, mode) = map_parsed(parse_mode(input), Some)
                    .unwrap_or((input, None));
                let (input, _) = newline(input)?;
                return Ok((input, GitMetadataLine::Index(old_hash, new_hash, mode)));
            }
        }
        b'r' => {
            if let Some(input) = input.strip_prefix(b"rename from ") {
                // The filename behind "rename to" and "rename from" is ignored by patch, so we ignore it too.
                let (input, _) = take_line_skip(input)?;
                return Ok((input, GitMetadataLine::RenameFrom));
            } else if let Some(input) = input.strip_prefix(b"rename to ") {
                let (input, _) = take_line_skip(input)?;
                return Ok((input, GitMetadataLine::RenameTo));
            }
        }
        b'c' => {
            if let Some(input) = input.strip_prefix(b"copy from ") {
                let (input, _) = take_line_skip(input)?;
                return Ok((input, GitMetadataLine::CopyFrom));
            } else if let Some(input) = input.strip_prefix(b"copy to ") {
                let (input, _) = take_line_skip(input)?;
                return Ok((input, GitMetadataLine::CopyTo));
            }
        }
        b'G' => {
            if let Some(input) = input.strip_prefix(b"GIT binary patch") {
                let (input, _) = take_line_skip(input)?;
                return Ok((input, GitMetadataLine::GitBinaryPatch));
            }
        }
        b'o' => {
            if let Some(input) = input.strip_prefix(b"old mode ") {
                let (input, mode) = parse_mode(input)?;
                let (input, _) = newline(input)?;
                return Ok((input, GitMetadataLine::OldMode(mode)));
            }
        }
        b'n' => {
            if let Some(input) = input.strip_prefix(b"new mode ") {
                let (input, mode) = parse_mode(input)?;
                let (input, _) = newline(input)?;
                return Ok((input, GitMetadataLine::NewMode(mode)));
            } else if let Some(input) = input.strip_prefix(b"new file mode ") {
                let (input, mode) = parse_mode(input)?;
                let (input, _) = newline(input)?;
                return Ok((input, GitMetadataLine::NewFileMode(mode)));
            }
        }
        b'd' => {
            if let Some(input) = input.strip_prefix(b"deleted file mode ") {
                let (input, mode) = parse_mode(input)?;
                let (input, _) = newline(input)?;
                return Ok((input, GitMetadataLine::DeletedFileMode(mode)));
            }
        }
        _ => {}
    }
    Err(ErrorBuilder::NoMatch)
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

    // Random garbage
    assert_eq!(parse_git_metadata_line(b"Bla ble bli.\n"),
               Err(ErrorBuilder::NoMatch));
}

#[derive(Debug, PartialEq)]
enum PatchLine<'a> {
    Garbage(&'a [u8]),
    Metadata(MetadataLine<'a>),
    GitMetadata(GitMetadataLine<'a>),
    EndOfPatch,
}

fn parse_patch_line(input: &[u8]) -> Result<(&[u8], PatchLine), ErrorBuilder> {
    map_parsed(parse_metadata_line(input), PatchLine::Metadata)
	.or_else(|_| input.is_empty().then(|| Ok((input, PatchLine::EndOfPatch)))
		 .unwrap_or_else(|| map_parsed(Ok(take_line_or_eof(input)), PatchLine::Garbage)))
}

#[cfg(test)]
#[test]
fn test_parse_patch_line() {
    use self::PatchLine::*;
    use self::MetadataLine::*;

    assert_parsed!(parse_patch_line, b"diff --git aaa bbb\n", Metadata(GitDiffSeparator(Filename::Real(Cow::Owned(PathBuf::from("aaa"))), Filename::Real(Cow::Owned(PathBuf::from("bbb"))))));
    assert_parsed!(parse_patch_line, b"--- aaa\n", Metadata(MinusFilename(Filename::Real(Cow::Owned(PathBuf::from("aaa"))))));
    assert_parsed!(parse_patch_line, b"+++ bbb\n", Metadata(PlusFilename(Filename::Real(Cow::Owned(PathBuf::from("bbb"))))));

    assert_garbage!(parse_patch_line, b"Bla ble bli.\n");

    assert_garbage!(parse_patch_line, b"index 0123456789a..fedcba98765 100644\n");

    assert_garbage!(parse_patch_line, b"old mode 100644\n");
    assert_garbage!(parse_patch_line, b"new mode 100755\n");
    assert_garbage!(parse_patch_line, b"deleted file mode 100644\n");
    assert_garbage!(parse_patch_line, b"new file mode 100644\n");

    assert_garbage!(parse_patch_line, b"rename from oldname\n");
    assert_garbage!(parse_patch_line, b"rename to newname\n");
    assert_garbage!(parse_patch_line, b"copy from oldname\n");
    assert_garbage!(parse_patch_line, b"copy to newname\n");
    assert_garbage!(parse_patch_line, b"GIT binary patch\n");

    assert_parsed!(parse_patch_line, b"", EndOfPatch);

    assert_garbage!(parse_patch_line, b"No newline at EOF");
}

fn parse_git_patch_line(input: &[u8]) -> Result<(&[u8], PatchLine), ErrorBuilder> {
    map_parsed(parse_metadata_line(input), PatchLine::Metadata)
        .or_else(|_| map_parsed(parse_git_metadata_line(input), PatchLine::GitMetadata))
        .or_else(|_| map_parsed(take_line_incl(input), PatchLine::Garbage))
        .or_else(|_| input.is_empty().then(|| Ok((input, PatchLine::EndOfPatch)))
		 .unwrap_or_else(|| map_parsed(Ok(take_line_or_eof(input)), PatchLine::Garbage)))
}

#[cfg(test)]
#[test]
fn test_parse_git_patch_line() {
    use self::PatchLine::*;
    use self::MetadataLine::*;
    use self::GitMetadataLine::*;

    assert_parsed!(parse_git_patch_line, b"diff --git aaa bbb\n", Metadata(GitDiffSeparator(Filename::Real(Cow::Owned(PathBuf::from("aaa"))), Filename::Real(Cow::Owned(PathBuf::from("bbb"))))));
    assert_parsed!(parse_git_patch_line, b"--- aaa\n", Metadata(MinusFilename(Filename::Real(Cow::Owned(PathBuf::from("aaa"))))));

    assert_garbage!(parse_git_patch_line, b"Bla ble bli.\n");

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

    assert_parsed!(parse_git_patch_line, b"", EndOfPatch);

    assert_garbage!(parse_git_patch_line, b"No newline at EOF");
}

fn parse_number_usize(input: &[u8]) -> Result<(&[u8], usize), ErrorBuilder> {
    let (digits, input_) = split_at_cond(input, |c| !is_digit(c));
    if digits.is_empty() {
        return Err(ErrorBuilder::BadNumber(input));
    }
    let str = std::str::from_utf8(&digits).unwrap(); // NOTE(unwrap): We know it is just digits 0-9, so it is guaranteed to be valid UTF8.
    match usize::from_str(str) {
        Ok(number) => Ok((input_, number)),
        Err(_) => Err(ErrorBuilder::NumberTooBig(digits)),
    }
}

#[cfg(test)]
#[test]
fn test_parse_number_usize() {
    assert_parsed!(parse_number_usize, b"0", 0);
    assert_parsed!(parse_number_usize, b"1", 1);
    assert_parsed!(parse_number_usize, b"123", 123);

    let num = "";
    assert_parse_error!(parse_number_usize, num.as_bytes(),
                        ParseError::BadNumber(num.to_string()));

    let num = "xyz";
    assert_parse_error!(parse_number_usize, num.as_bytes(),
                        ParseError::BadNumber(num.to_string()));

    let num = "123456789012345678901234567890";
    assert_parse_error!(parse_number_usize, num.as_bytes(),
                        ParseError::NumberTooBig(num.to_string()));
}

// Parses line and count like "3,4" or just "3"
fn parse_hunk_line_and_count(input: &[u8]) -> Result<(&[u8], (usize, usize)), ErrorBuilder> {
    let (input, line) = parse_number_usize(input)?;
    if input.first() == Some(&b',') {
        let (input, count) = parse_number_usize(&input[1..])?;
        Ok((input, (line, count)))
    } else {
        // If there is no ",123" part, then the line count is 1.
        Ok((input, (line, 1)))
    }
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

/// Parses a line like "@@ -3,4 +5,6 @@ function\n"
fn parse_hunk_header(input: &[u8]) -> Result<(&[u8], HunkHeader), ErrorBuilder> {
    let input = input.strip_prefix(b"@@ -")
        .ok_or(ErrorBuilder::NoMatch)?;

    let (input, (remove_line, remove_count)) = parse_hunk_line_and_count(input)
        .map_err(|_| ErrorBuilder::BadHunkHeader(input))?;
    let input = input.strip_prefix(b" +")
        .ok_or_else(|| ErrorBuilder::BadHunkHeader(input))?;
    let (input, (add_line, add_count)) = parse_hunk_line_and_count(input)
        .map_err(|_| ErrorBuilder::BadHunkHeader(input))?;
    let input = input.strip_prefix(b" @")
        .ok_or_else(|| ErrorBuilder::BadHunkHeader(input))?;

    // Parse function if it is separated by " @@ "
    let (input, function) = match input.strip_prefix(b"@ ") {
        Some(input) =>
            take_line_skip(input)?,
        None =>
            map_parsed(take_line_incl(input), |_| &b""[..])?,
    };

    Ok((input,
        HunkHeader {
            add_line, add_count,
            remove_line, remove_count,
            function
        }
    ))
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

    let h4 = HunkHeader {
        add_line: 3,
        add_count: 4,
        remove_line: 1,
        remove_count: 2,

        function: s!(b""),
    };
    assert_parsed!(parse_hunk_header, b"@@ -1,2 +3,4 @@function name\n", h4);
    assert_parsed!(parse_hunk_header, b"@@ -1,2 +3,4 @function name\n", h4);
    assert_parsed!(parse_hunk_header, b"@@ -1,2 +3,4 @ function name\n", h4);

    // garbage with EOL
    assert_eq!(parse_hunk_header(b"\n"), Err(ErrorBuilder::NoMatch));
    assert_eq!(parse_hunk_header(b"some garbage\n"), Err(ErrorBuilder::NoMatch));

    // garbage without EOL
    assert_eq!(parse_hunk_header(b""), Err(ErrorBuilder::NoMatch));
    assert_eq!(parse_hunk_header(b"some garbage"), Err(ErrorBuilder::NoMatch));

    assert_parse_error!(parse_hunk_header, b"@@ - invalid\n",
                        ParseError::BadHunkHeader(" invalid".to_string()));
}

#[derive(Debug, PartialEq)]
enum HunkLineType {
    Add,
    Remove,
    Context,
}

fn parse_hunk_line(input: &[u8]) -> Result<(&[u8], (HunkLineType, &[u8])), ErrorBuilder> {
    let (hunk_line_type, (input, line)) = match input.first() {
        Some(b'+') =>
            (HunkLineType::Add, take_line_incl(&input[1..])?),
        Some(b'-') =>
            (HunkLineType::Remove, take_line_incl(&input[1..])?),
        Some(b' ') =>
            (HunkLineType::Context, take_line_incl(&input[1..])?),
        // XXX: patch allows context lines starting with TAB character. That TAB is then part of the line.
        Some(b'\t') =>
            (HunkLineType::Context, take_line_incl(input)?),
        // XXX: patch allows completely empty line as an empty context line.
        Some(b'\n') =>
            (HunkLineType::Context, (&input[1..], &input[..1])),
        Some(_) =>
            return Err(ErrorBuilder::BadLineInHunk(input)),
        None =>
            return Err(ErrorBuilder::UnexpectedEndOfFile),
    };
    // Was there "No newline..." tag?
    match input.first() {
        // There was, remove the newline at the end
        Some(&c) if c == NO_NEW_LINE_TAG[0] =>
            Ok((take_line_incl(input)?.0, (hunk_line_type, &line[..line.len() - 1]))),
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
                        ParseError::BadLineInHunk("wtf is this".to_string()));
    assert_parse_error!(parse_hunk_line, b"wtf",
                        ParseError::BadLineInHunk("wtf".to_string()));
}

fn parse_hunk(input: &[u8]) -> Result<(&[u8], TextHunk), ErrorBuilder> {
    let (mut input, mut header) = parse_hunk_header(input)
        .map_err(|err| if err == ErrorBuilder::NoMatch { err } else {
            ErrorBuilder::BadHunkHeader(input)
        })?;

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
                    return Err(ErrorBuilder::BadLineInHunk(input));
                }

                hunk.add.content.push(line);
                header.add_count -= 1;

                there_was_a_non_context_line = true;
                hunk.suffix_context = 0;
            }
            HunkLineType::Remove => {
                if header.remove_count == 0 {
                    return Err(ErrorBuilder::BadLineInHunk(input));
                }

                hunk.remove.content.push(line);
                header.remove_count -= 1;

                there_was_a_non_context_line = true;
                hunk.suffix_context = 0;
            }
            HunkLineType::Context => {
                if header.remove_count == 0 || header.add_count == 0 {
                    return Err(ErrorBuilder::BadLineInHunk(input));
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
                        ParseError::UnexpectedEndOfFile);


    // Bad line in hunk (nonsense)
    let hunk_txt = br#"@@ -100,6 +110,7 @@ place
 aaa
 bbb
 ccc
xxxxx
"#;
    assert_parse_error!(parse_hunk, s!(hunk_txt),
                        ParseError::BadLineInHunk("xxxxx".to_string()));


    // Bad line in hunk (unexpected '+', '-' or ' ')
    let hunk_txt = br#"@@ -100,3 +110,2 @@ place
 aaa
-bbb
-ccc
 ddd
"#;
    assert_parse_error!(parse_hunk, s!(hunk_txt),
                        ParseError::BadLineInHunk(" ddd".to_string()));

    // Invalid hunk header
    assert_parse_error!(parse_hunk, b"@@ - invalid\n",
                        ParseError::BadHunkHeader("@@ - invalid".to_string()));
}

fn parse_hunks(mut input: &[u8]) -> Result<(&[u8], HunksVec<&[u8]>), ErrorBuilder> {
    let mut hunks = HunksVec::<&[u8]>::new();
    loop {
        match parse_hunk(input) {
            Ok((input_, hunk)) => {
                hunks.push(hunk);
                input = input_;
            }
            Err(ErrorBuilder::NoMatch) =>
                // TODO: Do anything for the case of not even one hunk?
                return Ok((input, hunks)),
            Err(err) =>
                return Err(err),
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

fn parse_filepatch(bytes: &[u8], mut want_header: bool)
    -> Result<(&[u8], (&[u8], TextFilePatch)), ErrorBuilder>
{
    let mut input = bytes;
    let mut header = &bytes[..0];
    let mut state = MetadataState::Normal;
    let mut extended_headers = false;

    let mut metadata = FilePatchMetadata::default();

    // First we read metadata lines or garbage and wait until we find a first hunk.
    while !metadata.have_filename() || parse_hunk_header(input) == Err(ErrorBuilder::NoMatch) {
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
                        ErrorBuilder::MissingFilenameForHunk(input))
                        .map(|filepatch| (input, (header, filepatch)))
                } else {
                    Err(ErrorBuilder::NoMatch)
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
                return Err(ErrorBuilder::UnsupportedMetadata(input));
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
        ErrorBuilder::MissingFilenameForHunk(input)
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
        Err(error) => {
            assert_eq!(ParseError::from(error),
                       ParseError::UnsupportedMetadata(
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
        Err(error) => {
            assert_eq!(ParseError::from(error),
                       ParseError::MissingFilenameForHunk(
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

pub fn parse_patch(bytes: &[u8], strip: usize, mut wants_header: bool) -> Result<TextPatch, ParseError> {
    let mut input = bytes;

    let mut header = &bytes[..0];
    let mut file_patches = Vec::<TextFilePatch>::new();

    loop {
        // Parse one filepatch at time. If it is the first one, ask it to give us its header as well.
        let (_input, (filepatch_header, mut filepatch)) = match parse_filepatch(input, wants_header) {
            // We got one
            Ok(header_and_filepatch) => header_and_filepatch,

            // No more filepatches...
            Err(ErrorBuilder::NoMatch) => break,

            // Actual error
            Err(err) => {
                return Err(ParseError::from(err));
            }
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
