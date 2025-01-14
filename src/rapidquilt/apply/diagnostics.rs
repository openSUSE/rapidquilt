// Licensed under the MIT license. See LICENSE.md

//! This module contains functions for diagnosing and reporting patch apply
//! failure. Performance is less important for these functions, since they are
//! called only few times when there was application failure. The priority is
//! to provide user-friendly report.

use std::borrow::Cow;
use std::cmp::{min, max};
use std::collections::HashMap;
use std::fmt::Write;
use std::hash::BuildHasher;
use std::io::{self, Write as IoWrite};

use std::path::Path;

use colored::*;
use anyhow::Result;
use libpatch::analysis::{AnalysisSet, Note, NoteSeverity, fn_analysis_note_noop};
use libpatch::modified_file::ModifiedFile;

use libpatch::patch::{
    TextFilePatch,
    TextHunk,
    HunkApplyFailureReason,
    HunkApplyReport,
    HunkPosition,
    PatchDirection
};
use libpatch::patch::unified::writer::UnifiedPatchHunkHeaderWriter;
use libpatch::patch::FilePatchApplyReport;

use crate::apply::common::*;
use crate::apply::Verbosity;


/// Try if the patch would apply with some fuzz. It doesn't do any permanent changes.
pub fn test_apply_with_fuzzes<'arena, H: BuildHasher>(
    patch_status: &PatchStatus,
    modified_files: &HashMap<Cow<'arena, Path>, ModifiedFile, H>)
    -> Option<usize>
{
    let file = modified_files.get(&patch_status.final_filename).unwrap(); // NOTE(unwrap): It must be there, otherwise we got bad modified_files, which would be bug.

    // Make our own copy for experiments
    let mut file = file.clone();

    // Rollback the failed application
    patch_status.file_patch.rollback(&mut file, PatchDirection::Forward, &patch_status.report);

    let current_fuzz = patch_status.report.max_fuzz();
    let max_fuzz = patch_status.file_patch.max_useable_fuzz();

    if current_fuzz >= max_fuzz {
        return None;
    }

    for fuzz in (current_fuzz + 1)..=max_fuzz {
        // Make another copy for test application
        let mut file = file.clone();

        let report = patch_status.file_patch.apply(&mut file, PatchDirection::Forward, fuzz, &AnalysisSet::default(), &fn_analysis_note_noop);

        if report.ok() {
            return Some(fuzz);
        }
    }

    None
}

pub fn test_apply_after_reverting_other<'arena, H: BuildHasher>(
    failed_patch_status: &PatchStatus,
    suspect_patch_status: &PatchStatus,
    modified_files: &HashMap<Cow<'arena, Path>, ModifiedFile, H>)
    -> bool
{
    let file = modified_files.get(&failed_patch_status.final_filename).unwrap(); // NOTE(unwrap): It must be there, otherwise we got bad modified_files, which would be bug.

    // Make our own copy for experiments
    let mut file = file.clone();

    // Rollback the failed application
    failed_patch_status.file_patch.rollback(&mut file, PatchDirection::Forward, &failed_patch_status.report);

    // Revert the suspect
    let revert_report = suspect_patch_status.file_patch.apply(&mut file, PatchDirection::Revert, suspect_patch_status.report.max_fuzz(), &AnalysisSet::default(), &fn_analysis_note_noop);
    if revert_report.failed() {
        // If we couldn't even revert the suspect, we can't test anything
        return false;
    }

    // Try to apply our failed patch again
    let apply_report = failed_patch_status.file_patch.apply(&mut file, PatchDirection::Forward, failed_patch_status.report.max_fuzz(), &AnalysisSet::default(), &fn_analysis_note_noop);

    // Report whether it would apply ok now
    apply_report.ok()
}

/// Render a report into `writer` about why the `broken_patch_index` failed to
/// apply.
pub fn analyze_patch_failure<'arena, H: BuildHasher, W: Write>(
    verbosity: Verbosity,
    broken_patch_index: usize,
    applied_patches: &Vec<PatchStatus<'arena, '_>>,
    modified_files: &HashMap<Cow<'arena, Path>, ModifiedFile, H>,
    writer: &mut W)
    -> Result<()>
{
    for patch_status in applied_patches.iter().rev() {
        if patch_status.index != broken_patch_index {
            break;
        }

        write!(writer, "  {} {} ", "File".yellow(), patch_status.target_filename.display())?;

        if patch_status.report.ok() {
            writeln!(writer, "{}", "OK".bright_green().bold())?;
        } else {
            writeln!(writer, "{}", "FAILED".bright_red().bold())?;

            for (i, hunk_report) in patch_status.report.hunk_reports().iter().enumerate() {
                write!(writer, "    {} #{}: ", "Hunk".yellow(), i + 1)?;

                match hunk_report {
                    HunkApplyReport::Applied { offset, .. } => {
                        write!(writer, "{}", "OK".bright_green().bold())?;

                        if *offset != 0 {
                            write!(writer, " with offset {}", offset)?;
                        } else {
                            write!(writer, "     ")?; // Spaces to balance width of "failed " and "skipped"
                        }
                    }

                    HunkApplyReport::Failed(reason) => {
                        write!(writer, "{}", "FAILED ".bright_red().bold())?;

                        let reason_str = match reason {
                            HunkApplyFailureReason::NoMatchingLines =>
                                // This is the "normal" reason, no need to print
                                // any additional info.
                                None,

                            HunkApplyFailureReason::FileDoesNotExist =>
                                Some("Can not find file to patch."),

                            HunkApplyFailureReason::CreatingFileThatExists =>
                                Some("Attempting to create file that already exists."),

                            HunkApplyFailureReason::DeletingFileThatDoesNotMatch =>
                                Some("Attempting to delete file with content that does not match."),

                            HunkApplyFailureReason::MisorderedHunks =>
                                Some("Misordered hunks! The hunk would modify content before (or overlapping) some previous hunk."),
                        };

                        if let Some(reason_str) = reason_str {
                            write!(writer, "{}", reason_str.bright_red())?;
                        }
                    }
                }

                let mut buf = Vec::<u8>::new();
                patch_status.file_patch.hunks()[i].write_header_to(&mut buf)?;
                writeln!(writer, "\t{}", String::from_utf8_lossy(&buf).bright_blue())?;

                if let HunkApplyReport::Failed(HunkApplyFailureReason::NoMatchingLines) = hunk_report {
                    if verbosity >= Verbosity::Normal {
                        print_difference_to_closest_match(&patch_status.report,
                                                          &patch_status.file_patch.hunks()[i],
                                                          &modified_files[&patch_status.target_filename],
                                                          writer,
                                                          "      ")?;
                    }
                }
            }

            if verbosity >= Verbosity::Normal {
                // Find which other patches touched this file
                let mut other_patches = Vec::<(&Path, bool)>::new();
                for other_patch_status in applied_patches.iter() {
                    if other_patch_status.index >= broken_patch_index {
                        break;
                    }

                    // TODO: Follow thru renames?

                    if other_patch_status.target_filename == patch_status.target_filename {
                        let is_suspect = test_apply_after_reverting_other(patch_status, other_patch_status, modified_files);

                        other_patches.push((other_patch_status.patch_filename, is_suspect));
                    }
                }

                // Fuzz hint
                writeln!(writer)?;
                if let Some(working_fuzz) = test_apply_with_fuzzes(patch_status, modified_files) {
                    write!(writer, "    {} Patch would apply on this file with fuzz {}", "hint:".purple(), working_fuzz)?;
                } else {
                    write!(writer, "    {} Patch would not apply on this file with any fuzz", "hint:".purple())?;
                }
                writeln!(writer)?;

                // Other patches hint
                writeln!(writer)?;
                write!(writer, "    {} ", "hint:".purple())?;

                if other_patches.is_empty() {
                    writeln!(writer, "No previous patches touched this file.")?;
                } else {
                    writeln!(writer, "{} previous patches touched this file:", other_patches.len())?;

                    let mut any_suspect = false;
                    for (other_patch, is_suspect) in other_patches {
                        write!(writer, "      {}", other_patch.display())?;
                        if is_suspect {
                            write!(writer, " {}", " !".bright_red())?;
                            any_suspect = true;
                        }
                        writeln!(writer)?;
                    }

                    if any_suspect {
                        writeln!(writer)?;
                        writeln!(writer, "      {} = Reverting the patch fixes this failure.", "!".bright_red())?;
                    }
                }
            }

            writeln!(writer)?;
        }
    }

    Ok(())
}

/// Tests if `c` is a space, TAB or newline
fn is_space(c: u8) -> bool {
    c == b' ' ||
    c == b'\t' ||
    c == b'\n'
}

fn contains_only_space(line: &[u8]) -> bool
{
    !line.iter().any(|&byte| !is_space(byte))
}

fn compare_ignore_space(a: &[u8], b: &[u8]) -> bool
{
    let mut b_iter = b.iter();
    for &a_byte in a {
        if is_space(a_byte) {
            continue;
        }
        loop {
            let &b_byte = match b_iter.next() {
                Some(n) => n,
                None => return false,
            };
            if b_byte == a_byte {
                break;
            } else if !is_space(b_byte) {
                return false;
            }
        }
    }
    !b_iter.any(|&b_byte| !is_space(b_byte))
}

/// Cost of one line of difference. The value of 256 allows up to 16M lines
/// without overflowing usize even on 32-bit platforms. By choosing a power
/// of two, the compiler can (hopefully) optimize the multiplication to a
/// bit shift. By choosing a bit shift of 8, it may also use a byte shift
/// on platforms where that would be more efficient.
const SCORE_SCALE: usize = 256;

type Matches = Vec<Vec<usize>>;

type MatchPos = (usize, usize);

/// Matches for the first step (fan out to the first matched line)
struct FirstStepMatches<'a> {
    matches: &'a Matches,
    line_index: usize,
    match_index: usize,
    target_line: usize,
    file_length: usize,
}

impl<'a> FirstStepMatches<'a> {
    pub fn new(
	matches: &'a Matches,
	target_line: usize,
	file_length: usize)
	-> Self
    {
	Self {
	    matches,
	    target_line,
	    file_length,
	    line_index: 0,
	    match_index: 0,
	}
    }

    pub fn next(&mut self)
	-> Option<(MatchPos, usize)>
    {
	while let Some(line_matches) = &self.matches.get(self.line_index) {
	    if let Some(&file_line) = &line_matches.get(self.match_index) {
		let match_index = self.match_index;
		self.match_index += 1;

		let line_diff = if file_line < self.target_line {
		    self.target_line - file_line
		} else {
		    file_line - self.target_line
		};
		let cost =
		    // skipped lines at hunk beginning
		    SCORE_SCALE * self.line_index +
		    // hunk offset within the target file
		    SCORE_SCALE * line_diff / self.file_length;
		return Some(((self.line_index, match_index), cost));
	    }
	    self.line_index += 1;
	    self.match_index = 0;
	}
	None
    }
}

/// Matches for the next steps (after the first matched hunk line)
struct NextStepMatches<'a> {
    matches: &'a Matches,
    line_index: usize,
    match_index: usize,
    target_line: usize,
    first_index: usize,
}

impl<'a> NextStepMatches<'a> {
    pub fn new(
	matches: &'a Matches,
	target_line: usize,
	first_index: usize)
	-> Self
    {
	Self {
	    matches,
	    target_line,
	    first_index,
	    line_index: first_index,
	    match_index: 0,
	}
    }

    pub fn next(&mut self)
		-> Option<(MatchPos, usize)>
    {
	while let Some(line_matches) = &self.matches.get(self.line_index) {
	    while let Some(&file_line) = &line_matches.get(self.match_index) {
		let match_index = self.match_index;
		self.match_index += 1;

		if file_line >= self.target_line {
		    let inserted = file_line - self.target_line;
		    let deleted = self.line_index - self.first_index;
		    let cost = SCORE_SCALE * max(inserted, deleted);
		    return Some(((self.line_index, match_index), cost));
		}
	    }
	    self.line_index += 1;
	    self.match_index = 0;
	}

	let num_lines = self.matches.len();
	if self.line_index == num_lines {
	    self.line_index += 1;
	    Some(((num_lines, 0), SCORE_SCALE * (num_lines - self.first_index)))
	} else {
	    None
	}
    }
}

enum MatchIterator<'a> {
    FirstStep(FirstStepMatches<'a>),
    NextStep(NextStepMatches<'a>),
}

impl<'a> Iterator for MatchIterator<'a> {
    type Item = (MatchPos, usize);

    fn next(&mut self) -> Option<Self::Item> {
	use MatchIterator::*;
	match self {
	    FirstStep(iter) => iter.next(),
	    NextStep(iter) => iter.next(),
	}
    }
}

/// Figure out where the hunk was supposed to apply and print it out with highlighted differences.
pub fn print_difference_to_closest_match<W: Write>(
    report: &FilePatchApplyReport,
    hunk: &TextHunk,
    modified_file: &ModifiedFile,
    writer: &mut W,
    prefix: &str)
    -> Result<()>
{
    // Get a HunkView with the same direction as used during patching,
    // but with maximum available context.
    let hunk_view = hunk.view(report.direction(), 0);
    let hunk_len = hunk_view.remove_content().len();
    let file_len = modified_file.content.len();

    // We want to guess as best as we can where the hunk was supposed to go in the file. This is
    // more complicated (and smarter) than fuzzy patching.
    //
    // The hunk expects some content in the file (its context and remove lines), but the actual
    // content of the file may not match. Some lines may have been modified, some completely removed
    // and some added.

    // First, find all matching lines.
    let mut matches = Vec::with_capacity(hunk_len);
    for hunk_line in hunk_view.remove_content() {
        let mut line_matches = Vec::new();
	if !contains_only_space(hunk_line) {
            for (line_number, file_line) in modified_file.content.iter().enumerate() {
		if compare_ignore_space(file_line, hunk_line) {
                    line_matches.push(line_number);
		}
            }
        }
        matches.push(line_matches);
    }

    // We use dijkstra's algorithm to find the path. Since this implementation allows only single
    // starting point, we add an artificial starting node (MAX, MAX). This node is connected to
    // to every node on the left side of the matrix. The search ends when it manages to find a path
    // all the way out of the right side of the matrix.
    let target_line = match hunk_view.position() {
        HunkPosition::Start |
        HunkPosition::Middle => hunk_view.remove_target_line() as usize,
        HunkPosition::End => file_len - hunk_len,
    };
    let best_path = pathfinding::directed::dijkstra::dijkstra(
        // Starting point - the artificial point out of the matrix.
        &(std::usize::MAX, std::usize::MAX),

        // Function that for given node (x, y) returns iterable with its successors and cost to walk
        // to them.
        |&(line, index)| {
            // If this is the artificial starting node, we can make step to
            // every other node (with an appropriate cost).
            // This basically gives us multiple starting points.
            if line == std::usize::MAX {
		MatchIterator::FirstStep(FirstStepMatches::new(&matches, target_line, file_len))
	    } else {
		let file_line = matches[line][index] + 1;
		MatchIterator::NextStep(NextStepMatches::new(&matches, file_line, line + 1))
	    }
        },

        // Success condition.
        |&(line, _)| line == matches.len()
    );

    enum WriteLineType {
        Matching,
        InFile,
        InHunk,
    }

    let write_line = |writer: &mut W, line_type: WriteLineType, line_str: &str, line_num: Option<usize>| -> Result<()> {
        let line_num_str = match line_num {
            Some(line_num) => Cow::Owned(format!("{:5}", line_num + 1)),
            None                 => Cow::Borrowed("     "), // 5 characters for number + 1 for ':'
        };

        match line_type {
            WriteLineType::Matching => write!(writer, "{}{}", prefix, format!("{}: {}", line_num_str, line_str).bright_black())?,
            WriteLineType::InFile   => write!(writer, "{}{}", prefix, format!("{}< {}", line_num_str, line_str).bright_cyan())?,
            WriteLineType::InHunk   => write!(writer, "{}{}", prefix, format!("{}> {}", line_num_str, line_str).bright_magenta())?,
        }

        if !line_str.ends_with('\n') {
            writeln!(writer)?;
            writeln!(writer, "{}      {}{}", prefix, " ".repeat(line_str.len()), "^ no new line".bright_red())?;
        }
        if line_str.ends_with("\r\n") {
            writeln!(writer, "{}      {}{}", prefix, " ".repeat(line_str.len()), "^ windows new line".bright_red())?;
        }

        Ok(())
    };

    if let Some((best_path, _)) = best_path {
        writeln!(writer)?;
        writeln!(writer, "{}{} Comparison of the content of the {} and the content expected by the {}:", prefix, "hint:".purple(), "<file<".bright_cyan(), ">hunk>".bright_magenta())?;
        writeln!(writer)?;

        // NOTE: There must be at least two nodes in the path: the artificial
        // start node and the target node.
        let (start_line, start_index) = best_path[1];
        let mut file_line = matches[start_line][start_index];
        file_line -= min(file_line, start_line);
        let mut hunk_line = 0;
        for &(next_hunk_line, match_index) in &best_path[1..] {
	    while hunk_line < next_hunk_line {
		let content = &hunk_view.remove_content()[hunk_line];
		if modified_file.content.get(file_line) != Some(content) {
		    break;
		}
                write_line(writer, WriteLineType::Matching, &String::from_utf8_lossy(content), Some(file_line))?;
                file_line += 1;
                hunk_line += 1;
	    }
            let next_file_line = match matches.get(next_hunk_line) {
                Some(line_matches) => line_matches[match_index],
                None => min(file_len, file_line + (next_hunk_line - hunk_line)),
            };
            while file_line < next_file_line {
                write_line(writer, WriteLineType::InFile, &String::from_utf8_lossy(modified_file.content[file_line]), Some(file_line))?;
                file_line += 1;
            }

            while hunk_line < next_hunk_line {
                write_line(writer, WriteLineType::InHunk, &String::from_utf8_lossy(hunk_view.remove_content()[hunk_line]), None)?;
                hunk_line += 1;
            }

            if let Some(content) = hunk_view.remove_content().get(hunk_line)  {
                let file_content = &modified_file.content[file_line];
                if file_content == content {
                    write_line(writer, WriteLineType::Matching, &String::from_utf8_lossy(content), Some(file_line))?;
                } else {
                    write_line(writer, WriteLineType::InFile, &String::from_utf8_lossy(file_content), Some(file_line))?;
                    write_line(writer, WriteLineType::InHunk, &String::from_utf8_lossy(content), None)?;
                }
                file_line += 1;
                hunk_line += 1;
            }
        }

        writeln!(writer)?;
    }

    Ok(())
}

/// This function prints note from libpatch'es analysis
pub fn print_analysis_note(patch_filename: &Path, note: &dyn Note, file_patch: &TextFilePatch) -> Result<()> {
    let stderr = io::stderr();
    let mut out = stderr.lock();

    writeln!(out, "{} {}", "Patch".yellow(), patch_filename.display())?;
    writeln!(out, "  {} {}", "File".yellow(), file_patch.old_filename().unwrap_or_else(|| file_patch.new_filename().unwrap()).display())?;

    if let Some(hunk_index) = note.hunk() {
        let mut buf = Vec::<u8>::new();
        file_patch.hunks()[hunk_index].write_header_to(&mut buf)?;

        writeln!(out, "    {} #{}\t{}", "Hunk".yellow(), hunk_index + 1, String::from_utf8_lossy(&buf).bright_blue())?;
        write!(out, "      ")?;
    } else {
        write!(out, "    ")?;
    }

    match note.severity() {
        NoteSeverity::Warning => write!(out, "{}: ", "warning".bright_yellow().bold())?,
    }

    note.write(&mut out)?;
    writeln!(out)?;
    writeln!(out)?;

    Ok(())
}
