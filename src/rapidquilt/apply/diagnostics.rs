// Licensed under the MIT license. See LICENSE.md

//! This module contains functions for diagnosing and reporting patch apply
//! failure. Performance is less important for these functions, since they are
//! called only few times when there was application failure. The priority is
//! to provide user-friendly report.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Write};
use std::hash::BuildHasher;

use std::path::{Path, PathBuf};

use smallvec::{SmallVec, smallvec};

use strsim::levenshtein;
use colored::*;
use libpatch::analysis::{AnalysisSet, Note, NoteSeverity, fn_analysis_note_noop};
use libpatch::interned_file::InternedFile;
use libpatch::line_interner::LineInterner;

use libpatch::patch::{InternedFilePatch, HunkApplyFailureReason, HunkApplyReport, PatchDirection};
use libpatch::patch::unified::writer::UnifiedPatchHunkHeaderWriter;
use libpatch::patch::InternedHunk;
use libpatch::patch::FilePatchApplyReport;

use crate::apply::common::*;
use crate::apply::Verbosity;


/// Try if the patch would apply with some fuzz. It doesn't do any permanent changes.
pub fn test_apply_with_fuzzes<H: BuildHasher>(
    patch_status: &PatchStatus,
    modified_files: &HashMap<PathBuf, InternedFile, H>)
    -> Option<usize>
{
    let file = modified_files.get(&patch_status.final_filename).unwrap(); // NOTE(unwrap): It must be there, otherwise we got bad modified_files, which would be bug.

    // Make our own copy for experiments
    let mut file = file.clone();

    // Rollback the failed application
    patch_status.file_patch.rollback(&mut file, PatchDirection::Forward, &patch_status.report);

    let current_fuzz = patch_status.report.fuzz();
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

pub fn test_apply_after_reverting_other<H: BuildHasher>(
    failed_patch_status: &PatchStatus,
    suspect_patch_status: &PatchStatus,
    modified_files: &HashMap<PathBuf, InternedFile, H>)
    -> bool
{
    let file = modified_files.get(&failed_patch_status.final_filename).unwrap(); // NOTE(unwrap): It must be there, otherwise we got bad modified_files, which would be bug.

    // Make our own copy for experiments
    let mut file = file.clone();

    // Rollback the failed application
    failed_patch_status.file_patch.rollback(&mut file, PatchDirection::Forward, &failed_patch_status.report);

    // Revert the suspect
    let revert_report = suspect_patch_status.file_patch.apply(&mut file, PatchDirection::Revert, suspect_patch_status.report.fuzz(), &AnalysisSet::default(), &fn_analysis_note_noop);
    if revert_report.failed() {
        // If we couldn't even revert the suspect, we can't test anything
        return false;
    }

    // Try to apply our failed patch again
    let apply_report = failed_patch_status.file_patch.apply(&mut file, PatchDirection::Forward, failed_patch_status.report.fuzz(), &AnalysisSet::default(), &fn_analysis_note_noop);

    // Report whether it would apply ok now
    apply_report.ok()
}

/// Render a report into `writer` about why the `broken_patch_index` failed to
/// apply.
pub fn analyze_patch_failure<H: BuildHasher, W: Write>(
    verbosity: Verbosity,
    broken_patch_index: usize,
    applied_patches: &Vec<PatchStatus>,
    modified_files: &HashMap<PathBuf, InternedFile, H>,
    interner: &LineInterner,
    writer: &mut W)
    -> Result<(), io::Error>
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

                            HunkApplyFailureReason::FileWasDeleted =>
                                Some("The file was deleted by some previous patch."),

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

                    HunkApplyReport::Skipped => {
                        unreachable!(); // This should never happen here. Hunk can be skipped only during rollback.
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
                                                          interner,
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

/// Figure out where the hunk was supposed to apply and print it out with highlighted differences.
pub fn print_difference_to_closest_match<W: Write>(
    report: &FilePatchApplyReport,
    hunk: &InternedHunk,
    interned_file: &InternedFile,
    interner: &LineInterner,
    writer: &mut W,
    prefix: &str)
    -> Result<(), io::Error>
{
    // Get a HunkView that will be the same as the one used during patching
    let hunk_view = hunk.view(report.direction(), report.fuzz());

    // We want to guess as best as we can where the hunk was supposed to go in the file. This is
    // more complicated (and smarter) than fuzzy patching.
    //
    // The hunk expects some content in the file (its context and remove lines), but the actual
    // content of the file may not match. Some lines may have been modified, some completely removed
    // and some added.
    //
    // Regular patch works with a line precision. The whole line either matches or not, nothing in
    // between. But we need to be smarter and work on the character level, so we start by
    // de-interning the file and the hunk back into a vector of strings.

    let file_content_txt = interned_file.content.iter().map(|line_id| {
        let line =  interner.get(*line_id).unwrap(); // NOTE(unwrap): Must succeed. If it is not there, it is a bug.
        String::from_utf8_lossy(line)
    }).collect::<Vec<_>>();

    let hunk_content_txt = hunk_view.remove_content().iter().map(|line_id| {
        let line =  interner.get(*line_id).unwrap(); // NOTE(unwrap): Must succeed. If it is not there, it is a bug.
        String::from_utf8_lossy(line)
    }).collect::<Vec<_>>();

    // Next we will calculate levenshtein distance for every pair of lines from the file and from
    // the hunk. We will save these results into MxN matrix, where M is length of the hunk and N is
    // length of the file. Item at (m, n) coordinates is the edit distance from the m-th line in
    // hunk to the n-th line in the file.

    // TODO: We could probably start with empty matrix and calculate the edit distances on-demand
    //       later? We probably don't need all of them. We should check how many of them are usually
    //       needed during search...

    type Score = usize;
    let mut matrix: Vec<Vec<Score>> = Vec::with_capacity(file_content_txt.len());
    for file_line_txt in &file_content_txt {
        let mut matrix_row = Vec::with_capacity(hunk_content_txt.len());
        for hunk_line_txt in &hunk_content_txt {
            matrix_row.push(levenshtein(file_line_txt, hunk_line_txt));
        }
        matrix.push(matrix_row);
    }

    // If the hunk was present in its exact form somewhere in the file, there will be a diagonal
    // line filed with zeroes in the matrix. But that is typically not the case. (You wouldn't call
    // this function if the hunk applied.) Something in the file doesn't match expectations of the
    // hunk. This describes the effects of changes on the matrix:
    //
    // * If a line that is in both the hunk and the file changed slightly, there will be small
    //   number instead of zero.
    //
    // * If a line was added to the file, there will be extra line with big numbers breaking the
    //   diagonal with zeroes.
    //
    // * If a line was removed from the file, the diagonal won't be perfect diagonal, but will have
    //   a horizontal step in it.
    //
    // So to find the place where the hunk most closely matches, we need to find the cheapest path
    // from the left side to the right side of the matrix. We can step diagonally down+right, or
    // just down or just right. The cost of each step is the edit distance stored in the element.
    //
    // We use dijkstra's algorithm to find the path. Since this implementation allows only single
    // starting point, we add an artificial starting node (MAX, MAX). This node is connected to
    // to every node on the left side of the matrix. The search ends when it manages to find a path
    // all the way out of the right side of the matrix.

    let best_path = pathfinding::directed::dijkstra::dijkstra(
        // Starting point - the artificial point out of the matrix.
        &(std::usize::MAX, std::usize::MAX),

        // Function that for given node (x, y) returns iterable with its successors and cost to walk
        // to them.
        |&(x, y)| -> SmallVec<[((usize, usize), Score); 3]> {
            // TODO: Change this into generator once they are stable, so we don't have to allocate
            //       and return SmallVec with all successors at once.

            // If this is the artificial starting node, we can make step to every node in the left
            // side. This basically gives us multiple starting points.
            if x == std::usize::MAX {
                return (0..file_content_txt.len()).map(|y1| ((0, y1), matrix[y1][0])).collect();
            }

            // If we could only step out of the matrix, there is nowhere else to go.
            if x + 1 >= hunk_content_txt.len() || y + 1 >= file_content_txt.len() {
                return smallvec![];
            }

            smallvec![
                // Move down. We proceed one line further in the file while staying on the same line
                // in the hunk. If this turns out to be the shortest path, it means that an extra
                // line was added to the file.
                ((x,     y + 1), file_content_txt[y + 1].len()),

                // Diagonal move. We take one line from the hunk and from the file at cost of
                // editing the line from one to another. I.e. if they are the same, the edit
                // distance is 0 and so the cost is 0.
                ((x + 1, y + 1), matrix[y + 1][x + 1] * 5),

                // Move right. We proceed one line further in the hunk while staying on the same
                // line in the file. If this turns out to be the shortest path, it means that there
                // is line in hunk that is no longer present in the file.
                ((x + 1, y),     hunk_content_txt[x + 1].len() * 5),
            ]
        },

        // Success condition.
        |&(x, _)| x == hunk_content_txt.len() - 1
    );

    // Now we got the best path from the left to the right side of the matrix. Now we have to
    // interpret the right/down/diagonal steps as the lines being added/removed/modified and print
    // them out accordingly.

    enum WriteLineType {
        Matching,
        InFile,
        InHunk,
    }

    let write_line = |writer: &mut W, line_type: WriteLineType, line_str: &str, line_num: Option<isize>| -> Result<(), io::Error> {
        let line_num_str = match line_num {
            Some(line_num) => Cow::Owned(format!("{:5}:", line_num + 1)),
            None                 => Cow::Borrowed("     :"), // 5 characters for number + 1 for ':'
        };

        match line_type {
            WriteLineType::Matching => write!(writer, "{}{}", prefix, format!("{} {}", line_num_str, line_str).bright_black())?,
            WriteLineType::InFile   => write!(writer, "{}{}", prefix, format!("{} {}", line_num_str, line_str).bright_cyan())?,
            WriteLineType::InHunk   => write!(writer, "{}{}", prefix, format!("{} {}", line_num_str, line_str).bright_magenta())?,
        }

        if !line_str.ends_with('\n') {
            writeln!(writer)?;
            writeln!(writer, "{}      {}{}", prefix, " ".repeat(line_str.len()), "^ no new line".bright_red())?;
        }
        if !line_str.ends_with("\r\n") {
            writeln!(writer, "{}      {}{}", prefix, " ".repeat(line_str.len()), "^ windows new line".bright_red())?;
        }

        Ok(())
    };

    if let Some(best_path) = best_path {
        writeln!(writer)?;
        writeln!(writer, "{}{} Comparison of the content of the {} and the content expected by the {}:", prefix, "hint:".purple(), "file".bright_cyan(), "hunk".bright_magenta())?;
        writeln!(writer)?;

        for step in best_path.0.windows(2) {
            let (prev_x, prev_y) = step[0];
            let (x, y)           = step[1];

            if prev_x == std::usize::MAX || (prev_x + 1 == x && prev_y + 1 == y) {
                if matrix[y][x] == 0 {
                    write_line(writer, WriteLineType::Matching, &file_content_txt[y], Some(y as isize))?;
                } else {
                    write_line(writer, WriteLineType::InFile, &file_content_txt[y], Some(y as isize))?;
                    write_line(writer, WriteLineType::InHunk, &hunk_content_txt[x], Some(y as isize))?;
                }
            } else if prev_x + 1 == x {
                write_line(writer, WriteLineType::InHunk, &hunk_content_txt[x], None)?; // No line number if this line is just in hunk
            } else {
                write_line(writer, WriteLineType::InFile, &file_content_txt[y], Some(y as isize))?;
            }
        }

        writeln!(writer)?;
    }

    Ok(())
}

/// This function prints note from libpatch'es analysis
pub fn print_analysis_note(patch_filename: &Path, note: &Note, file_patch: &InternedFilePatch) -> Result<(), io::Error> {
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
