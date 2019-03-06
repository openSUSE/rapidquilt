use std::borrow::Cow;
use std::io::{self, Write};
use std::ops::Range;

use crate::analysis::*;
use crate::modified_file::ModifiedFile;
use crate::patch::{
    FilePatchApplyReport,
    HunkApplyReport,
    TextFilePatch,
    PatchDirection,
    HunkPosition,
};
use crate::util::Searcher;


#[derive(Clone, Debug)]
struct MultiApplyNote {
    hunk: usize,
    line: isize,
    offset: isize,
    places: Vec<Range<isize>>,
}

impl Note for MultiApplyNote {
    fn hunk(&self) -> Option<usize> {
        Some(self.hunk)
    }

    fn boxed_clone(&self) -> Box<Note> {
        Box::new(self.clone())
    }

    fn severity(&self) -> NoteSeverity {
        NoteSeverity::Warning
    }

    fn write(&self, out: &mut dyn Write) -> Result<(), io::Error> {
        write!(out, "Applied on line {}{}, but would also apply on line{} {}",
               self.line + 1,
               if self.offset == 0 { Cow::Borrowed("") } else { Cow::Owned(format!(" (offset {})", self.offset)) },
               if self.places.len() == 1 { "" } else { "s" },
               self.places.iter().map(|r| format!("{}", r.start + 1)).collect::<Vec<_>>().join(", ")
        )
    }
}

#[derive(Default)]
pub struct MultiApplyAnalysis {}

impl Analysis for MultiApplyAnalysis {
    // This duplicates some of the functionality from `patch::try_apply_hunk`. I prefer to duplicate
    // it slightly differently here, rather than complicate that function. `patch::try_apply_hunk`
    // should remain fast and readable.

    fn before_modifications(
        &self,
        modified_file: &ModifiedFile,
        file_patch: &TextFilePatch,
        direction: PatchDirection,
        report: &FilePatchApplyReport,
        fn_analysis_note: &Fn(&dyn Note, &TextFilePatch))
    {
        for (i, (hunk, hunk_report)) in file_patch.hunks().iter().zip(report.hunk_reports()).enumerate() {
            // We only care if the hunk was applied
            let (applied_with_fuzz, applied_on_line, applied_with_offset) = match hunk_report {
                HunkApplyReport::Applied { fuzz, line, offset, .. } => (fuzz, line, offset),
                _ => return,
            };

            let hunk_view = hunk.view(direction, *applied_with_fuzz);
            let remove_content = hunk_view.remove_content();

            // Only hunks that are applied in the middle (i.e. are not force to the beginning or the end of patch)
            if hunk_view.position() != HunkPosition::Middle {
                return;
            }

            // Check if there are any more places where the hunk could apply,
            // we must exclude places where some hunk already applied.
            let places: Vec<Range<isize>> = Searcher::new(&remove_content) // TODO: We no longer use Searcher in patch::try_apply_hunk and we could stop using it here and remove it completely...
                .search_in(&modified_file.content)
                .map(|line| (line as isize)..((line + remove_content.len()) as isize))
                .filter(|range| {
                    for (other_hunk, other_hunk_report) in file_patch.hunks().iter().zip(report.hunk_reports()) {
                        if let HunkApplyReport::Applied { line, fuzz, .. } = other_hunk_report {
                            let other_hunk_view = other_hunk.view(direction, *fuzz);
                            let other_remove_content = other_hunk_view.remove_content();
                            let other_range = (*line as isize)..(*line + other_remove_content.len() as isize);

                            if range.end > other_range.start && other_range.end > range.start {
                                // Overlap, kill it
                                return false;
                            }
                        }
                    }

                    true
                })
                .collect();

            if !places.is_empty() {
                fn_analysis_note(&MultiApplyNote {
                    hunk: i,
                    line: *applied_on_line,
                    offset: *applied_with_offset,
                    places
                }, file_patch);
            }
        }
    }
}
