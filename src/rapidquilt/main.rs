// Licensed under the MIT license. See LICENSE.md

#![cfg_attr(feature = "bencher", feature(test))]
#[cfg(feature = "bencher")]
extern crate test;

mod apply;
mod arena;

#[cfg(test)]
mod tests;

use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process;

use colored::*;
use failure::{Error, ResultExt, format_err};
use getopts::{Matches, Options};

use libpatch::analysis::{AnalysisSet, MultiApplyAnalysis};

use crate::apply::{
    ApplyConfig,
    ApplyConfigBackupCount,
    ApplyConfigDoBackups,
    apply_patches,
    apply_patches_parallel,
    SeriesPatch,
    Verbosity,
};
use crate::arena::{Arena, FileArena};

#[cfg(unix)]
use crate::arena::MmapArena;


// Jemalloc has much better performance in multi threaded use than system allocator (at least on
// linux). This may change in the future, so this may be reverted, but make measurements first.
//
// Example benchmark on openSUSE Leap 15.0, 8 core Intel Xeon E5-1620 applying
// 44247 patches of SUSE's kernel-source branch SLE15-SP1:
//
// threads    system allocator    jemalloc
//       1               5.2 s       5.1 s
//       2               3.6 s       2.7 s
//       4               3.0 s       1.6 s
//       8               3.0 s       1.2 s
//
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;


const DEFAULT_PATCH_STRIP: usize = 1;


fn usage(opts: &Options) -> ! {
    println!("{}", opts.usage("Usage: rapidquilt push [<options>] [num|patch]"));
    process::exit(1);
}

fn version() -> ! {
    println!(concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")));
    process::exit(0);
}

fn read_series_file<P: AsRef<Path>>(series_path: P) -> Result<Vec<SeriesPatch>, Error> {
    let mut patch_opts = Options::new();
    patch_opts.optopt("p", "strip", "Strip this many directories in paths of patched files.", "<n>");
    patch_opts.optflag("R", "reverse", "Reverse the patch direction.");

    let file = File::open(series_path)?;
    let file = BufReader::new(file);

    file.lines()
        .filter_map(|line| {
            match line {
                Ok(line) => {
                    // Comments in series file must start with '#' without whitespace before.
                    if line.is_empty() || line.starts_with('#') {
                        None
                    } else {
                        // Quilt has no way to handle whitespace in filenames of patches. Leading whitespace
                        // is ignored and then everything up to any other whitespace is considered as filename.
                        // Anything left out is used as parameters for patch command.
                        let mut parts = line.split_whitespace().peekable();

                        if let Some(filename) = parts.next() {
                            Some((|| -> Result<SeriesPatch, Error> { // Poor-man's try block
                                let filename = std::path::PathBuf::from(filename);

                                // Fast path when there are no options
                                if parts.peek().is_none() {
                                    return Ok(SeriesPatch {
                                        filename,
                                        strip: DEFAULT_PATCH_STRIP,
                                        reverse: false,
                                    });
                                }

                                let matches = patch_opts.parse(parts)
                                    .with_context(|_| format!("Parsing patch options for \"{}\"", filename.display()))?;

                                let strip = matches.opt_str("strip").and_then(|n| n.parse::<usize>().ok()).unwrap_or(DEFAULT_PATCH_STRIP);
                                let reverse = matches.opt_present("R");

                                Ok(SeriesPatch {
                                    filename,
                                    strip,
                                    reverse,
                                })
                            })())
                        } else {
                            // Line was just whitespace
                            None
                        }
                    }
                }
                Err(err) => Some(Err(err.into())),
            }
        }).collect()
}

fn save_applied_patches(applied_patches: &[SeriesPatch]) -> Result<(), Error> {
    fs::create_dir_all(".pc")?;
    let mut file_applied_patches = BufWriter::new(fs::OpenOptions::new().create(true).append(true).open(".pc/applied-patches")?);
    for applied_patch in applied_patches {
        writeln!(file_applied_patches, "{}", applied_patch.filename.display())?;
    }
    Ok(())
}

enum PushGoal {
    All,
    Count(usize),
    UpTo(PathBuf),
}

/// Returns true if all patches were applied, false if only some, and error if there was error.
fn cmd_push<'a, F: Iterator<Item = &'a String>>(matches: &Matches, mut free_args: F, verbosity: Verbosity) -> Result<bool, Error>
{
    // Parse "push" specific arguments
    let do_backups = match matches.opt_str("backup") {
        Some(ref s) if s == "always" => ApplyConfigDoBackups::Always,
        Some(ref s) if s == "onfail" => ApplyConfigDoBackups::OnFail,
        Some(ref s) if s == "never"  => ApplyConfigDoBackups::Never,
        None                         => ApplyConfigDoBackups::OnFail,
        _ => return Err(format_err!("Bad value given to \"backup\" parameter!")),
    };

    let backup_count = match matches.opt_str("backup-count") {
        Some(ref s) if s == "all" => ApplyConfigBackupCount::All,
        Some(n)                   => ApplyConfigBackupCount::Last(n.parse::<usize>()?),
        None                      => ApplyConfigBackupCount::Last(100),
    };

    let patches_path = matches.opt_str("p").unwrap_or_else(|| "patches".to_string());

    let fuzz = matches.opt_str("fuzz").and_then(|n| n.parse::<usize>().ok()).unwrap_or(0);

    if fuzz > 0 {
        println!(concat!("{}: You are using --fuzz {}. The fuzzy patching algorithm in rapidquilt follows the ",
                         "same ideas as the one in patch, but it does not replicate all its quirks and corner cases. ",
                         "You may get different (but still sane) results compared to patch."),
                "WARNING".bright_yellow(), fuzz);
    }

    let dry_run = matches.opt_present("dry-run");
    let stats = matches.opt_present("stats");

    let arena = build_arena(matches.opt_present("mmap"));

    let mut goal = if matches.opt_present("a") {
        PushGoal::All
    } else {
        PushGoal::Count(1)
    };
    if let Some(first_free_arg) = free_args.next() {
        if let Ok(number) = first_free_arg.parse::<usize>() {
            goal = PushGoal::Count(number);
        } else {
            goal = PushGoal::UpTo(PathBuf::from(first_free_arg));
        }
    }

    // Process series file
    let series_patches = read_series_file("series")
        .with_context(|_| "When reading \"series\" file.")?;

    // Determine the last patch
    let first_patch = if let Ok(applied_patch_filenames) = read_series_file(".pc/applied-patches") {
        for (p1, p2) in series_patches.iter().zip(applied_patch_filenames.iter()) {
            if p1.filename != p2.filename {
                return Err(format_err!("There is mismatch in \"series\" and \".pc/applied-patches\" files! {} vs {}", p1.filename.display(), p2.filename.display()));
            }
        }
        applied_patch_filenames.len()
    } else {
        0
    };

    if first_patch == series_patches.len() {
        if verbosity >= Verbosity::Normal {
            println!("All patches applied. Nothing to do.");
            return Ok(true);
        }
    }

    let last_patch = match goal {
        PushGoal::All => series_patches.len(),
        PushGoal::Count(n) => std::cmp::min(first_patch + n, series_patches.len()),
        PushGoal::UpTo(patch_filename) => {
            if let Some(index) = series_patches.iter().position(|item| item.filename == patch_filename) {
                if index < first_patch {
                    return Err(format_err!("Patch already applied: {:?}", patch_filename));
                }
                index + 1
            } else {
                return Err(format_err!("Patch not in series: {:?}", patch_filename));
            }
        }
    };

    let series_patches = &series_patches[first_patch..last_patch];

    let config = ApplyConfig {
        series_patches,
        patches_path: patches_path.as_ref(),
        fuzz,
        do_backups,
        backup_count,
        dry_run,
        stats,
        verbosity,
    };

    let mut analyses = AnalysisSet::new();

    for analysis_name in matches.opt_strs("analyze") {
        if analysis_name.eq_ignore_ascii_case("multiapply") {
            analyses.add_default::<MultiApplyAnalysis>();
        } else {
            return Err(format_err!("Unknown analysis \"{}\"", analysis_name));
        }
    }

    let apply_result = if rayon::current_num_threads() <= 1 {
        apply_patches(&config, &*arena, &analyses)?
    } else {
        apply_patches_parallel(&config, &*arena, &analyses)?
    };

    if !config.dry_run {
        save_applied_patches(&config.series_patches[0..apply_result.applied_patches])
            .with_context(|_| "When saving applied patches.")?;
    }

    Ok(apply_result.skipped_patches == 0)
}

#[cfg(unix)]
fn build_arena(use_mmap: bool) -> Box<dyn Arena> {
    if use_mmap {
        Box::new(MmapArena::new())
    } else {
        Box::new(FileArena::new())
    }
}

#[cfg(not(unix))]
fn build_arena(use_mmap: bool) -> Box<Arena> {
    if use_mmap {
        panic!();
    } else {
        Box::new(FileArena::new())
    }
}

// Basically main(), but returning `Result` so we can easily propagate errors with try operator and
// then format them our own way.
//
// We could return `Result` directly from main(), but then it would be formatted using the default
// formatter, which is ugly and doesn't print the failure's causes, so there is less context. The
// proper solution is to use own type that will implement `std::process::Termination`, but that is
// not stable yet.
//
// TODO: Use the `std::process::Termination` trait once it is stable.
fn main_result() -> Result<bool, Error> {
    let args: Vec<_> = env::args().collect();

    let mut opts = Options::new();
    opts.optflag("a", "all", "apply all patches in series");
    opts.optopt("d", "directory", "working directory", "DIR");
    opts.optopt("p", "patch-directory", "directory with patches (default: \"patches\")", "DIR");
    opts.optopt("b", "backup", "create backup files for `quilt pop` (default: onfail)", "always|onfail|never");
    opts.optopt("", "backup-count", "amount of backup files for `quilt pop` to create (default: 100)", "all|<n>");
    opts.optopt("F", "fuzz", "maximal allowed fuzz (default: 0)", "<n>");
    opts.optopt("", "color", "use colors in output (default: auto)", "always|auto|never");
    opts.optflag("", "dry-run", "do not save any changes");
    opts.optmulti("A", "analyze", "run additional analysis while patching. You can use this option multiple times to run multiple analyses at once. Available analyses: multiapply", "ANALYSIS"); // TODO: Don't hardcoded the list of available analyses?
    opts.optflag("", "stats", "print statistics in the end");
    opts.optflag("q", "quiet", "only print errors");
    opts.optflagmulti("v", "verbose", "print extra information. Repeat for more verbosity. It may affect performance.");

    #[cfg(unix)]
    opts.optflag("", "mmap", "mmap files instead of reading into buffers. This may reduce memory usage and improve \
                              performance in some cases. Warning: You must ensure that no external program will modify the \
                              files while rapidquilt is running, otherwise you may get incorrect results or even crash.");

    opts.optflag("h", "help", "print this help menu");
    opts.optflag("", "version", "print version");


    let matches = opts.parse(&args[1..])?;
    let mut free_args = matches.free.iter();

    if matches.opt_present("version") {
        version();
    }

    if matches.opt_present("help") {
        usage(&opts);
    }

    match matches.opt_str("color") {
        Some(ref s) if s == "always" => colored::control::set_override(true),
        Some(ref s) if s == "never" => colored::control::set_override(false),
        Some(ref s) if s != "auto" => return Err(format_err!("Bad value given to \"color\" parameter!")),
        _ /* auto */ => {
            // Force it off if either of the outputs is not terminal. Otherwise leave on default,
            // which uses some env variables.
            if atty::isnt(atty::Stream::Stdout) || atty::isnt(atty::Stream::Stderr) {
                colored::control::set_override(false);
            }
        }
    };

    // "--verbose" beats "--quiet"
    let verbosity = if matches.opt_count("verbose") >= 2 {
        Verbosity::ExtraVerbose
    } else if matches.opt_count("verbose") == 1 {
        Verbosity::Verbose
    } else if matches.opt_present("quiet") {
        Verbosity::Quiet
    } else {
        Verbosity::Normal
    };

    if let Some(directory) = matches.opt_str("directory") {
        env::set_current_dir(&directory).with_context(|_| format!("Changing current directory to \"{}\"", directory))?;
    }

    if let Some(manual_threads) = env::var("RAPIDQUILT_THREADS").ok().and_then(|value_txt| value_txt.parse().ok()) {
        rayon::ThreadPoolBuilder::new().num_threads(manual_threads).build_global()?;
    }

    let result = match free_args.next() {
        Some(cmd) if cmd == "push" => {
            cmd_push(&matches, free_args, verbosity)
        }
        _ => {
            usage(&opts);
        }
    };

    result
}

fn main() {
    match main_result() {
        Err(err) => {
            for (i, cause) in err.iter_chain().enumerate() {
                eprintln!("{}{}", "  ".repeat(i), format!("{}", cause).red());
            }

            process::exit(1);
        },
        Ok(false) => {
            process::exit(1);
        }
        _ => {}
    }
}
