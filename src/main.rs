// Licensed under the MIT license. See LICENSE.md

#![cfg_attr(feature = "bencher", feature(test))]
#[cfg(feature = "bencher")]
extern crate test;

mod apply;
mod arena;
mod line_interner;
mod interned_file;
mod patch;
mod util;

#[cfg(test)]
mod tests;

use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process;

use colored;
use failure::{Error, format_err};
use getopts::Options;

use crate::apply::{
    ApplyConfig,
    ApplyConfigBackupCount,
    ApplyConfigDoBackups,
    apply_patches,
    apply_patches_parallel
};
use crate::arena::{Arena, FileArena};

#[cfg(unix)]
use crate::arena::MmapArena;



fn usage(opts: &Options) {
    println!("{}", opts.usage("Usage: rapidquilt push [<options>] [num|patch]"));
    process::exit(1);
}

fn read_series_file<P: AsRef<Path>>(series_path: P) -> Result<Vec<PathBuf>, Error> {
    let file = File::open(series_path)?;
    let file = BufReader::new(file);

    let patch_filenames = file
        .lines()
        .map(|line| line.unwrap() /* <- TODO: Propagate up. */)
        .filter(|line| !line.is_empty() && !line.starts_with('#')) // man quilt says that comment lines start with '#', it does not mention any whitespace before that (TODO: Verify)
        .map(|line| {
            // TODO: Handle comments after the patch name

            std::path::PathBuf::from(line)
        }).collect();

    Ok(patch_filenames)
}

enum PushGoal {
    All,
    Count(usize),
    UpTo(PathBuf),
}

fn cmd_push<P: AsRef<Path>>(arena: &dyn Arena,
                            patches_path: P,
                            goal: PushGoal,
                            fuzz: usize,
                            strip: usize,
                            do_backups: ApplyConfigDoBackups,
                            backup_count: ApplyConfigBackupCount,
                            dry_run: bool,
                            stats: bool)
                            -> Result<bool, Error>
{
    let patch_filenames = read_series_file("series").unwrap();

    let first_patch = if let Ok(applied_patch_filenames) = read_series_file(".pc/applied-patches") {
        for (p1, p2) in patch_filenames.iter().zip(applied_patch_filenames.iter()) {
            if p1 != p2 {
                println!("There is mismatch in \"series\" and \".pc/applied-patches\" files! {} vs {}", p1.display(), p2.display());
                process::exit(1);
            }
        }
        applied_patch_filenames.len()
    } else {
        0
    };

    let last_patch = match goal {
        PushGoal::All => patch_filenames.len(),
        PushGoal::Count(n) => first_patch + n,
        PushGoal::UpTo(patch_filename) => {
            if let Some(index) = patch_filenames.iter().position(|item| *item == patch_filename) {
                if index <= first_patch {
                    return Err(format_err!("Patch already applied: {:?}", patch_filename));
                }
                index + 1
            } else {
                return Err(format_err!("Patch not in series: {:?}", patch_filename));
            }
        }
    };

    let patch_filenames = &patch_filenames[first_patch..last_patch];

    let config = ApplyConfig {
        patch_filenames,
        patches_path: patches_path.as_ref(),
        fuzz,
        strip,
        do_backups,
        backup_count,
        dry_run,
        stats,
    };

    let threads = match env::var("RAPIDQUILT_THREADS").ok().and_then(|value_txt| value_txt.parse().ok()) {
        Some(manual_threads) => {
            rayon::ThreadPoolBuilder::new().num_threads(manual_threads).build_global()?;
            manual_threads
        },
        None => {
            rayon::current_num_threads()
        }
    };

    let apply_result = if threads <= 1 {
        apply_patches(&config, arena)?
    } else {
        apply_patches_parallel(&config, arena)?
    };

    fs::create_dir_all(".pc")?;
    let mut file_applied_patches = BufWriter::new(fs::OpenOptions::new().create(true).append(true).open(".pc/applied-patches")?);
    for applied_patch in apply_result.applied_patches {
        writeln!(file_applied_patches, "{}", applied_patch.display())?;
    }

    Ok(apply_result.skipped_patches.is_empty())
}

#[cfg(unix)]
fn build_arena(use_mmap: bool) -> Box<Arena> {
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

fn main() {
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
    opts.optflag("", "stats", "print statistics in the end");

    #[cfg(unix)]
    opts.optflag("", "mmap", "mmap files instead of reading into buffers. This may reduce memory usage and improve \
                              performance in some cases. Warning: You must ensure that no external program will modify the \
                              files while rapidquilt is running, otherwise you may get incorrect results or even crash.");

    opts.optflag("h", "help", "print this help menu");

    if args.len() < 2 || args[1] != "push" {
        usage(&opts);
        process::exit(1);
    }

    let matches = opts.parse(&args[2..]).unwrap();

    if matches.opt_present("help") {
        usage(&opts);
        process::exit(1);
    }

    match matches.opt_str("color") {
        Some(ref s) if s == "always" => colored::control::set_override(true),
        Some(ref s) if s == "never"  => colored::control::set_override(false),
        Some(ref s) if s != "auto" => Err(format_err!("Bad value given to \"color\" parameter!")).unwrap(),
        _ /* auto */ => {
            // Force it off if either of the outputs is not terminal. Otherwise leave on default,
            // which uses some env variables.
            if atty::isnt(atty::Stream::Stdout) || atty::isnt(atty::Stream::Stderr) {
                colored::control::set_override(false);
            }
        }
    };

    if let Some(directory) = matches.opt_str("directory") {
        env::set_current_dir(directory).unwrap();
    }

    let do_backups = match matches.opt_str("backup") {
        Some(ref s) if s == "always" => ApplyConfigDoBackups::Always,
        Some(ref s) if s == "onfail" => ApplyConfigDoBackups::OnFail,
        Some(ref s) if s == "never"  => ApplyConfigDoBackups::Never,
        None                         => ApplyConfigDoBackups::OnFail,
        _ => Err(format_err!("Bad value given to \"backup\" parameter!")).unwrap(),
    };

    let backup_count = match matches.opt_str("backup-count") {
        Some(ref s) if s == "all" => ApplyConfigBackupCount::All,
        Some(n)                   => ApplyConfigBackupCount::Last(n.parse::<usize>().unwrap()),
        None                      => ApplyConfigBackupCount::Last(100),
    };

    let patches_path = matches.opt_str("p").unwrap_or_else(|| "patches".to_string());

    let fuzz = matches.opt_str("fuzz").and_then(|n| n.parse::<usize>().ok()).unwrap_or(0);

    if fuzz > 0 {
        println!("--fuzz > 0 is not working correctly right now, can not proceed.");
        process::exit(1);
    }

    let dry_run = matches.opt_present("dry-run");
    let stats = matches.opt_present("stats");

    let arena = build_arena(matches.opt_present("mmap"));

    let mut goal = if matches.opt_present("a") {
        PushGoal::All
    } else {
        PushGoal::Count(1)
    };
    if let Some(first_free_arg) = matches.free.first() {
        if let Ok(number) = first_free_arg.parse::<usize>() {
            goal = PushGoal::Count(number);
        } else {
            goal = PushGoal::UpTo(PathBuf::from(first_free_arg));
        }
    }

    match cmd_push(&*arena, patches_path, goal, fuzz, 1, do_backups, backup_count, dry_run, stats) {
        Err(err) => {
            for (i, cause) in err.iter_chain().enumerate() {
                eprintln!("{}{}", "  ".repeat(i), cause);
            }

            process::exit(1);
        },
        Ok(false) => {
            process::exit(1);
        }
        _ => {}
    }
}
