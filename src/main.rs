// Licensed under the MIT license. See LICENSE.md

#[macro_use] extern crate failure;
#[macro_use] extern crate lazy_static;

mod apply;
mod line_interner;
mod file_arena;
mod interned_file;
mod patch;

use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process;

use failure::Error;

use getopts::Options;

use crate::apply::{apply_patches, apply_patches_parallel};


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
        .filter(|line| line.len() > 0 && !line.starts_with('#')) // man quilt says that comment lines start with '#', it does not mention any whitespace before that (TODO: Verify)
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

fn cmd_push<P: AsRef<Path>>(patches_directory: P, goal: PushGoal, strip: usize) -> Result<(), Error> {
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

    let threads = env::var("RAPIDQUILT_THREADS").ok()
        .and_then(|value_txt| value_txt.parse().ok())
        .unwrap_or_else(|| num_cpus::get());

    let apply_result = if threads <= 1 {
        apply_patches(&patch_filenames, patches_directory, strip)?
    } else {
        apply_patches_parallel(&patch_filenames, patches_directory, strip, threads)?
    };

    fs::create_dir_all(".pc")?;
    let mut file_applied_patches = fs::OpenOptions::new().create(true).append(true).open(".pc/applied-patches")?;
    for applied_patch in apply_result.applied_patches {
        writeln!(file_applied_patches, "{}", applied_patch.display())?;
    }

    Ok(())
}

fn main() {
    let args: Vec<_> = env::args().collect();

    let mut opts = Options::new();
    opts.optflag("a", "all", "apply all patches in series");
    opts.optopt("d", "directory", "working directory", "DIR");
    opts.optopt("p", "patch-directory", "directory with patches (default: \"patches\")", "DIR");
    opts.optflag("h", "help", "print this help menu");

    if args.len() < 2 || args[1] != "push" {
        usage(&opts);
        process::exit(1);
    }

    let matches = opts.parse(&args[2..]).unwrap();

    if matches.opt_present("h") {
        usage(&opts);
        process::exit(1);
    }

    if let Some(directory) = matches.opt_str("d") {
        env::set_current_dir(directory).unwrap();
    }

    let patches_directory = matches.opt_str("p").unwrap_or("patches".to_string());

    let mut goal = PushGoal::Count(1);
    if matches.opt_present("a") {
        goal = PushGoal::All;
    }
    if let Some(first_free_arg) = matches.free.first() {
        if let Ok(number) = first_free_arg.parse::<usize>() {
            goal = PushGoal::Count(number);
        } else {
            goal = PushGoal::UpTo(PathBuf::from(first_free_arg));
        }
    }

    cmd_push(patches_directory, goal, 1).unwrap();
}
