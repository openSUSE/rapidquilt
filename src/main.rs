#[macro_use] extern crate failure;
#[macro_use] extern crate lazy_static;

mod apply;
mod line_interner;
mod file_arena;
mod interned_file;
mod patch;

use std::env;
use std::io;
use std::io::BufRead;

use failure::Error;

use getopts::Options;

use crate::apply::{apply_patches, apply_patches_parallel};


fn main() {
    let args: Vec<_> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("d", "directory", "working directory", "NAME");
    opts.optopt("p", "patch-directory", "directory with patches", "NAME");
//     opts.optflag("h", "help", "print this help menu");

    let matches = opts.parse(&args[1..]).unwrap();

    if let Some(directory) = matches.opt_str("d") {
        println!("Changing directory to {}", directory);
        env::set_current_dir(directory).unwrap();
    }

    let patch_directory = matches.opt_str("p").unwrap_or(".".to_string());

    let stdin = io::stdin();

    let patch_filenames: Vec<_> = stdin
        .lock()
        .lines()
        .map(|line| line.unwrap() /* <- TODO: Propagate up. */)
//         .filter(|line| line.len() > 0 && !line.starts_with('#')) // man quilt says that comment lines start with '#', it does not mention any whitespace before that (TODO: Verify)
        .map(|line| {
            std::path::PathBuf::from(line)
        }).collect();

    let threads = env::var("RAPIDQUILT_THREADS").ok()
        .and_then(|value_txt| value_txt.parse().ok())
        .unwrap_or_else(|| num_cpus::get());

    if threads <= 1 {
        apply_patches(&patch_filenames, patch_directory, 1).unwrap();
    } else {
        apply_patches_parallel(&patch_filenames, patch_directory, 1, threads).unwrap();
    }
}
