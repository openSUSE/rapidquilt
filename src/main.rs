#[macro_use] extern crate failure;
#[macro_use] extern crate lazy_static;

mod apply;
mod line_interner;
mod file_arena;
mod interned_file;
mod patch;

use std::env;
use std::fs::File;
use std::fs;
use std::io;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use failure::Error;

use getopts::Options;

use crate::apply::{apply_patches, apply_patches_parallel};
use crate::patch::PatchDirection;
use crate::line_interner::LineInterner;
use crate::interned_file::InternedFile;


fn backup_file(patch_filename: &Path, filename: &Path, original_file: &InternedFile, interner: &LineInterner) -> Result<(), Error> {
    let mut path = PathBuf::from(".pc");
    path.push(patch_filename);
    path.push(&filename);

    fs::create_dir_all(&path.parent().unwrap())?;
    original_file.write_to(interner, &mut File::create(path)?)?;

    Ok(())
}

fn main() {
    let args: Vec<_> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("d", "directory", "working directory", "NAME");
//     opts.optflag("h", "help", "print this help menu");

    let matches = opts.parse(&args[1..]).unwrap();

    if let Some(directory) = matches.opt_str("d") {
        println!("Changing directory to {}", directory);
        env::set_current_dir(directory).unwrap();
    }

    let stdin = io::stdin();

    let patch_filenames: Vec<_> = stdin
        .lock()
        .lines()
        .map(|line| line.unwrap() /* <- TODO: Propagate up. */)
//         .filter(|line| line.len() > 0 && !line.starts_with('#')) // man quilt says that comment lines start with '#', it does not mention any whitespace before that (TODO: Verify)
        .map(|line| {
            std::path::PathBuf::from(line)
        }).collect();

    apply_patches_parallel(&patch_filenames, ".", 1).unwrap();
}
