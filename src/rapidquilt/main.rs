// Licensed under the MIT license. See LICENSE.md

#![cfg_attr(feature = "bencher", feature(test))]
#[cfg(feature = "bencher")]
extern crate test;

mod apply;
mod arena;
mod cmd;

#[cfg(test)]
mod tests;

use std::env;
use std::process;

use colored::*;

fn main() {
    match cmd::run(env::args_os().skip(1)) {
        Err(err) => {
            for (i, cause) in err.chain().enumerate() {
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
