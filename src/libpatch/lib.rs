// Licensed under the MIT license. See LICENSE.md

#![cfg_attr(feature = "bencher", feature(test))]
#[cfg(feature = "bencher")]
extern crate test;

pub mod analysis;
pub mod modified_file;
pub mod patch;
mod util;

#[cfg(test)]
mod tests;
