#![no_main]
#[macro_use] extern crate libfuzzer_sys;

use libpatch::patch::unified::parser::parse_patch;

fuzz_target!(|data: &[u8]| {
    let _ = parse_patch(data, 0);
});
