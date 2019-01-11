// Licensed under the MIT license. See LICENSE.md

const NO_NEW_LINE_TAG: &[u8] = b"\\ No newline at end of file\n";
const NULL_FILENAME: &[u8] = b"/dev/null";

pub mod parser;
pub mod writer;
