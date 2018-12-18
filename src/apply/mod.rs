// Licensed under the MIT license. See LICENSE.md

mod sequential;
mod parallel;
mod common;

pub use self::sequential::apply_patches;
pub use self::parallel::apply_patches as apply_patches_parallel;
