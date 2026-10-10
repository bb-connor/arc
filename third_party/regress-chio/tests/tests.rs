// We like hashes around raw string literals.
#![allow(clippy::needless_raw_string_hashes)]

// Work around dead code warnings: rust-lang issue #46379
pub mod common;
use common::*;

include!("tests_cases/part_1.rs");
include!("tests_cases/part_2.rs");
