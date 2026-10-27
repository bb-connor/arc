#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::float_arithmetic
)]
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
    )
)]
//! Float-free Q16.16 fixed-point arithmetic for Chio decision models.
//!
//! Every operation is checked: a result outside the `i32` bit range is `None`,
//! never a wrapped or clamped value. Multiplication and division round toward
//! negative infinity. Ratio ordering is exact cross-multiplication with no
//! division.

mod q16;
mod ratio;

#[cfg(kani)]
pub mod kani_public_harnesses;

pub use q16::{checked_dot, checked_sum, Q16_16};
pub use ratio::ratio_cmp;
