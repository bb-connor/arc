#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions,
    )
)]
#![forbid(unsafe_code)]
//! Pure response evidence model shared by the kernel and quarantine runtime.
//!
//! This crate validates and projects data. It has no stores, effect executors,
//! schedulers, network clients or clocks and cannot admit or dispatch effects.

pub mod simulation;
pub mod state;

pub use state::{CanonicalFailure, StateMachineError};

mod rejection_codes;
