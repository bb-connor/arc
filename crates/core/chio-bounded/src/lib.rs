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
//! Reusable bounded in-memory collections for Chio serving processes.
//!
//! Core invariant: no long-lived collection in a serving process may exist
//! without (1) a capacity policy (ring, LRU, idle-sweep, or deny-at-cap) and
//! (2) a live size metric. This crate is the substrate: `Ring` and `BoundedMap`
//! each own a cloneable `SizeGauge`.

mod bounded_map;
mod gauge;
mod ring;
mod sync;

pub use bounded_map::BoundedMap;
pub use gauge::SizeGauge;
pub use ring::Ring;
