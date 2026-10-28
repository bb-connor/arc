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
//! Sealed feasible-set projection for Chio decision models.
//!
//! A proposer suggests an action; the envelope decides. Every projection
//! returns an action the envelope admits, and every fallback returns the
//! conservative action at index 0 of the feasible set.
//!
//! A `Projected` value has no public constructor, so the only way to obtain
//! one is through an `Envelope`:
//!
//! ```compile_fail
//! use chio_decision_model::{Projected, ProjectionOutcome};
//! let forged = Projected { action: 1u8, outcome: ProjectionOutcome::Identity };
//! ```
//!
//! ```compile_fail
//! use chio_decision_model::Projected;
//! let forged: Projected<u8> = 1u8.into();
//! ```
//!
//! ```compile_fail
//! use chio_decision_model::Envelope;
//! let forged = Envelope { feasible: &[1u8][..], fallback: 1u8 };
//! ```

mod envelope;
mod outcome;

#[cfg(kani)]
pub mod kani_public_harnesses;

pub use envelope::{Envelope, EnvelopeError, Projected, MAX_ENVELOPE_ACTIONS};
pub use outcome::{FallbackReason, ProjectionOutcome};
