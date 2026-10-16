//! `chio.work.v1`: the closed wire contract of the Work facade.
//!
//! These are untrusted data shapes with checked identifiers and bounds.
//! Decoding verifies no signature, authority, audience or liveness; every
//! owning service rechecks its own authority at commitment.

mod decode;
mod error;
mod ids;
mod wire;

pub use decode::*;
pub use error::*;
pub use ids::*;
pub use wire::*;
