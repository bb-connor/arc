//! Differential testing: executable ARC reference spec vs the production
//! capability structs and the normalized proof-facing AST in `arc-kernel-core`.
//!
//! This crate is the shipped proof-style release gate for scope attenuation
//! semantics. Lean assets remain advisory until they are root-imported and
//! `sorry`-free.

pub mod generators;
pub mod spec;
