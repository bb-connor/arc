//! Curated adversarial case metadata for Chio trust-boundary tests.
//!
//! This crate is the shared loader for malicious-but-well-formed cases.
//! Concrete vectors live under `cases/`; the crate fixes the envelope and
//! validation rules.

#![forbid(unsafe_code)]

pub mod manifest;

include!("lib.part1.inc");
