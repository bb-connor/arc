//! Chio tool-call fabric: provider-agnostic types and traits for LLM tool-call dispatch.
//!
//! Phase 1 of M07. T1 lands the workspace member; T2-T6 fill in the
//! ProvenanceStamp, signed-bytes equivalence, and per-provider adapter
//! interface.

#![forbid(unsafe_code)]

// pub mod types;       // T2
// pub mod adapter;     // T3
// pub mod provenance;  // T4

// Placeholder so the crate has a non-empty public surface.
pub const FABRIC_VERSION: &str = "0.1.0-skeleton";
