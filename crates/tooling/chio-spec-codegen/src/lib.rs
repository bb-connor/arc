//! Schema-to-Rust codegen for the Chio wire protocol.
//!
//! This crate is the Rust half of the four-language codegen pipeline gated by
//! `cargo xtask codegen` (see `xtask/codegen-tools.lock.toml` for the pinned
//! tool set per language). It walks
//! `spec/schemas/chio-wire/v1/**/*.schema.json`, parses each file as a
//! `schemars::schema::RootSchema`, registers each schema with its own
//! `typify::TypeSpace`, and emits one path-named Rust module per schema inside
//! a consolidated source file. The file carries the canonical `// DO NOT
//! EDIT` header so downstream tooling and humans can tell at a glance that it
//! is a regeneration target.
//!
//! # Output layout
//!
//! For an input tree like
//!
//! ```text
//! spec/schemas/chio-wire/v1/
//!   agent/heartbeat.schema.json
//!   agent/list_capabilities.schema.json
//!   jsonrpc/request.schema.json
//!   ...
//! ```
//!
//! the generator produces:
//!
//! ```text
//! crates/chio-core-types/src/_generated/
//!   chio_wire_v1.rs   (all types, formatted via prettyplease)
//!   mod.rs            (header-only module marker; not pulled into lib.rs yet)
//! ```
//!
//! The single-file emission keeps downstream consumers pointing at one
//! well-known file.
//!
//! # Header policy
//!
//! Every regenerated file begins with [`GENERATED_HEADER`]. The companion
//! `crates/chio-core-types/tests/_generated_check.rs` integration test scans
//! every `*.rs` file under `_generated/` and fails the build if any file is
//! missing the header.
//!
//! # Determinism
//!
//! Schema files are sorted lexicographically before their independent
//! `TypeSpace` modules are rendered, and the consolidated syntax tree is fed
//! through `prettyplease` so the byte output is reproducible across machines.
//! The xtask `codegen --check` mode compares the freshly regenerated output
//! against the on-disk file and exits non-zero on drift.
//!
//! # House rules
//!
//! - No `unwrap()` / `expect()` in non-test code (workspace clippy denies).
//! - All errors are surfaced as [`CodegenError`]; the crate never panics on
//!   malformed input.
//! - Absolute URI `$ref`s fail closed before typify generation except for the
//!   canonical Chio wire-schema namespace, which is resolved inside the local
//!   schema tree without network access.
//! - No em dashes (U+2014); use `-` or parentheses.

#![forbid(unsafe_code)]
mod errors_pass;
pub mod statemachines_pass;
pub mod threat_coverage_doc;
pub mod threat_model;

pub use statemachines_pass::{
    check_statemachine_outputs, codegen_statemachines, load_statemachines,
    render_statemachine_outputs, StateMachine, CONFORMANCE_ORDERING_DIR, STATEMACHINES_INPUT,
    STATE_MACHINES_DOC_OUTPUT,
};

/// Canonical header stamped onto every regenerated Rust source file.
///
/// The phrasing is matched exactly by
/// `crates/chio-core-types/tests/_generated_check.rs`. Keep this string in
/// sync with that test and with `xtask::codegen` if either is updated.
pub const GENERATED_HEADER: &str = "\
// DO NOT EDIT - regenerate via 'make regen-rust' or 'cargo xtask codegen rust'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:   typify =0.4.3 (see xtask/codegen-tools.lock.toml)
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration; the
// `_generated_check` integration test enforces this header on every file
// under `crates/chio-core-types/src/_generated/`.
";

include!("lib_parts/part_01.rs");
include!("lib_parts/part_02.rs");
