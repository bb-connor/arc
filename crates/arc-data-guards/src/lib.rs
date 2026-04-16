//! Data layer guards for the ARC runtime kernel.
//!
//! This crate houses guards that inspect the *semantics* of data-store
//! accesses rather than merely the presence of a tool.  Phase 7.1 of the
//! ARC roadmap ships the first such guard, [`SqlQueryGuard`], which parses
//! SQL queries submitted to database tools and enforces allowlists on
//! operations, tables, columns, and predicates.
//!
//! Future phases (7.2, 7.3, 7.4) will add `VectorDbGuard`,
//! `WarehouseCostGuard`, and the post-invocation `QueryResultGuard` in
//! this same crate.  The module layout is designed to absorb those
//! additions without breaking the public surface.
//!
//! # Relationship to `arc-guards`
//!
//! `arc-data-guards` is a *sibling* of `arc-guards`.  It reuses the
//! [`arc_kernel::Guard`] trait and the [`arc_guards::extract_action`]
//! dispatcher; it does not redefine either.  Pipelines compose the two
//! crates transparently:
//!
//! ```ignore
//! use arc_guards::GuardPipeline;
//! use arc_data_guards::{SqlGuardConfig, SqlQueryGuard};
//!
//! let mut pipeline = GuardPipeline::default_pipeline();
//! pipeline.add(Box::new(SqlQueryGuard::new(SqlGuardConfig::default())));
//! ```
//!
//! # Fail-closed
//!
//! Every guard in this crate is fail-closed.  Parse errors deny, empty
//! configurations deny, and errors during regex compilation are logged
//! and dropped so they cannot accidentally widen policy.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod config;
pub mod error;
pub mod sql_guard;
pub mod sql_parser;

pub use config::{SqlDialect, SqlGuardConfig, SqlOperation};
pub use error::SqlGuardDenyReason;
pub use sql_guard::SqlQueryGuard;
pub use sql_parser::SqlAnalysis;
