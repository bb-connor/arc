//! Authenticated receipt query snapshots.
//!
//! A process-owned projection of every tool receipt in the claim log through
//! one watermark serves receipt pages, counts and point reads. The projection
//! is authenticated once into owned storage, extended by authenticating only
//! what was appended, and recertified on a schedule; payload bytes are re-read
//! from the store and accepted only when they match the authenticated leaf.
#[path = "receipt_query_snapshot/db.rs"]
mod db;
#[path = "receipt_query_snapshot/export.rs"]
mod export;
#[path = "receipt_query_snapshot/extend.rs"]
mod extend;
#[path = "receipt_query_snapshot/fetch.rs"]
mod fetch;
#[path = "receipt_query_snapshot/pass.rs"]
mod pass;
#[path = "receipt_query_snapshot/project.rs"]
pub(crate) mod project;
#[path = "receipt_query_snapshot/query.rs"]
mod query;
#[path = "receipt_query_snapshot/service.rs"]
mod service;
#[path = "receipt_query_snapshot/walk.rs"]
mod walk;

pub use service::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshotStatus,
    ReceiptQuerySnapshots,
};

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test fixtures deliberately fail on violated setup invariants."
)]
#[path = "receipt_query_snapshot/tests.rs"]
mod tests;
