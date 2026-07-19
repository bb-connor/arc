//! SQLite-backed HITL approval store.
//!
//! Pending requests survive kernel restart because every `store_pending`
//! call persists into a WAL-journaled SQLite database. Duplicate ids are
//! idempotent only when the serialized payload matches exactly; mismatched
//! retries are rejected so in-flight HITL state cannot be silently
//! overwritten. Resolved approvals and consumed tokens live in the same
//! database so the replay registry survives alongside the pending log.
//!
//! The store is synchronous; it uses a small r2d2 pool to keep the
//! hot-path query against a cheap connection pool rather than opening a
//! new file handle per call.

include!("approval_store_parts/part_01.rs");
include!("approval_store_parts/part_02.rs");
