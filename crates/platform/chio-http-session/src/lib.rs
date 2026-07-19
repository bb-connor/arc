//! Per-session journal for the Chio runtime.
//!
//! This crate provides an append-only, hash-chained journal that tracks
//! request history, cumulative data flow (bytes read/written), delegation
//! depth, and tool invocation sequence within a single session.
//!
//! The journal persists across requests within a session and is available
//! to all guards. Entries are tamper-evident: each entry includes a SHA-256
//! hash of the previous entry, forming a hash chain.
//!
//! # Design
//!
//! - **Append-only**: entries can only be added, never modified or removed.
//! - **Hash-chained**: each entry hashes the previous entry's hash for
//!   tamper detection.
//! - **Thread-safe**: the journal is wrapped in a `Mutex` for safe concurrent
//!   access from multiple guards.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/lib_parts/part_01.inc"
));
