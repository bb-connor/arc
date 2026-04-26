//! Chio deterministic-replay gate: library entry point.
//!
//! This crate hosts the corpus driver and golden infrastructure for the
//! M04 deterministic-replay gate (see `.planning/trajectory/04-deterministic-replay.md`).
//!
//! # Phase 1 layout (incremental)
//!
//! Phase 1 of M04 lands as a sequence of atomic tickets:
//!
//! - T1: workspace-member skeleton (Cargo.toml plus `lib.rs` /
//!   `main.rs` / `README.md`).
//! - T2 (this commit): `Scenario` and `ScenarioDriver` types in
//!   [`driver`] (fixed clock, deterministic nonce counter, signer
//!   loaded from `tests/replay/test-key.seed`).
//! - T3: golden writer (NDJSON receipts, JSON checkpoint, hex Merkle root).
//! - T4: golden reader plus byte-comparison harness (raw `Vec<u8>`, no
//!   serde round-trip).
//! - T5: 50 fixture manifests across the eight families enumerated in the
//!   source-of-truth document.
//! - T6: `cargo test -p chio-replay-gate` glue (`corpus_smoke` test target).
//! - T7: `LC_ALL=C` plus explicit directory-listing sort wired into the driver.
//!
//! # Module map
//!
//! - [`driver`]: `Scenario` and `ScenarioDriver` (T2).
//! - `golden` (future): writer / reader / byte-equivalence helpers (T3, T4).
//! - `bless` (future): `--bless` flag plus the gate-logic checks added in Phase 2.

#![forbid(unsafe_code)]

pub mod driver;
