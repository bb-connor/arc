//! Chio deterministic-replay gate: library entry point.
//!
//! # Module map
//!
//! - [`driver`]: `Scenario` and `ScenarioDriver`.
//! - [`golden_writer`]: NDJSON receipts + JSON checkpoint + hex Merkle root.
//! - [`golden_reader`]: read goldens back as raw `Vec<u8>`.
//! - [`byte_compare`]: byte-equivalence harness.
//! - [`fs_iter`]: deterministic `LC_ALL=C` directory enumeration.
//! - [`bless`]: CHIO_BLESS gate logic for the `--bless` flow.

#![forbid(unsafe_code)]

pub mod bless;
pub mod byte_compare;
pub mod driver;
pub mod fs_iter;
pub mod gate;
pub mod golden_format;
pub mod golden_reader;
pub mod golden_writer;
