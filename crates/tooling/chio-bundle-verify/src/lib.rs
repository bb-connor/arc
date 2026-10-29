//! Offline verification of Chio evidence bundles.
//!
//! A bundle is an exported evidence package directory. [`verify_package`]
//! checks it against a verifier-owned `chio.verifier-trust.v1` file:
//! the kernel-signed export envelope, every file digest, every receipt and
//! checkpoint signature under a pinned key, the checkpoint chain, inclusion
//! proofs, transparency claims and the export's query scope.
//! [`verify_bundle`] and [`verify_decoded_bundle`] add the per-receipt column
//! report and refuse a required column this verifier cannot verify;
//! [`VerificationReport::require_columns`] refuses a required column that is
//! not `verified`.
//!
//! The crate reads no clock and opens no network or database connection.

#![forbid(unsafe_code)]

pub mod error;
pub mod federation;
pub mod package;
pub mod read;
pub mod report;
pub mod trust;
pub mod verify;

pub use error::{exit_class_for_urn, BundleVerifyError, BundleVerifyErrorKind, ExitClass};
pub use report::{
    verify_bundle, verify_decoded_bundle, ColumnResult, EvidenceClass, ReceiptColumns,
    ReceiptReport, VerificationReport, VerifiedBundle, BUNDLE_VERIFY_REPORT_SCHEMA,
};
pub use trust::read_trust_file;
pub use verify::{
    read_package, verify_decoded_package, verify_package, EmbeddedHttpError,
    EmbeddedHttpReceiptVerifier, VerifiedPackage,
};
