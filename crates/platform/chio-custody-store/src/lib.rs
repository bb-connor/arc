#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::as_conversions,
    )
)]
//! Blob custody and enterprise migration state on SQLite, with the connection
//! core they share.
//!
//! This crate depends only on the core, security and IPC-free type crates, so a
//! custody consumer does not link the kernel or the economic stores.
//!
//! - [`encrypted_blob`] -- tenant-scoped encrypted blob persistence.
//! - [`enterprise_migration_state`] -- the signed, append-only migration
//!   transition ledger.
//! - [`store_connection`] -- single-connection lock-poison recovery.
//! - [`store_clock`] -- the supplied clock and its fence.
//! - [`schema_version`] -- schema stamping and refusal of foreign databases.
//! - [`sqlite_uri`] -- SQLite path and URI classification.

pub mod encrypted_blob;
pub mod enterprise_migration_state;
pub mod schema_version;
pub mod sqlite_uri;
pub mod store_clock;
pub mod store_connection;

pub use encrypted_blob::{
    decrypt_blob, encrypt_blob, BlobHandle, BlobReference, BlobReferenceMutationOutcome,
    BlobStoreError, DecryptError, EncryptError, EncryptedBlob, SqliteEncryptedBlobStore, TenantId,
    TenantKey,
};
pub use enterprise_migration_state::{
    enterprise_migration_transition_digest, sign_enterprise_migration_transition,
    SqliteEnterpriseMigrationOpenPolicy, SqliteEnterpriseMigrationStateStore,
    SqliteEnterpriseMigrationStateStoreError,
};
