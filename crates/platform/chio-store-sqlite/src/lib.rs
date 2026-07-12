//! SQLite-backed persistence, query, and report layer for the Chio protocol.
//!
//! This crate is the concrete persistent backend for the kernel's receipt log
//! and its supporting state. It implements the receipt store and query path,
//! budget and approval stores, capability-lineage and revocation stores, an
//! execution-nonce store, an encrypted-blob store, IOU and dead-letter stores,
//! and evidence-export queries. The store traits it implements are defined by
//! `chio-kernel` and `chio-core`. Reader-heavy receipt queries use a
//! connection pool (eight readers by default); writes are serialized through a
//! group-commit actor onto a single writer connection.
//!
//! # Modules
//!
//! - [`receipt_store`] / [`receipt_query`] -- receipt persistence and the
//!   query path.
//! - [`budget_store`] -- durable budget state.
//! - [`approval_store`] / [`batch_approval_store`] -- human-approval state.
//! - [`capability_lineage`] / [`revocation_store`] -- capability provenance and
//!   revocation.
//! - [`execution_nonce_store`] / [`dead_letters`] / [`iou_store`] -- nonce
//!   replay guard, settlement dead letters, and IOU envelopes.
//! - [`encrypted_blob`] / [`memory_provenance_store`] / [`evidence_export`] --
//!   encrypted payloads, memory provenance, and evidence export.

#![forbid(unsafe_code)]

pub mod approval_store;
pub mod authority;
pub mod batch_approval_store;
pub mod budget_store;
pub mod capability_lineage;
pub mod dead_letters;
pub mod encrypted_blob;
pub mod evidence_export;
pub mod execution_nonce_store;
pub mod iou_store;
#[cfg(feature = "lineage")]
pub mod lineage_cte;
pub mod memory_provenance_store;
pub mod receipt_query;
pub mod receipt_store;
pub mod revocation_store;
pub mod schema_version;

pub use chio_core::crypto::SharedCanonicalBytes;
pub use chio_core::{CanonicalBytes, CanonicalJsonWitness};
pub use chio_kernel::{EvidenceChildReceiptScope, EvidenceExportQuery};

/// Default SQLite reader pool size.
///
/// Reader-heavy receipt queries keep the existing eight-connection default.
pub const DEFAULT_READER_POOL_MAX_SIZE: u32 = 8;

/// Default SQLite writer pool size.
///
/// Receipt writes are serialized through the group-commit actor, so the
/// writer pool defaults to a single connection.
pub const DEFAULT_WRITER_POOL_MAX_SIZE: u32 = 1;

/// SQLite pool sizing for receipt-store read and write paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlitePoolConfig {
    pub reader_pool_max_size: u32,
    pub writer_pool_max_size: u32,
}

impl Default for SqlitePoolConfig {
    fn default() -> Self {
        Self {
            reader_pool_max_size: DEFAULT_READER_POOL_MAX_SIZE,
            writer_pool_max_size: DEFAULT_WRITER_POOL_MAX_SIZE,
        }
    }
}

/// Receipt-store construction options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteStoreOptions {
    pub pool: SqlitePoolConfig,
    /// When true (default), the append path uses the actor-owned verified
    /// head (O(1) predecessor check + O(b) delta cross-check). When false,
    /// the store keeps today's full per-append verification so operators can
    /// A/B a suspect database. Read-only after open.
    pub incremental_verification: bool,
}

impl Default for SqliteStoreOptions {
    fn default() -> Self {
        Self {
            pool: SqlitePoolConfig::default(),
            incremental_verification: true,
        }
    }
}

/// Whether a SQLite path opens a database that lives only in memory for the life
/// of the process. rusqlite enables URI filenames, so the bare `:memory:`
/// sentinel, `file::memory:`, and any `file:...?mode=memory` URI all open a
/// non-durable database that loses its contents on restart and must not be
/// mistaken for a durable store. Durability gates use this to refuse an in-memory
/// path where they would otherwise advertise durable persistence.
#[must_use]
pub fn is_in_memory_sqlite_path(path: &str) -> bool {
    if path.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    let Some(rest) = path.strip_prefix("file:") else {
        return false;
    };
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };
    if name.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|param| param.eq_ignore_ascii_case("mode=memory"))
    })
}

pub use approval_store::SqliteApprovalStore;
pub use authority::SqliteCapabilityAuthority;
pub use batch_approval_store::SqliteBatchApprovalStore;
pub use budget_store::SqliteBudgetStore;
pub use encrypted_blob::{
    decrypt_blob, encrypt_blob, BlobHandle, BlobStoreError, DecryptError, EncryptError,
    EncryptedBlob, SqliteEncryptedBlobStore, TenantId, TenantKey,
};
pub use execution_nonce_store::{SqliteExecutionNonceStore, SqliteExecutionNonceStoreError};
pub use iou_store::{SqliteIouEnvelopeStore, IOU_ENVELOPE_MIGRATION};
pub use memory_provenance_store::{SqliteMemoryProvenanceStore, SqliteMemoryProvenanceStoreError};
pub use receipt_store::{BackgroundCheckpointSigner, SqliteReceiptStore};
pub use revocation_store::SqliteRevocationStore;
pub use schema_version::{
    check_schema_version, stamp_schema_version, SchemaVersionError, CHIO_SQLITE_APPLICATION_ID,
};

#[cfg(test)]
mod tests {
    use super::is_in_memory_sqlite_path;

    #[test]
    fn classifies_in_memory_sqlite_paths() {
        for path in [
            ":memory:",
            ":MEMORY:",
            "file::memory:",
            "file:receipts.db?mode=memory",
            "file:receipts.db?cache=shared&mode=memory",
        ] {
            assert!(
                is_in_memory_sqlite_path(path),
                "{path} must classify as in-memory"
            );
        }
    }

    #[test]
    fn classifies_durable_sqlite_paths() {
        for path in [
            "receipts.db",
            "/var/lib/chio/receipts.db",
            "file:/var/lib/chio/receipts.db?mode=rwc",
            "file:receipts.db",
            "memory-notes.db",
        ] {
            assert!(
                !is_in_memory_sqlite_path(path),
                "{path} must classify as durable"
            );
        }
    }
}
