//! Encrypted persistence adapter for tee payload BLOBs.
//!
//! The tee only persists redacted payload bytes. At-rest encryption is
//! delegated to `chio-store-sqlite` so the runtime uses the same
//! tenant-key hook as other SQLite-backed surfaces.

use chio_core::crypto::sha256_hex;
use chio_store_sqlite::{
    BlobHandle, BlobStoreError, EncryptedBlob, SqliteEncryptedBlobStore, TenantId, TenantKey,
};

/// Metadata returned for a persisted redacted payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedBlob {
    /// Store handle required to read the encrypted BLOB later.
    pub handle: BlobHandle,
    /// Plaintext hash computed before encryption for frame linking.
    pub plaintext_sha256: String,
    /// Plaintext length in bytes.
    pub plaintext_len: usize,
}

/// Errors returned by tee encrypted persistence.
#[derive(Debug)]
pub enum PersistenceError {
    /// Underlying encrypted BLOB store failure.
    Store(BlobStoreError),
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "tee persistence store error: {error}"),
        }
    }
}

impl std::error::Error for PersistenceError {}

impl From<BlobStoreError> for PersistenceError {
    fn from(error: BlobStoreError) -> Self {
        Self::Store(error)
    }
}

/// Tee persistence facade backed by `SqliteEncryptedBlobStore`.
pub struct TeeBlobPersistence {
    store: SqliteEncryptedBlobStore,
}

impl TeeBlobPersistence {
    /// Construct from an already-open encrypted BLOB store.
    #[must_use]
    pub fn new(store: SqliteEncryptedBlobStore) -> Self {
        Self { store }
    }

    /// Persist redacted payload bytes with tenant-scoped encryption.
    pub fn persist_redacted_blob(
        &self,
        tenant_id: &TenantId,
        key: &TenantKey,
        payload: &[u8],
    ) -> Result<PersistedBlob, PersistenceError> {
        let plaintext_sha256 = sha256_hex(payload);
        let plaintext_len = payload.len();
        let handle = self.store.write_encrypted_blob(tenant_id, key, payload)?;
        Ok(PersistedBlob {
            handle,
            plaintext_sha256,
            plaintext_len,
        })
    }

    /// Read and decrypt a persisted payload.
    pub fn read_blob(
        &self,
        handle: &BlobHandle,
        key: &TenantKey,
    ) -> Result<Vec<u8>, PersistenceError> {
        self.store
            .read_encrypted_blob(handle, key)
            .map_err(PersistenceError::from)
    }

    /// Load encrypted material without returning plaintext.
    pub fn load_encrypted_blob(
        &self,
        handle: &BlobHandle,
    ) -> Result<EncryptedBlob, PersistenceError> {
        self.store
            .load_encrypted_blob(handle)
            .map_err(PersistenceError::from)
    }
}
