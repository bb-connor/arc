use std::collections::HashSet;

use crate::RevocationStoreError;

/// Trait for checking whether a capability has been revoked.
///
/// Implementations may be in-memory, SQLite-backed, or subscribe to a
/// distributed revocation feed via Spine/NATS.
pub trait RevocationStore: Send {
    /// Check if a capability ID has been revoked.
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError>;

    /// Revoke a capability. Returns `true` if it was newly revoked.
    fn revoke(&mut self, capability_id: &str) -> Result<bool, RevocationStoreError>;
}

/// In-memory revocation store for development and testing.
#[derive(Debug, Default)]
pub struct InMemoryRevocationStore {
    revoked: HashSet<String>,
}

impl InMemoryRevocationStore {
    /// Create an empty revocation store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl RevocationStore for InMemoryRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(self.revoked.contains(capability_id))
    }

    fn revoke(&mut self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        Ok(self.revoked.insert(capability_id.to_owned()))
    }
}
