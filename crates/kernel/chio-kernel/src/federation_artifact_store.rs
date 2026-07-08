//! Additive durable seam for bilateral co-sign artifacts (RFC-0004 F10). The
//! kernel caches DualSignedReceipt / DsseEnvelope in a capped, idle-swept
//! BoundedMap; when a FederationArtifactStore is configured, the co-sign hook
//! writes through to it first, and accessors fall through to it on a cache miss.

use std::collections::HashMap;
use std::sync::Mutex;

use chio_federation::bilateral::DualSignedReceipt;
use chio_federation::bilateral_dsse::DsseEnvelope;

use crate::KernelError;

pub trait FederationArtifactStore: Send + Sync {
    fn put_dual_signed(&self, id: &str, receipt: &DualSignedReceipt) -> Result<(), KernelError>;
    fn get_dual_signed(&self, id: &str) -> Result<Option<DualSignedReceipt>, KernelError>;
    fn put_dsse(&self, id: &str, envelope: &DsseEnvelope) -> Result<(), KernelError>;
    fn get_dsse(&self, id: &str) -> Result<Option<DsseEnvelope>, KernelError>;
}

/// Reference in-memory implementation (test double and default backing when a
/// deployment wants durable bilateral evidence without a database). A
/// deployment requiring persistence installs a database-backed impl instead.
#[derive(Default)]
pub struct InMemoryFederationArtifactStore {
    dual: Mutex<HashMap<String, DualSignedReceipt>>,
    dsse: Mutex<HashMap<String, DsseEnvelope>>,
}

impl FederationArtifactStore for InMemoryFederationArtifactStore {
    fn put_dual_signed(&self, id: &str, receipt: &DualSignedReceipt) -> Result<(), KernelError> {
        let mut guard = match self.dual.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(id.to_string(), receipt.clone());
        Ok(())
    }

    fn get_dual_signed(&self, id: &str) -> Result<Option<DualSignedReceipt>, KernelError> {
        let guard = match self.dual.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Ok(guard.get(id).cloned())
    }

    fn put_dsse(&self, id: &str, envelope: &DsseEnvelope) -> Result<(), KernelError> {
        let mut guard = match self.dsse.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(id.to_string(), envelope.clone());
        Ok(())
    }

    fn get_dsse(&self, id: &str) -> Result<Option<DsseEnvelope>, KernelError> {
        let guard = match self.dsse.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Ok(guard.get(id).cloned())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn trait_object_round_trips_absence_and_presence() {
        let store: Box<dyn FederationArtifactStore> =
            Box::new(InMemoryFederationArtifactStore::default());
        assert!(store.get_dual_signed("missing").unwrap().is_none());
        assert!(store.get_dsse("missing").unwrap().is_none());
    }
}
