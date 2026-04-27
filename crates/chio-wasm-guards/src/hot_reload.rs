//! Hot-reload engine for WASM guards.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};

use crate::{EpochId, WasmGuard, WasmGuardAbi, WasmGuardError};

/// Factory used by [`Engine`] to compile replacement module bytes.
pub trait ReloadBackendFactory: Send + Sync + 'static {
    /// Build a loaded WASM backend from replacement module bytes.
    fn build_backend(
        &self,
        new_module_bytes: &[u8],
    ) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError>;
}

impl<F> ReloadBackendFactory for F
where
    F: Fn(&[u8]) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> + Send + Sync + 'static,
{
    fn build_backend(
        &self,
        new_module_bytes: &[u8],
    ) -> Result<Box<dyn WasmGuardAbi>, WasmGuardError> {
        self(new_module_bytes)
    }
}

/// Errors returned by the hot-reload engine.
#[derive(Debug, thiserror::Error)]
pub enum HotReloadError {
    /// The requested guard is not registered in this engine.
    #[error("guard {guard_id:?} is not registered")]
    GuardNotFound {
        /// Guard identifier passed to reload.
        guard_id: String,
    },

    /// Replacement module compilation or validation failed.
    #[error("failed to load replacement module for guard {guard_id:?}: {source}")]
    ReplacementLoad {
        /// Guard identifier passed to reload.
        guard_id: String,
        /// Backend load error.
        #[source]
        source: WasmGuardError,
    },

    /// The target guard's epoch counter is exhausted.
    #[error("epoch counter exhausted for guard {guard_id:?}")]
    EpochCounterExhausted {
        /// Guard identifier passed to reload.
        guard_id: String,
    },

    /// The internal guard registry lock was poisoned.
    #[error("hot-reload guard registry lock poisoned")]
    RegistryLockPoisoned,
}

/// Runtime hot-reload engine.
///
/// Guards are registered by stable guard ID. A reload builds the replacement
/// backend first, then atomically publishes it through the guard's ArcSwap
/// pointer. Existing evaluations that already loaded an older module snapshot
/// keep using that old epoch.
pub struct Engine<F>
where
    F: ReloadBackendFactory,
{
    guards: RwLock<HashMap<String, Arc<WasmGuard>>>,
    backend_factory: F,
}

impl<F> Engine<F>
where
    F: ReloadBackendFactory,
{
    /// Create a hot-reload engine with the supplied backend factory.
    #[must_use]
    pub fn new(backend_factory: F) -> Self {
        Self {
            guards: RwLock::new(HashMap::new()),
            backend_factory,
        }
    }

    /// Register a guard by stable guard ID.
    pub fn register_guard(
        &self,
        guard_id: impl Into<String>,
        guard: WasmGuard,
    ) -> Result<Arc<WasmGuard>, HotReloadError> {
        let guard = Arc::new(guard);
        self.guards
            .write()
            .map_err(|_| HotReloadError::RegistryLockPoisoned)?
            .insert(guard_id.into(), Arc::clone(&guard));
        Ok(guard)
    }

    /// Return the guard registered for `guard_id`, if present.
    pub fn guard(&self, guard_id: &str) -> Result<Option<Arc<WasmGuard>>, HotReloadError> {
        Ok(self
            .guards
            .read()
            .map_err(|_| HotReloadError::RegistryLockPoisoned)?
            .get(guard_id)
            .cloned())
    }

    /// Replace a guard's loaded module and return the published epoch ID.
    pub fn reload(
        &self,
        guard_id: &str,
        new_module_bytes: &[u8],
    ) -> Result<EpochId, HotReloadError> {
        let guard = self
            .guard(guard_id)?
            .ok_or_else(|| HotReloadError::GuardNotFound {
                guard_id: guard_id.to_string(),
            })?;

        let backend = self
            .backend_factory
            .build_backend(new_module_bytes)
            .map_err(|source| HotReloadError::ReplacementLoad {
                guard_id: guard_id.to_string(),
                source,
            })?;
        let module_sha256 = hex::encode(Sha256::digest(new_module_bytes));

        guard
            .replace_loaded_module(backend, Some(module_sha256))
            .ok_or_else(|| HotReloadError::EpochCounterExhausted {
                guard_id: guard_id.to_string(),
            })
    }
}
