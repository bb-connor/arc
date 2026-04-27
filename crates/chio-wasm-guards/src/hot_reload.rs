//! Hot-reload engine for WASM guards.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

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

/// Poller used by [`Engine`] to fetch the current registry digest for a guard.
pub trait RegistryDigestPoller: Send + 'static {
    /// Return the current digest for a guard, if the registry has one.
    fn current_digest(&mut self, guard_id: &str) -> Result<Option<String>, HotReloadError>;
}

impl<F> RegistryDigestPoller for F
where
    F: for<'a> FnMut(&'a str) -> Result<Option<String>, HotReloadError> + Send + 'static,
{
    fn current_digest(&mut self, guard_id: &str) -> Result<Option<String>, HotReloadError> {
        self(guard_id)
    }
}

/// Source-specific reload trigger details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadTriggerSource {
    /// A watched file or directory changed.
    FileChanged {
        /// Path reported by the file watcher.
        path: PathBuf,
    },
    /// A registry poll observed a new digest for the guard artifact.
    RegistryDigestChanged {
        /// New digest returned by the registry poller.
        digest: String,
    },
}

/// Reload trigger emitted by file watchers and registry poll tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadTrigger {
    /// Guard identifier associated with the trigger.
    pub guard_id: String,
    /// Trigger source.
    pub source: ReloadTriggerSource,
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

    /// File watcher setup failed.
    #[error("hot-reload file watcher failed: {0}")]
    FileWatcher(#[from] notify::Error),

    /// Reload trigger receiver was closed before the trigger could be sent.
    #[error("reload trigger receiver closed")]
    TriggerReceiverClosed,
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

    /// Watch a guard path and emit reload triggers when it changes.
    pub fn watch_guard_path(
        &self,
        guard_id: impl Into<String>,
        path: impl AsRef<Path>,
        trigger_tx: std::sync::mpsc::Sender<ReloadTrigger>,
    ) -> Result<RecommendedWatcher, HotReloadError> {
        let guard_id = guard_id.into();
        let watched_path = path.as_ref().to_path_buf();
        let fallback_path = watched_path.clone();
        let mut watcher =
            notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
                let Ok(event) = result else {
                    return;
                };
                if !is_reload_file_event(&event.kind) {
                    return;
                }
                let path = event
                    .paths
                    .first()
                    .cloned()
                    .unwrap_or_else(|| fallback_path.clone());
                let _ = trigger_tx.send(ReloadTrigger {
                    guard_id: guard_id.clone(),
                    source: ReloadTriggerSource::FileChanged { path },
                });
            })?;
        watcher.watch(&watched_path, RecursiveMode::NonRecursive)?;
        Ok(watcher)
    }

    /// Spawn a registry digest poll task keyed by guard ID.
    ///
    /// The task emits a reload trigger each time the observed digest changes
    /// from the last seen digest.
    pub fn spawn_registry_poll_task<P>(
        &self,
        guard_id: impl Into<String>,
        initial_digest: Option<String>,
        interval: Duration,
        mut poller: P,
        trigger_tx: mpsc::Sender<ReloadTrigger>,
    ) -> JoinHandle<Result<(), HotReloadError>>
    where
        P: RegistryDigestPoller,
    {
        let guard_id = guard_id.into();
        tokio::spawn(async move {
            let mut last_digest = initial_digest;
            let mut interval = tokio::time::interval(interval);
            loop {
                interval.tick().await;
                let Some(current_digest) = poller.current_digest(&guard_id)? else {
                    continue;
                };
                if last_digest.as_deref() == Some(current_digest.as_str()) {
                    continue;
                }
                last_digest = Some(current_digest.clone());
                trigger_tx
                    .send(ReloadTrigger {
                        guard_id: guard_id.clone(),
                        source: ReloadTriggerSource::RegistryDigestChanged {
                            digest: current_digest,
                        },
                    })
                    .await
                    .map_err(|_| HotReloadError::TriggerReceiverClosed)?;
            }
        })
    }
}

fn is_reload_file_event(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::Any | EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    )
}
