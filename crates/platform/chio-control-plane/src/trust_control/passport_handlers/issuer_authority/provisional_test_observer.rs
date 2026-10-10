//! One-shot observations of successful provisional issuer construction.
use super::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

type Observer = Box<dyn FnOnce(&PublicKey) -> Result<(), Response> + Send>;

fn observers() -> &'static Mutex<BTreeMap<PathBuf, Observer>> {
    static OBSERVERS: OnceLock<Mutex<BTreeMap<PathBuf, Observer>>> = OnceLock::new();
    OBSERVERS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(crate) struct ProvisionalIssuerObservation(PathBuf);

impl Drop for ProvisionalIssuerObservation {
    fn drop(&mut self) {
        observers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.0);
    }
}

/// Scope one callback to a fixture's unique registry path. The brief map lock
/// is released before the callback runs, so another fixture never waits for it.
pub(crate) fn observe_provisional_issuer_once(
    path: &Path,
    observer: impl FnOnce(&PublicKey) -> Result<(), Response> + Send + 'static,
) -> Result<ProvisionalIssuerObservation, &'static str> {
    let mut registered = observers().lock().map_err(|_| "observer lock poisoned")?;
    if registered.contains_key(path) {
        return Err("provisional observer already registered for this fixture");
    }
    registered.insert(path.to_path_buf(), Box::new(observer));
    Ok(ProvisionalIssuerObservation(path.to_path_buf()))
}

pub(crate) fn after_operation(
    state: &TrustServiceState,
    selected: &PublicKey,
) -> Result<(), Response> {
    let Some(path) = state.config.passport_issuance_offers_file.as_deref() else {
        return Ok(());
    };
    let observer = observers()
        .lock()
        .map_err(|_| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, "observer lock poisoned"))?
        .remove(path);
    if let Some(observer) = observer {
        observer(selected)?;
    }
    Ok(())
}
