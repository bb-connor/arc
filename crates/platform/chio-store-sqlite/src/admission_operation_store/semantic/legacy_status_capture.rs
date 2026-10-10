//! Exact, default-off predecessor model for an absent authored status audience.
use super::*;
use std::{
    collections::BTreeSet,
    sync::{Mutex, OnceLock},
};

const MAX_SELECTIONS: usize = 16;
type Selection = (String, Vec<u8>);

fn selected_requests() -> &'static Mutex<BTreeSet<Selection>> {
    static REQUESTS: OnceLock<Mutex<BTreeSet<Selection>>> = OnceLock::new();
    REQUESTS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// One exact request in one actual store may model the predecessor gate.
/// This does not alter signatures, dispatch custody or any other authority.
#[must_use]
pub struct ModeledLegacyMissingStatusCaptureGuard {
    selection: Selection,
}

impl Drop for ModeledLegacyMissingStatusCaptureGuard {
    fn drop(&mut self) {
        if let Ok(mut selected) = selected_requests().lock() {
            selected.remove(&self.selection);
        }
    }
}

pub(super) fn selected(
    store_uuid: &str,
    request: &ToolCallRequest,
) -> Result<bool, AdmissionOperationStoreError> {
    let selected = selected_requests()
        .lock()
        .map_err(|_| refused("legacy status fixture registry unavailable"))?;
    if !selected.iter().any(|(store, _)| store == store_uuid)
        || super::legacy_input_floor::has_transient_credentials(request)
    {
        return Ok(false);
    }
    Ok(selected.contains(&(
        store_uuid.to_owned(),
        super::legacy_input_floor::request_bytes(request)?,
    )))
}

impl SqliteAdmissionOperationStore {
    /// Model only the predecessor's missing authored status declaration for
    /// one exact request. Current native checks and every other semantic gate
    /// remain active. Dropping the guard restores the current declaration gate.
    pub fn modeled_legacy_missing_status_capture_for_test(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ModeledLegacyMissingStatusCaptureGuard, AdmissionOperationStoreError> {
        let selection = (
            self.serving_owner.fence.store_uuid.clone(),
            super::legacy_input_floor::request_bytes(request)?,
        );
        let mut selected = selected_requests()
            .lock()
            .map_err(|_| refused("legacy status fixture registry unavailable"))?;
        if selected.len() >= MAX_SELECTIONS || !selected.insert(selection.clone()) {
            return Err(refused("legacy status fixture is full or already selected"));
        }
        Ok(ModeledLegacyMissingStatusCaptureGuard { selection })
    }
}
