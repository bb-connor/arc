//! Default-off predecessor capture model for owning native upgrade regressions.
use super::*;
use std::{
    collections::BTreeSet,
    sync::{Mutex, OnceLock},
};

fn selected_stores() -> &'static Mutex<BTreeSet<String>> {
    static STORES: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    STORES.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// The scope belongs to one actual authority store, including its native worker
/// threads. Dropping it restores current mandatory annotation behavior.
#[must_use]
pub struct ModeledLegacyIncompleteAnnotationCaptureGuard {
    store_uuid: String,
}

impl Drop for ModeledLegacyIncompleteAnnotationCaptureGuard {
    fn drop(&mut self) {
        // A poisoned registry makes every later selection fail closed. Cleanup
        // must neither panic nor silently reset that failed registry.
        if let Ok(mut selected) = selected_stores().lock() {
            selected.remove(&self.store_uuid);
        }
    }
}

pub(super) fn selected(store_uuid: &str) -> Result<bool, AdmissionOperationStoreError> {
    Ok(selected_stores()
        .lock()
        .map_err(|_| refused("legacy annotation fixture registry unavailable"))?
        .contains(store_uuid))
}

impl SqliteAdmissionOperationStore {
    /// Model only the predecessor's absent completeness/current-answer gates.
    /// All native signed route, caller, dispatch, receipt and output custody
    /// checks remain active. This fixture cannot be selected by request bytes.
    pub fn modeled_legacy_incomplete_annotation_capture_for_test(
        &self,
    ) -> Result<ModeledLegacyIncompleteAnnotationCaptureGuard, AdmissionOperationStoreError> {
        let store_uuid = self.serving_owner.fence.store_uuid.clone();
        let mut selected = selected_stores()
            .lock()
            .map_err(|_| refused("legacy annotation fixture registry unavailable"))?;
        if !selected.insert(store_uuid.clone()) {
            return Err(refused("legacy annotation fixture already selected"));
        }
        Ok(ModeledLegacyIncompleteAnnotationCaptureGuard { store_uuid })
    }
}
