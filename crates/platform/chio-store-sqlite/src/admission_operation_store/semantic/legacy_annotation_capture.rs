//! Default-off producer for captures whose selected annotation answers were omitted.
use super::*;
use std::{
    collections::BTreeSet,
    sync::{Mutex, OnceLock},
};

fn selected_stores() -> &'static Mutex<BTreeSet<String>> {
    static STORES: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    STORES.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// Scoped to one authority store, including its native worker threads.
/// Dropping the guard restores mandatory annotation answers.
struct LegacyIncompleteAnnotationCaptureGuard {
    store_uuid: String,
}

impl Drop for LegacyIncompleteAnnotationCaptureGuard {
    fn drop(&mut self) {
        // A poisoned registry leaves every later selection failing closed.
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
    /// Lifts only the completeness and current-answer gates for selected
    /// annotators, so a genuine native capture can retain an omitted answer.
    /// Signed route, caller, source, ACL, dispatch, receipt and output custody
    /// checks stay active. Request bytes cannot select this fixture.
    #[must_use = "dropping the guard restores mandatory annotation answers"]
    pub fn modeled_legacy_incomplete_annotation_capture_for_test(
        &self,
    ) -> Result<impl Drop + 'static, AdmissionOperationStoreError> {
        let store_uuid = self.serving_owner.fence.store_uuid.clone();
        let mut selected = selected_stores()
            .lock()
            .map_err(|_| refused("legacy annotation fixture registry unavailable"))?;
        if !selected.insert(store_uuid.clone()) {
            return Err(refused("legacy annotation fixture already selected"));
        }
        Ok(LegacyIncompleteAnnotationCaptureGuard { store_uuid })
    }
}
