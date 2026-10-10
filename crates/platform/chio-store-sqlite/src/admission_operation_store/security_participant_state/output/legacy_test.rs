//! Default-off modeled predecessor output join, scoped to one actual store.
use super::*;
use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

fn stores() -> &'static Mutex<BTreeSet<String>> {
    static STORES: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();
    STORES.get_or_init(|| Mutex::new(BTreeSet::new()))
}
pub(super) struct ModeledLegacyOutputScope(String);
impl Drop for ModeledLegacyOutputScope {
    fn drop(&mut self) {
        if let Ok(mut selected) = stores().lock() {
            selected.remove(&self.0);
        }
    }
}
impl SqliteAdmissionOperationStore {
    /// Qualification only: preserves the exact predecessor output join
    /// algorithm during a genuine owning native finalization. No operation,
    /// capture, raw output, receipt, signature or protected anchor is fabricated.
    /// Drop this scope before checking current completed-output delivery.
    pub fn modeled_legacy_output_join_for_test(
        &self,
    ) -> Result<impl Drop + 'static, AdmissionOperationStoreError> {
        let mut selected = stores()
            .lock()
            .map_err(|_| invalid("legacy output test scope is poisoned"))?;
        let key = self.serving_owner.fence.store_uuid.clone();
        if selected.len() >= 16 || !selected.insert(key.clone()) {
            return Err(invalid(
                "legacy output test scope is already selected or full",
            ));
        }
        Ok(ModeledLegacyOutputScope(key))
    }
}
pub(super) fn selected(store: &str) -> Result<bool, AdmissionOperationStoreError> {
    stores()
        .lock()
        .map(|selected| selected.contains(store))
        .map_err(|_| invalid("legacy output test scope is poisoned"))
}
