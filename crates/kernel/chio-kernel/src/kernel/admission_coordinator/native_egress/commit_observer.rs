//! Bounded test observation after event preparation and before the native writer.
use super::*;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

type Observer = Arc<dyn Fn(u64) + Send + Sync>;

fn registry() -> &'static Mutex<BTreeMap<String, Observer>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<String, Observer>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

struct ObservationScope {
    store_uuid: String,
}

impl Drop for ObservationScope {
    fn drop(&mut self) {
        if let Ok(mut observers) = registry().lock() {
            observers.remove(&self.store_uuid);
        }
    }
}

impl ChioKernel {
    /// Test-only observation of prepared event time. It grants no store or
    /// capture authority and never replaces the signed grant or original lease.
    pub fn observe_native_egress_commit_for_test(
        &self,
        observer: Arc<dyn Fn(u64) + Send + Sync>,
    ) -> Result<impl Drop + 'static, KernelError> {
        let store_uuid = self.durable_runtime()?.fence.store_uuid.clone();
        let mut observers = registry()
            .lock()
            .map_err(|_| invalid("native egress test observer registry is poisoned"))?;
        if observers.len() >= 64 || observers.contains_key(&store_uuid) {
            return Err(invalid("native egress test observer capacity is exhausted"));
        }
        observers.insert(store_uuid.clone(), observer);
        Ok(ObservationScope { store_uuid })
    }
}

pub(super) fn observe(store_uuid: &str, prepared_at: u64) -> Result<(), KernelError> {
    let observer = registry()
        .lock()
        .map_err(|_| invalid("native egress test observer registry is poisoned"))?
        .get(store_uuid)
        .cloned();
    if let Some(observer) = observer {
        observer(prepared_at);
    }
    Ok(())
}
