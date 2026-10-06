//! The original kernel owns progress; one call visits one bounded physical page.
use super::*;
use crate::admission_operation::AdmissionOperationStoreError;

struct RunningGuard<'a>(&'a Mutex<AdmissionRecoveryBatchState>);
impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.running = false;
        }
    }
}

impl ChioKernel {
    /// Reconcile at most one physical page of retained admissions.
    ///
    /// The count must be 1..=256. Known item failures retain their original
    /// operation and a fenced backoff marker. Global authority or integrity
    /// failures return an error and leave the cursor at its previous page.
    /// A concurrently owned batch returns zero changes. This count never
    /// claims that every deferred financial effect has completed.
    pub fn reconcile_recoverable_admissions_batch(
        &self,
        candidate_limit: usize,
    ) -> Result<usize, KernelError> {
        if !(1..=256).contains(&candidate_limit) {
            return Err(durable_store_error(
                AdmissionOperationStoreError::Invariant(
                    "recovery batch candidate limit must be between 1 and 256".into(),
                ),
            ));
        }
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(0);
        };
        let cursor = {
            let mut state = runtime
                .recovery_batch
                .lock()
                .map_err(|_| cursor_lock_error())?;
            if state.running {
                return Ok(0);
            }
            state.running = true;
            state.cursor.clone()
        };
        let running = RunningGuard(&runtime.recovery_batch);
        let now = runtime.refresh_trusted_time(0)?;
        let (changed, next) =
            self.reconcile_admission_recovery_page(now, candidate_limit, cursor.as_ref())?;
        {
            let mut state = runtime
                .recovery_batch
                .lock()
                .map_err(|_| cursor_lock_error())?;
            state.cursor = next;
        }
        // Keep the logical running claim until cursor publication is complete.
        // No cursor mutex is held while a rail or qualified store is called.
        drop(running);
        Ok(changed)
    }
}

fn cursor_lock_error() -> KernelError {
    durable_store_error(AdmissionOperationStoreError::Invariant(
        "recovery batch cursor lock is poisoned".into(),
    ))
}
