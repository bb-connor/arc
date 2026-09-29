//! Secret-bearing prepared dispatch ownership. Transport never receives its lock or records.
use super::{
    BTreeMap, BrokerError, BrokerService, CanonicalBrokerRevocationSet, Mutex, MutexGuard,
    PreparedHttpsDispatch, Result, SecretMaterial,
};

#[derive(Default)]
pub(super) struct RetainedDispatchCustody {
    entries: Mutex<BTreeMap<String, RetainedPreparedDispatch>>,
}

struct RetainedPreparedDispatch {
    operation_id: String,
    attempt_id: String,
    prepared_dispatch_id: String,
    request_canonical_digest: String,
    prepared_at_unix_seconds: u64,
    dispatch: PreparedHttpsDispatch,
    credential: SecretMaterial,
    credential_version: chio_store_sqlite::BlobHandle,
    revocation_set: CanonicalBrokerRevocationSet,
}

mod execution;
mod registration;

impl BrokerService {
    fn retained_prepared_dispatches(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<String, RetainedPreparedDispatch>>> {
        self.retained_dispatches.entries.lock().map_err(|_| {
            BrokerError::Invariant("retained prepared-dispatch lock is poisoned".to_string())
        })
    }

    pub(super) fn discard_prepared_dispatch(&self, operation_id: &str) -> Result<()> {
        self.retained_prepared_dispatches()?.remove(operation_id);
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn retained_prepared_dispatch_keys(
        &self,
    ) -> Result<std::collections::BTreeSet<String>> {
        Ok(self
            .retained_prepared_dispatches()?
            .keys()
            .cloned()
            .collect())
    }
}
