//! A default-off sealing fault, available only through the
//! admission-test-support feature. The next seal of one armed authority
//! persists, then its writer fails before the entry the seal precedes, so the
//! owning transaction rolls back the seal and the entry together.
use super::*;
use crate::admission_operation_store::SqliteAdmissionOperationStore;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use std::sync::{Mutex, OnceLock};

type FaultKey = (String, String);

static ARMED: OnceLock<Mutex<BTreeSet<FaultKey>>> = OnceLock::new();

pub struct NativeJournalSealFaultGuard {
    key: FaultKey,
}

impl Drop for NativeJournalSealFaultGuard {
    fn drop(&mut self) {
        if let Some(armed) = ARMED.get() {
            if let Ok(mut armed) = armed.lock() {
                armed.remove(&self.key);
            }
        }
    }
}

impl SqliteAdmissionOperationStore {
    /// Arm one sealing fault for this store's native authority. It fires once.
    pub fn inject_native_journal_seal_fault_fixture(
        &self,
        binding: &NativeSecurityAuthorityBindingV1,
    ) -> Result<NativeJournalSealFaultGuard, AdmissionOperationStoreError> {
        if binding.store_uuid().as_str() != self.serving_owner.fence.store_uuid {
            return Err(invalid("native journal seal fault binding"));
        }
        let key = (
            self.serving_owner.fence.store_uuid.clone(),
            binding.security_authority_id().as_str().to_owned(),
        );
        let mut armed = ARMED
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
            .map_err(|_| invalid("native journal seal fault poisoned"))?;
        if !armed.insert(key.clone()) {
            return Err(invalid("native journal seal fault already armed"));
        }
        Ok(NativeJournalSealFaultGuard { key })
    }
}

/// Fails the sealing writer once, after its seal persisted, when armed.
pub(super) fn after_seal(
    owner: &SqliteServingOwner,
    authority: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(armed) = ARMED.get() else {
        return Ok(());
    };
    let mut armed = armed
        .lock()
        .map_err(|_| invalid("native journal seal fault poisoned"))?;
    if armed.remove(&(owner.fence.store_uuid.clone(), authority.to_owned())) {
        return Err(invalid("injected native journal seal fault"));
    }
    Ok(())
}
