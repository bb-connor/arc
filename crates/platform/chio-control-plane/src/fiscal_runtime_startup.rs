use chio_fiscal::{
    FiscalCharterRegistry, FiscalGenesisPolicy, FiscalRuntimeAdapterRegistry, FiscalStateAnchor,
    VerifiedFiscalContinuityCheckpoint, VerifiedFiscalRuntimeReadiness,
};
use chio_kernel::admission_operation::StoreMutationFence;
use chio_store_sqlite::fiscal_store::{FiscalStoreError, SqliteFiscalStore};

use crate::fiscal_state_recovery::{
    reconcile_fiscal_startup, FiscalStartupRecoveryAction, FiscalStartupRecoveryError,
};

#[derive(Debug, thiserror::Error)]
pub enum FiscalRuntimeStartupError {
    #[error("configured fiscal genesis policy differs from durable state")]
    GenesisPolicyMismatch,
    #[error("the installed fiscal runtime registry differs from anchored readiness")]
    RuntimeRegistryMismatch,
    #[error(transparent)]
    Store(#[from] FiscalStoreError),
    #[error(transparent)]
    Recovery(#[from] FiscalStartupRecoveryError),
}

#[derive(Debug, Clone)]
pub struct FiscalRuntimeStartup {
    pub recovery_action: FiscalStartupRecoveryAction,
    pub checkpoint: VerifiedFiscalContinuityCheckpoint,
    pub readiness: VerifiedFiscalRuntimeReadiness,
    pub charters: FiscalCharterRegistry,
}

pub fn reconcile_fiscal_runtime_startup(
    store: &SqliteFiscalStore,
    anchor: &dyn FiscalStateAnchor,
    configured_policy: &FiscalGenesisPolicy,
    installed_registry: &FiscalRuntimeAdapterRegistry,
    fence: &StoreMutationFence,
) -> Result<FiscalRuntimeStartup, FiscalRuntimeStartupError> {
    if store.load_genesis_policy()? != *configured_policy {
        return Err(FiscalRuntimeStartupError::GenesisPolicyMismatch);
    }
    let stored_charters = store.load_charter_registry()?;
    let recovery =
        reconcile_fiscal_startup(store, anchor, configured_policy, &stored_charters, fence)?;
    let readiness = store.load_runtime_readiness(
        &recovery.checkpoint.body().runtime_readiness_digest,
        configured_policy,
    )?;
    if readiness.runtime_registry() != installed_registry {
        return Err(FiscalRuntimeStartupError::RuntimeRegistryMismatch);
    }
    Ok(FiscalRuntimeStartup {
        recovery_action: recovery.action,
        checkpoint: recovery.checkpoint,
        readiness,
        charters: stored_charters,
    })
}
