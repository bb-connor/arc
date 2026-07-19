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

#[cfg(test)]
mod tests {
    use chio_fiscal::{
        FiscalAuthorityState, FiscalBootstrapState, FiscalRuntimeAdapter, FiscalStateAnchorError,
        SignedFiscalCharter, SignedFiscalContinuityCheckpoint, SignedFiscalRuntimeReadiness,
        VerifiedFiscalCharter, VerifiedFiscalContinuityCheckpoint, FISCAL_RUNTIME_ADAPTER_COUNT,
    };
    use chio_store_sqlite::SqliteAuthorityStore;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct FixedAnchor {
        checkpoint: SignedFiscalContinuityCheckpoint,
        unavailable: bool,
    }

    impl FiscalStateAnchor for FixedAnchor {
        fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
            if self.unavailable {
                Err(FiscalStateAnchorError::Unavailable)
            } else {
                Ok(self.checkpoint.clone())
            }
        }

        fn compare_and_swap(
            &self,
            _expected_checkpoint_digest: &str,
            _advance: &chio_fiscal::VerifiedFiscalContinuityAdvance,
        ) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
            Err(FiscalStateAnchorError::Conflict)
        }
    }

    fn fixture_bytes(name: &str) -> TestResult<Vec<u8>> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../../spec/schemas/chio-fiscal/v1/fixtures/{name}.positive.json"
        ));
        Ok(std::fs::read(path)?)
    }

    fn registry(version: &str) -> TestResult<FiscalRuntimeAdapterRegistry> {
        Ok(FiscalRuntimeAdapterRegistry::new(
            format!("build-{version}"),
            "chio.fiscal.runtime.v1".to_owned(),
            (0..FISCAL_RUNTIME_ADAPTER_COUNT)
                .map(|index| {
                    FiscalRuntimeAdapter::new(
                        format!("adapter-{index}"),
                        format!("{version}.{index}"),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        )?)
    }

    #[test]
    fn startup_requires_exact_local_pins_anchor_and_runtime_registry() -> TestResult {
        let policy: FiscalGenesisPolicy =
            serde_json::from_slice(&fixture_bytes("genesis-policy")?)?;
        let charter = VerifiedFiscalCharter::verify(
            serde_json::from_slice::<SignedFiscalCharter>(&fixture_bytes("charter")?)?,
        )?;
        let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()])?;
        let readiness = VerifiedFiscalRuntimeReadiness::verify(
            serde_json::from_slice::<SignedFiscalRuntimeReadiness>(&fixture_bytes(
                "consumer-readiness",
            )?)?,
            &policy,
            registry("1")?,
        )?;
        let checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
            serde_json::from_slice(&fixture_bytes("continuity-checkpoint")?)?,
            &policy,
            &charters,
        )?;
        let authority_state = FiscalAuthorityState::from_checkpoint(
            &policy,
            &checkpoint,
            FiscalBootstrapState::CharterPinned,
        )?;
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        std::fs::create_dir(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority.mutation_fence();
        let store = authority.fiscal_store();
        store.initialize_genesis(
            &policy,
            &authority_state,
            &charter,
            &readiness,
            &checkpoint,
            &fence,
        )?;
        let anchor = FixedAnchor {
            checkpoint: checkpoint.signed().clone(),
            unavailable: false,
        };

        let ready =
            reconcile_fiscal_runtime_startup(&store, &anchor, &policy, &registry("1")?, &fence)?;
        assert_eq!(ready.recovery_action, FiscalStartupRecoveryAction::Ready);
        assert_eq!(ready.checkpoint.digest(), checkpoint.digest());
        assert_eq!(ready.readiness.digest(), readiness.digest());

        assert!(matches!(
            reconcile_fiscal_runtime_startup(&store, &anchor, &policy, &registry("2")?, &fence,),
            Err(FiscalRuntimeStartupError::RuntimeRegistryMismatch)
        ));
        let unavailable = FixedAnchor {
            checkpoint: checkpoint.signed().clone(),
            unavailable: true,
        };
        assert!(matches!(
            reconcile_fiscal_runtime_startup(
                &store,
                &unavailable,
                &policy,
                &registry("1")?,
                &fence,
            ),
            Err(FiscalRuntimeStartupError::Recovery(
                FiscalStartupRecoveryError::Anchor(FiscalStateAnchorError::Unavailable)
            ))
        ));
        let mut mismatched_policy = policy.clone();
        mismatched_policy.anchor_namespace.push_str("-other");
        assert!(matches!(
            reconcile_fiscal_runtime_startup(
                &store,
                &anchor,
                &mismatched_policy,
                &registry("1")?,
                &fence,
            ),
            Err(FiscalRuntimeStartupError::GenesisPolicyMismatch)
        ));
        Ok(())
    }
}
