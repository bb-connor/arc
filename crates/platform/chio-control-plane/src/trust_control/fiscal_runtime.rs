use super::*;
use chio_fiscal::{FiscalGenesisPolicy, FiscalRuntimeAdapterRegistry, FiscalStateAnchor};
use chio_kernel::admission_operation::StoreMutationFence;
use chio_store_sqlite::fiscal_store::SqliteFiscalStore;

use crate::fiscal_runtime_readiness::production_fiscal_runtime_assembler;
use crate::fiscal_runtime_startup::{reconcile_fiscal_runtime_startup, FiscalRuntimeStartup};
use crate::fiscal_state_anchor::{compose_fiscal_state_anchor, RemoteFiscalStateAnchorConfig};

const FISCAL_RUNTIME_SCHEMA_VERSION: &str = "chio.fiscal.runtime.v1";

pub(crate) struct TrustFiscalRuntime {
    store: SqliteFiscalStore,
    fence: StoreMutationFence,
    anchor: Arc<dyn FiscalStateAnchor>,
    policy: FiscalGenesisPolicy,
    registry: FiscalRuntimeAdapterRegistry,
}

impl TrustFiscalRuntime {
    pub(crate) fn reconcile(&self) -> Result<FiscalRuntimeStartup, CliError> {
        reconcile_fiscal_runtime_startup(
            &self.store,
            self.anchor.as_ref(),
            &self.policy,
            &self.registry,
            &self.fence,
        )
        .map_err(fiscal_startup_error)
    }
}

pub(crate) fn compose_trust_fiscal_runtime(
    authority: Option<&Arc<SqliteAuthorityStore>>,
    config: Option<&TrustFiscalRuntimeConfig>,
) -> Result<Option<Arc<TrustFiscalRuntime>>, CliError> {
    let Some(config) = config else {
        return Ok(None);
    };
    let authority = authority.ok_or_else(|| {
        CliError::cli_other_error("fiscal runtime requires the joint authority database".to_owned())
    })?;
    let store = authority.fiscal_store();
    let charters = store
        .load_charter_registry()
        .map_err(fiscal_startup_error)?;
    let anchor = compose_fiscal_state_anchor(RemoteFiscalStateAnchorConfig {
        base_url: config.anchor_url.clone(),
        bearer_token: config.anchor_bearer_token.clone(),
        timeout: config.anchor_timeout,
        policy: config.genesis_policy.clone(),
        charters,
    })
    .map_err(fiscal_startup_error)?;
    compose_trust_fiscal_runtime_with_anchor(authority, config, anchor).map(Some)
}

fn compose_trust_fiscal_runtime_with_anchor(
    authority: &SqliteAuthorityStore,
    config: &TrustFiscalRuntimeConfig,
    anchor: Arc<dyn FiscalStateAnchor>,
) -> Result<Arc<TrustFiscalRuntime>, CliError> {
    let store = authority.fiscal_store();
    let fence = authority.mutation_fence();
    let registry = production_fiscal_runtime_assembler()
        .and_then(|assembler| {
            assembler.self_test_and_build_registry(
                env!("CARGO_PKG_VERSION"),
                FISCAL_RUNTIME_SCHEMA_VERSION,
            )
        })
        .map_err(fiscal_startup_error)?;
    reconcile_fiscal_runtime_startup(
        &store,
        anchor.as_ref(),
        &config.genesis_policy,
        &registry,
        &fence,
    )
    .map_err(fiscal_startup_error)?;
    Ok(Arc::new(TrustFiscalRuntime {
        store,
        fence,
        anchor,
        policy: config.genesis_policy.clone(),
        registry,
    }))
}

fn fiscal_startup_error(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(format!(
        "fiscal runtime failed closed during trust-control startup: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_fiscal::{
        FiscalAuthorityState, FiscalBootstrapState, FiscalCharterRegistry,
        FiscalContinuityCheckpointBuilder, FiscalDomain, FiscalDomainState,
        FiscalRuntimeReadinessBuilder, FiscalStateAnchorError, SignedFiscalCharter,
        SignedFiscalContinuityCheckpoint, VerifiedFiscalCharter,
        VerifiedFiscalContinuityCheckpoint, VerifiedFiscalRuntimeReadiness,
    };

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct FixedAnchor(SignedFiscalContinuityCheckpoint);

    impl FiscalStateAnchor for FixedAnchor {
        fn read(&self) -> Result<SignedFiscalContinuityCheckpoint, FiscalStateAnchorError> {
            Ok(self.0.clone())
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
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../../spec/schemas/chio-fiscal/v1/fixtures/{name}.positive.json"
        ));
        Ok(std::fs::read(path)?)
    }

    #[test]
    fn service_composition_recomputes_readiness_before_serving() -> TestResult {
        let policy: FiscalGenesisPolicy =
            serde_json::from_slice(&fixture_bytes("genesis-policy")?)?;
        let charter = VerifiedFiscalCharter::verify(
            serde_json::from_slice::<SignedFiscalCharter>(&fixture_bytes("charter")?)?,
        )?;
        let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()])?;
        let registry = production_fiscal_runtime_assembler()?.self_test_and_build_registry(
            env!("CARGO_PKG_VERSION"),
            FISCAL_RUNTIME_SCHEMA_VERSION,
        )?;
        let anchor_key = Keypair::from_seed(&[8; 32]);
        let readiness = VerifiedFiscalRuntimeReadiness::verify(
            FiscalRuntimeReadinessBuilder {
                readiness_sequence: 1,
                runtime_registry: registry.clone(),
                attested_at: 50,
            }
            .sign(&policy, &anchor_key)?,
            &policy,
            registry,
        )?;
        let checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
            FiscalContinuityCheckpointBuilder {
                continuity_sequence: 0,
                previous_checkpoint_digest: None,
                pinned_charter_id: charter.body().charter_id.clone(),
                pinned_charter_digest: charter.digest().to_owned(),
                pinned_charter_sequence: charter.body().sequence,
                runtime_readiness_digest: readiness.digest().to_owned(),
                domains: [
                    FiscalDomain::TierLimits,
                    FiscalDomain::MarketplaceDiscountPerHundred,
                    FiscalDomain::DecisionPremiumBasisPoints,
                    FiscalDomain::InsurancePremiumSchedule,
                    FiscalDomain::OpenMarketFeeAndBondSchedule,
                ]
                .into_iter()
                .map(FiscalDomainState::never_activated)
                .collect(),
                trusted_clock_high_water: 50,
                staged_transition: None,
            }
            .sign(&policy, &anchor_key)?,
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
        authority.fiscal_store().initialize_genesis(
            &policy,
            &authority_state,
            &charter,
            &readiness,
            &checkpoint,
            &authority.mutation_fence(),
        )?;
        let config = TrustFiscalRuntimeConfig {
            genesis_policy: policy,
            anchor_url: "https://fiscal-anchor.example".to_owned(),
            anchor_bearer_token: "fixture-token".to_owned(),
            anchor_timeout: Duration::from_secs(1),
        };

        let runtime = compose_trust_fiscal_runtime_with_anchor(
            &authority,
            &config,
            Arc::new(FixedAnchor(checkpoint.signed().clone())),
        )?;

        let reconciled = runtime.reconcile()?;
        assert_eq!(reconciled.checkpoint.digest(), checkpoint.digest());
        assert_eq!(reconciled.readiness.digest(), readiness.digest());
        assert_eq!(runtime.policy, config.genesis_policy);
        assert_eq!(runtime.store.load_authority_state()?, authority_state);
        assert_eq!(runtime.fence, authority.mutation_fence());
        assert_eq!(runtime.anchor.read()?, *checkpoint.signed());
        Ok(())
    }
}
