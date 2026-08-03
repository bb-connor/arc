use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use super::super::active_defense::{
    TrustControlActiveDefenseRuntime, TrustControlActiveDefenseRuntimeConfig,
};
use crate::security::{
    ActiveDefenseServiceRegistry, AlertOutboxConfig, AttestedFindingAdmissionArtifacts,
    AttestedFindingDispatchCommittedResume, AttestedFindingPreDispatchReconstruction,
    AttestedFindingResponseCompletionProof, AttestedFindingResponseCoordinator,
    AttestedFindingResponsePolicyPlanner, AttestedFindingResponseRecoveryLimits,
    PreparedAttestedFindingResponse, ProductionActiveDefenseConfig,
    ProductionActiveDefenseHostConfig, ProductionResponseSchedulerConfig,
    ProductionResponseWorkerLoopConfig, ProductionSecurityStateAuthority,
    ReservedAttestedFindingResponsePlan, ResponseWorkerLifecycle, SecurityDurability,
    SqliteSiemOutbox, TrustedSecurityEventProducer,
};
use chio_core::{Ed25519Backend, Keypair, SigningBackend};
use chio_kernel::IndexedSecurityEvidenceStore;
use chio_quarantine::{CorrelationPolicy, RuleLimits, SchedulerPolicy, TemporalRule};
use chio_security_kernel::SecurityClock;
use chio_security_types::ports::{
    BlastRadiusFenceAcquisition, BlastRadiusPort, BlastRadiusRequest, BlastRadiusResult,
    LeaseOwnerId, LineageFence, LineageFenceRelease, LineageFenceRequest, PortError, PortResult,
    PreparedActiveResponseDispatchBinding, ProducerId, RecordId, SchedulerHealthPort, TenantId,
};
use chio_security_types::ResponsePlan;
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::SqliteReceiptStore;

struct NoopAlertBackend;

impl AlertBackend for NoopAlertBackend {
    fn name(&self) -> &str {
        "trust-control-active-defense-test"
    }

    fn dispatch<'a>(
        &'a self,
        _: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

struct FixedClock(u64);

impl SecurityClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(self.0)
    }
}

impl chio_store_sqlite::security_state::SecurityStateClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        Ok(self.0)
    }
}

struct ReadyBlastRadius;

impl BlastRadiusPort for ReadyBlastRadius {
    fn ensure_blast_radius_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn resolve(&self, _: &BlastRadiusRequest) -> PortResult<BlastRadiusResult> {
        Err(PortError::unavailable())
    }

    fn acquire_fence(
        &self,
        _: &BlastRadiusFenceAcquisition,
        _: &LineageFenceRequest,
    ) -> PortResult<LineageFence> {
        Err(PortError::unavailable())
    }

    fn query_fence(&self, _: &LineageFenceRequest) -> PortResult<Option<LineageFence>> {
        Ok(None)
    }

    fn renew_fence(
        &self,
        _: &chio_security_types::ports::LineageFenceRenewal,
    ) -> PortResult<LineageFence> {
        Err(PortError::unavailable())
    }

    fn release_fence(&self, _: &LineageFenceRelease) -> PortResult<()> {
        Err(PortError::unavailable())
    }
}

struct ReadyPlanner;

impl AttestedFindingResponsePolicyPlanner for ReadyPlanner {
    fn ensure_ready(&self) -> PortResult<()> {
        Ok(())
    }
}

struct FailClosedResponseCoordinator;

impl AttestedFindingResponseCoordinator for FailClosedResponseCoordinator {
    fn ensure_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn recover_committed(
        &self,
        _: &ResponsePlan,
        _: &RecordId,
    ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
        Err(PortError::integrity_failure())
    }

    fn resume_dispatch_committed(
        &self,
        _: &ResponsePlan,
        _: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingDispatchCommittedResume> {
        Err(PortError::integrity_failure())
    }

    fn reconstruct_pre_dispatch(
        &self,
        _: &ReservedAttestedFindingResponsePlan,
        _: AttestedFindingAdmissionArtifacts,
        _: &PreparedActiveResponseDispatchBinding,
    ) -> PortResult<AttestedFindingPreDispatchReconstruction> {
        Err(PortError::integrity_failure())
    }

    fn terminate_never_committed(
        &self,
        _: &ResponsePlan,
        _: &PreparedActiveResponseDispatchBinding,
        _: Option<&AttestedFindingAdmissionArtifacts>,
    ) -> PortResult<()> {
        Err(PortError::integrity_failure())
    }

    fn prepare_admission(
        &self,
        _: &ReservedAttestedFindingResponsePlan,
        _: AttestedFindingAdmissionArtifacts,
    ) -> PortResult<PreparedAttestedFindingResponse> {
        Err(PortError::integrity_failure())
    }

    fn cancel_prepared(
        &self,
        _: &ReservedAttestedFindingResponsePlan,
        _: &PreparedAttestedFindingResponse,
    ) -> PortResult<()> {
        Err(PortError::integrity_failure())
    }

    fn execute_prepared(
        &self,
        _: &ReservedAttestedFindingResponsePlan,
        _: PreparedAttestedFindingResponse,
    ) -> PortResult<AttestedFindingResponseCompletionProof> {
        Err(PortError::integrity_failure())
    }
}

struct RuntimeFixture {
    _directory: tempfile::TempDir,
    security_path: std::path::PathBuf,
    config: ProductionActiveDefenseHostConfig,
}

impl RuntimeFixture {
    fn new() -> Self {
        let directory =
            chio_test_support::private_fs::private_tempdir("control-plane-service-active-defense-")
                .unwrap_or_else(|error| panic!("tempdir: {error}"));
        let security_path = directory.path().join("security.sqlite");
        let clock = Arc::new(FixedClock(50_000));
        let store_clock: Arc<dyn chio_store_sqlite::security_state::SecurityStateClock> =
            clock.clone();
        let security_state_authority =
            ProductionSecurityStateAuthority::open_with_trusted_clock(&security_path, store_clock)
                .unwrap_or_else(|error| panic!("security state authority: {error}"));
        let receipt_store = Arc::new(
            SqliteReceiptStore::open(directory.path().join("receipts.sqlite"))
                .unwrap_or_else(|error| panic!("receipt store: {error}")),
        );
        let alert_outbox = Arc::new(
            SqliteSiemOutbox::open(
                directory.path().join("alerts.sqlite"),
                vec![Arc::new(NoopAlertBackend) as Arc<dyn AlertBackend>],
                AlertOutboxConfig {
                    base_retry_ms: 10,
                    max_retry_ms: 100,
                    max_attempts: 3,
                },
            )
            .unwrap_or_else(|error| panic!("alert outbox: {error}")),
        );
        let keypair = Keypair::from_seed(&[73_u8; 32]);
        let signer: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(keypair.clone()));
        let indexed_evidence_store: Arc<dyn IndexedSecurityEvidenceStore> = receipt_store;
        let scheduler_health: Arc<dyn SchedulerHealthPort> = alert_outbox.clone();
        let tenant_id =
            TenantId::new("tenant-trust-runtime").unwrap_or_else(|error| panic!("tenant: {error}"));
        let rule = TemporalRule::parse_json(
            br#"{
                "rule_id":"trust-runtime-rule",
                "policy_version":"trust-runtime-policy",
                "group_by":"session_id",
                "max_groups":8,
                "max_partial_matches_per_group":8,
                "allow_event_reuse":false,
                "stages":[{
                    "name":"credential-access",
                    "event_kind":"credential_access",
                    "minimum_severity":"low"
                }]
            }"#,
            &RuleLimits::default(),
        )
        .unwrap_or_else(|error| panic!("rule: {error}"));
        let config = ProductionActiveDefenseHostConfig {
            durability: SecurityDurability::persistent(),
            security_state_authority,
            indexed_evidence_store,
            signer,
            alert_outbox,
            blast_radius: Arc::new(ReadyBlastRadius),
            scheduler_health,
            response_policy_planner: Arc::new(ReadyPlanner),
            response_coordinator: Arc::new(FailClosedResponseCoordinator),
            clock,
            active_defense: ProductionActiveDefenseConfig {
                scheduler: ProductionResponseSchedulerConfig {
                    tenant_id: tenant_id.clone(),
                    lease_owner_id: LeaseOwnerId::new("trust-runtime-worker")
                        .unwrap_or_else(|error| panic!("lease owner: {error}")),
                    scheduler_policy: SchedulerPolicy {
                        lease_duration_ms: 30_000,
                        base_backoff_ms: 10,
                        max_backoff_ms: 100,
                        operator_page_threshold_ms: 1_000,
                        max_claims: 8,
                    },
                    renewal_margin_ms: 1_000,
                },
                correlation_policy: CorrelationPolicy::new(1_000, 128, 2, false)
                    .unwrap_or_else(|error| panic!("correlation policy: {error}")),
                rules: vec![rule],
                policy_hashes: Default::default(),
                trusted_event_producers: vec![TrustedSecurityEventProducer {
                    tenant_id,
                    producer_id: ProducerId::new("trust-runtime-producer")
                        .unwrap_or_else(|error| panic!("producer: {error}")),
                    producer_key_id: RecordId::new("trust-runtime-producer-key")
                        .unwrap_or_else(|error| panic!("producer key: {error}")),
                    policy_version: RecordId::new("trust-runtime-policy")
                        .unwrap_or_else(|error| panic!("event policy: {error}")),
                    producer_key: keypair.public_key(),
                }],
                trusted_event_receipt_producers: Vec::new(),
                max_event_age_ms: 60_000,
                max_future_skew_ms: 1_000,
                response_recovery_limits: AttestedFindingResponseRecoveryLimits::new(
                    128, 4_096, 30_000,
                )
                .unwrap_or_else(|error| panic!("response recovery limits: {error}")),
            },
            worker_loop: ProductionResponseWorkerLoopConfig {
                tick_interval: Duration::from_secs(30),
            },
        };
        Self {
            _directory: directory,
            security_path,
            config,
        }
    }

    fn install_active_overlay(&self) {
        let connection = rusqlite::Connection::open(&self.security_path)
            .unwrap_or_else(|error| panic!("open overlay store: {error}"));
        connection
            .execute(
                "INSERT INTO security_overlay_state (tenant_id, target_id, generation, effective_posture_rank, highest_fencing_token) VALUES ('tenant-trust-runtime', 'session:runtime', 1, 3, 1)",
                [],
            )
            .unwrap_or_else(|error| panic!("insert overlay state: {error}"));
        connection
            .execute(
                "INSERT INTO security_effect_contributions (tenant_id, target_id, effect_id, action_id, posture_rank, contribution_hash, expires_at) VALUES ('tenant-trust-runtime', 'session:runtime', 'runtime-effect', 'runtime-action', 3, ?1, 120000)",
                rusqlite::params![vec![7_u8; 32]],
            )
            .unwrap_or_else(|error| panic!("insert overlay contribution: {error}"));
    }

    fn clear_active_overlay(&self) {
        let connection = rusqlite::Connection::open(&self.security_path)
            .unwrap_or_else(|error| panic!("open overlay store: {error}"));
        connection
            .execute("DELETE FROM security_effect_contributions", [])
            .unwrap_or_else(|error| panic!("delete overlay contribution: {error}"));
        connection
            .execute(
                "UPDATE security_overlay_state SET effective_posture_rank = 0",
                [],
            )
            .unwrap_or_else(|error| panic!("clear overlay posture: {error}"));
    }
}

#[test]
fn active_defense_runtime_selection_is_explicit() {
    let _serve_entrypoint: fn(
        super::super::super::TrustServiceConfig,
        ProductionActiveDefenseHostConfig,
    ) -> Result<(), crate::CliError> = super::super::super::serve_with_active_defense;
    assert!(matches!(
        TrustControlActiveDefenseRuntimeConfig::Disabled,
        TrustControlActiveDefenseRuntimeConfig::Disabled
    ));
    assert!(!TrustControlActiveDefenseRuntime::disabled().is_enabled());
}

#[tokio::test]
async fn enabled_runtime_owns_the_exact_published_service_and_one_worker() {
    let fixture = RuntimeFixture::new();
    let registry = Arc::new(ActiveDefenseServiceRegistry::default());
    let mut runtime = TrustControlActiveDefenseRuntime::start_with_registry(
        Arc::clone(&registry),
        TrustControlActiveDefenseRuntimeConfig::Enabled(Box::new(fixture.config.clone())),
    )
    .await
    .unwrap_or_else(|error| panic!("start runtime: {error}"));
    let published = runtime
        .published_services()
        .unwrap_or_else(|| panic!("published service missing"));
    let owned = runtime
        .owned_services()
        .unwrap_or_else(|| panic!("owned service missing"));
    assert!(Arc::ptr_eq(&published, &owned));
    assert!(matches!(
        runtime
            .service()
            .worker_health()
            .unwrap_or_else(|| panic!("worker health missing"))
            .lifecycle,
        ResponseWorkerLifecycle::Running | ResponseWorkerLifecycle::Ready
    ));

    assert!(TrustControlActiveDefenseRuntime::start_with_registry(
        Arc::clone(&registry),
        TrustControlActiveDefenseRuntimeConfig::Enabled(Box::new(fixture.config.clone())),
    )
    .await
    .is_err());
    let still_published = runtime
        .published_services()
        .unwrap_or_else(|| panic!("published service was replaced"));
    assert!(Arc::ptr_eq(&still_published, &owned));

    runtime
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown runtime: {error}"));
    assert!(registry.snapshot().is_none());
}

#[tokio::test]
async fn runtime_refuses_unpublish_until_durable_contributions_are_clear() {
    let fixture = RuntimeFixture::new();
    let registry = Arc::new(ActiveDefenseServiceRegistry::default());
    let mut runtime = TrustControlActiveDefenseRuntime::start_with_registry(
        Arc::clone(&registry),
        TrustControlActiveDefenseRuntimeConfig::Enabled(Box::new(fixture.config.clone())),
    )
    .await
    .unwrap_or_else(|error| panic!("start runtime: {error}"));
    fixture.install_active_overlay();

    let error = match runtime.shutdown().await {
        Ok(()) => panic!("active overlay unexpectedly allowed unpublish"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("active overlay contributions"));
    assert!(registry.snapshot().is_some());
    assert_ne!(
        runtime
            .service()
            .worker_health()
            .unwrap_or_else(|| panic!("worker health missing"))
            .lifecycle,
        ResponseWorkerLifecycle::Stopped
    );

    fixture.clear_active_overlay();
    runtime
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown after lift: {error}"));
    assert!(registry.snapshot().is_none());
}
