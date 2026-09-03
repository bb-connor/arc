use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::security::adapters::effect_port::{
    session_containment_target, session_overlay_version_hash, ActiveResponseEffectPort,
};
use crate::security::event_consumer::{
    AttestedFindingAdmissionArtifacts, AttestedFindingDispatchCommittedResume,
    AttestedFindingPreDispatchReconstruction, AttestedFindingResponseCompletionProof,
    AttestedFindingResponseCoordinator, PreparedAttestedFindingResponse,
    ReservedAttestedFindingResponsePlan,
};
use crate::security::{
    ActiveDefenseServiceRegistry, ActiveDefenseServices, AlertOutboxConfig,
    AttestedFindingResponsePolicyPlanner, AttestedFindingResponseRecoveryLimits,
    DurableActiveResponseExecutor, NativeSecurityReceiptSink, ProductionActiveDefenseConfig,
    ProductionActiveDefenseHost, ProductionActiveDefenseHostConfig,
    ProductionResponseSchedulerConfig, ProductionResponseWorkerLoopConfig,
    ProductionSecurityStateAuthority, ResponseWorkerLifecycle, SecurityDurability,
    SqliteSiemOutbox, TrustedSecurityEventProducer,
};
use chio_core::{Ed25519Backend, Keypair, SigningBackend};
use chio_kernel::{ActiveResponseExecutorAuthorityIdentity, IndexedSecurityEvidenceStore};
use chio_quarantine::{
    build_response_plan, decode_response_record, CorrelationPolicy, RuleLimits, SchedulerPolicy,
    TemporalRule,
};
use chio_security_kernel::SecurityClock;
use chio_security_types::ports::{
    containment_session_target, ActionId, BlastRadiusFenceAcquisition, BlastRadiusPort,
    BlastRadiusRequest, BlastRadiusResult, CanonicalBody, Digest32, EventId, LeaseOwnerId,
    LineageFence, LineageFenceRelease, LineageFenceRequest, OpaqueReceiptRef, PortError,
    PortErrorKind, PortResult, PreparedActiveResponseDispatchBinding, ProducerId, RecordId,
    ResponsePlanKey, ResponseStore, SessionId, TenantId, UnverifiedSecurityEvent,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec,
    ResponsePlanInput, ResponseState, ResponseTarget,
};
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::{SqliteReceiptStore, SqliteSecurityStateStore};

const HOST_LIFECYCLE_TEST_TIMEOUT: Duration = Duration::from_secs(30);

struct NoopAlertBackend;

impl AlertBackend for NoopAlertBackend {
    fn name(&self) -> &str {
        "active-defense-host-test"
    }

    fn dispatch<'a>(
        &'a self,
        _: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExportError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

struct FixedClock {
    now_unix_ms: AtomicU64,
    panic_once: AtomicBool,
    block_once: AtomicBool,
    block_worker_once: AtomicBool,
    read_blocked: AtomicBool,
    release_blocked_read: AtomicBool,
}

impl FixedClock {
    fn new(now_unix_ms: u64) -> Self {
        Self {
            now_unix_ms: AtomicU64::new(now_unix_ms),
            panic_once: AtomicBool::new(false),
            block_once: AtomicBool::new(false),
            block_worker_once: AtomicBool::new(false),
            read_blocked: AtomicBool::new(false),
            release_blocked_read: AtomicBool::new(false),
        }
    }

    fn set(&self, now_unix_ms: u64) {
        self.now_unix_ms.store(now_unix_ms, Ordering::Release);
    }

    fn panic_on_next_read(&self) {
        self.panic_once.store(true, Ordering::Release);
    }

    fn block_next_read(&self) {
        self.read_blocked.store(false, Ordering::Release);
        self.release_blocked_read.store(false, Ordering::Release);
        self.block_once.store(true, Ordering::Release);
    }

    fn block_next_worker_read(&self) {
        self.read_blocked.store(false, Ordering::Release);
        self.release_blocked_read.store(false, Ordering::Release);
        self.block_worker_once.store(true, Ordering::Release);
    }

    fn read_is_blocked(&self) -> bool {
        self.read_blocked.load(Ordering::Acquire)
    }

    fn release_read(&self) {
        self.release_blocked_read.store(true, Ordering::Release);
    }

    fn read_now_unix_ms(&self) -> PortResult<u64> {
        if self.panic_once.swap(false, Ordering::AcqRel) {
            panic!("controlled active-defense worker crash");
        }
        let worker_read = std::thread::current()
            .name()
            .is_some_and(|name| name == "chio-response-worker");
        if self.block_once.swap(false, Ordering::AcqRel)
            || (worker_read && self.block_worker_once.swap(false, Ordering::AcqRel))
        {
            self.read_blocked.store(true, Ordering::Release);
            while !self.release_blocked_read.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            self.read_blocked.store(false, Ordering::Release);
        }
        Ok(self.now_unix_ms.load(Ordering::Acquire))
    }
}

impl SecurityClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        self.read_now_unix_ms()
    }
}

impl chio_store_sqlite::security_state::SecurityStateClock for FixedClock {
    fn now_unix_ms(&self) -> PortResult<u64> {
        self.read_now_unix_ms()
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

struct FailClosedResponseCoordinator {
    ready: AtomicBool,
}

impl FailClosedResponseCoordinator {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(true),
        }
    }

    fn fail_readiness(&self) {
        self.ready.store(false, Ordering::Release);
    }
}

impl AttestedFindingResponseCoordinator for FailClosedResponseCoordinator {
    fn ensure_configured(&self) -> PortResult<()> {
        Ok(())
    }

    fn ensure_ready(&self) -> PortResult<()> {
        if self.ready.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(PortError::unavailable())
        }
    }

    fn recover_committed(
        &self,
        _: &chio_security_types::ResponsePlan,
        _: &RecordId,
    ) -> PortResult<Option<AttestedFindingResponseCompletionProof>> {
        Ok(None)
    }

    fn resume_dispatch_committed(
        &self,
        _: &chio_security_types::ResponsePlan,
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
        _: &chio_security_types::ResponsePlan,
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

struct HostFixture {
    _directory: tempfile::TempDir,
    security_path: std::path::PathBuf,
    security_store: Arc<SqliteSecurityStateStore>,
    registry: Arc<ActiveDefenseServiceRegistry>,
    config: ProductionActiveDefenseHostConfig,
    clock: Arc<FixedClock>,
    response_coordinator: Arc<FailClosedResponseCoordinator>,
}

impl HostFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let security_path = directory.path().join("security-state.sqlite");
        let clock = Arc::new(FixedClock::new(50_000));
        let store_clock: Arc<dyn chio_store_sqlite::security_state::SecurityStateClock> =
            clock.clone();
        let security_state_authority = ProductionSecurityStateAuthority::open_with_trusted_clock(
            &security_path,
            Arc::clone(&store_clock),
        )
        .unwrap_or_else(|error| panic!("security state authority: {error}"));
        let security_store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(&security_path, store_clock)
                .unwrap_or_else(|error| panic!("security state inspection store: {error:?}")),
        );
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
        let signer_keypair = Keypair::from_seed(&[91_u8; 32]);
        let signer: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(signer_keypair.clone()));
        let indexed_evidence_store: Arc<dyn IndexedSecurityEvidenceStore> = receipt_store;
        let alert_health = Arc::clone(&alert_outbox);
        let tenant_id = TenantId::new("tenant-host-lifecycle")
            .unwrap_or_else(|error| panic!("tenant: {error}"));
        let rule = TemporalRule::parse_json(
            br#"{
                "rule_id":"host-lifecycle-rule",
                "policy_version":"host-lifecycle-policy",
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
        .unwrap_or_else(|error| panic!("temporal rule: {error}"));
        let security_clock: Arc<dyn SecurityClock> = clock.clone();
        let response_coordinator = Arc::new(FailClosedResponseCoordinator::new());
        let config = ProductionActiveDefenseHostConfig {
            durability: SecurityDurability::persistent(),
            security_state_authority,
            indexed_evidence_store,
            signer,
            alert_outbox,
            blast_radius: Arc::new(ReadyBlastRadius),
            scheduler_health: alert_health,
            response_policy_planner: Arc::new(ReadyPlanner),
            response_coordinator: response_coordinator.clone(),
            clock: security_clock,
            active_defense: ProductionActiveDefenseConfig {
                scheduler: ProductionResponseSchedulerConfig {
                    tenant_id: tenant_id.clone(),
                    lease_owner_id: LeaseOwnerId::new("host-lifecycle-worker")
                        .unwrap_or_else(|error| panic!("worker owner: {error}")),
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
                    producer_id: ProducerId::new("host-lifecycle-producer")
                        .unwrap_or_else(|error| panic!("producer: {error}")),
                    producer_key_id: RecordId::new("host-lifecycle-producer-key")
                        .unwrap_or_else(|error| panic!("producer key id: {error}")),
                    policy_version: RecordId::new("host-lifecycle-policy")
                        .unwrap_or_else(|error| panic!("event policy: {error}")),
                    producer_key: signer_keypair.public_key(),
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
                tick_interval: Duration::from_millis(10),
            },
        };
        Self {
            _directory: directory,
            security_path,
            security_store,
            registry: Arc::new(ActiveDefenseServiceRegistry::default()),
            config,
            clock,
            response_coordinator,
        }
    }

    fn install_ttl_containment_plan(&self) -> u64 {
        let created_at_unix_ms = 50_000;
        let ttl_ms = 1_000;
        let expires_at_unix_ms = 51_000;
        let capability_expires_at_unix_ms = 120_000;
        self.clock.set(created_at_unix_ms);
        let tenant_id = TenantId::new("tenant-host-lifecycle")
            .unwrap_or_else(|error| panic!("tenant: {error}"));
        let session_id = SessionId::new("session-host-lifecycle")
            .unwrap_or_else(|error| panic!("session: {error}"));
        let executor_identity =
            ActiveResponseExecutorAuthorityIdentity::new(self.config.signer.public_key(), 1)
                .unwrap_or_else(|error| panic!("executor identity: {error}"));
        let target = session_containment_target(&tenant_id, &session_id)
            .unwrap_or_else(|error| panic!("containment target: {error}"));
        let observed_base_version_hash =
            session_overlay_version_hash(self.security_store.as_ref(), &target)
                .unwrap_or_else(|error| panic!("containment base version: {error}"));
        let canonical_contribution = CanonicalBody::new(b"{\"posture_rank\":3}".to_vec())
            .unwrap_or_else(|error| panic!("containment contribution: {error}"));
        let contribution_hash =
            Digest32::new(*chio_core::sha256(canonical_contribution.as_bytes()).as_bytes());
        let authorization_capability_hash = Digest32::new([4_u8; 32]);
        let plan = build_response_plan(ResponsePlanInput {
            action_id: ActionId::new("host-lifecycle-ttl-action")
                .unwrap_or_else(|error| panic!("action id: {error}")),
            trigger_finding_id: RecordId::new("host-lifecycle-ttl-finding")
                .unwrap_or_else(|error| panic!("finding id: {error}")),
            trigger_finding_hash: Digest32::new([2_u8; 32]),
            trigger_finding_receipt_id: OpaqueReceiptRef::new("host-lifecycle-ttl-receipt")
                .unwrap_or_else(|error| panic!("finding receipt: {error}")),
            tenant_id,
            policy_version: RecordId::new("host-lifecycle-policy")
                .unwrap_or_else(|error| panic!("policy version: {error}")),
            policy_hash: Digest32::new([3_u8; 32]),
            affected_ids: vec![RecordId::new(session_id.as_str())
                .unwrap_or_else(|error| panic!("affected session: {error}"))],
            effects: vec![ResponseEffectSpec {
                kind: ResponseEffectKind::SuspendSession,
                target: ResponseTarget::Session { session_id },
                canonical_contribution,
                contribution_hash,
                observed_base_version_hash,
            }],
            ttl_ms,
            created_at_unix_ms,
            operator_capability: OperatorCapabilityBinding {
                capability_id: RecordId::new("host-lifecycle-ttl-capability")
                    .unwrap_or_else(|error| panic!("capability id: {error}")),
                capability_digest: authorization_capability_hash,
                expires_at_unix_ms: capability_expires_at_unix_ms,
                executor_subject: RecordId::new(executor_identity.subject().to_hex())
                    .unwrap_or_else(|error| panic!("executor subject: {error}")),
            },
            approval_requirement: ResponseApprovalRequirement::Automatic,
            submitter: RecordId::new("host-lifecycle-ttl-submitter")
                .unwrap_or_else(|error| panic!("submitter: {error}")),
            reason_hash: Digest32::new([5_u8; 32]),
        })
        .unwrap_or_else(|error| panic!("build TTL response plan: {error}"));
        let plan_key = ResponsePlanKey {
            tenant_id: plan.tenant_id.clone(),
            action_id: plan.action_id.clone(),
        };
        let effects = Arc::new(
            ActiveResponseEffectPort::production(
                Arc::clone(&self.security_store),
                Arc::clone(&self.config.alert_outbox),
                Arc::clone(&self.config.blast_radius),
            )
            .unwrap_or_else(|error| panic!("construct TTL response effects: {error}")),
        );
        let receipts = Arc::new(NativeSecurityReceiptSink::new(
            Arc::clone(&self.config.indexed_evidence_store),
            Arc::clone(&self.config.signer),
        ));
        let executor = DurableActiveResponseExecutor::new(
            executor_identity,
            LeaseOwnerId::new("host-lifecycle-executor")
                .unwrap_or_else(|error| panic!("executor lease owner: {error}")),
            Arc::clone(&self.security_store),
            effects,
            receipts,
            Arc::clone(&self.config.alert_outbox),
            self.clock.clone(),
            500,
        )
        .unwrap_or_else(|error| panic!("construct durable TTL response executor: {error}"));
        executor
            .execute_automatic_for_test(
                plan,
                Digest32::new([6_u8; 32]),
                Digest32::new([7_u8; 32]),
                created_at_unix_ms,
            )
            .unwrap_or_else(|error| panic!("activate TTL response dispatch: {error}"));
        let stored = self
            .security_store
            .load_plan(&plan_key)
            .unwrap_or_else(|error| panic!("load active TTL response: {error}"))
            .unwrap_or_else(|| panic!("active TTL response is missing"));
        let stored = decode_response_record(&stored)
            .unwrap_or_else(|error| panic!("decode active TTL response: {error}"));
        assert_eq!(stored.state, ResponseState::Active);
        assert_eq!(stored.plan.expires_at_unix_ms, expires_at_unix_ms);
        assert_eq!(stored.due_at_unix_ms, Some(expires_at_unix_ms));
        assert!(self.has_active_overlay_contributions());
        self.clock.set(created_at_unix_ms.saturating_add(2));
        expires_at_unix_ms
    }

    fn has_active_overlay_contributions(&self) -> bool {
        self.security_store
            .active_defense_overlay_inventory()
            .unwrap_or_else(|error| panic!("active-defense inventory: {error}"))
            .has_active_contributions()
    }

    fn install_containment_row(&self) {
        let tenant_id = TenantId::new("tenant-host-lifecycle")
            .unwrap_or_else(|error| panic!("tenant: {error}"));
        let target = containment_session_target(
            &tenant_id,
            &SessionId::new("session-host-lifecycle")
                .unwrap_or_else(|error| panic!("session: {error}")),
        )
        .unwrap_or_else(|error| panic!("target: {error}"));
        let connection = rusqlite::Connection::open(&self.security_path)
            .unwrap_or_else(|error| panic!("open containment seed connection: {error}"));
        connection
            .execute(
                "INSERT INTO security_overlay_state (tenant_id, target_id, generation, effective_posture_rank, highest_fencing_token) VALUES (?1, ?2, 1, 3, 1)",
                rusqlite::params![tenant_id.as_str(), target.id.as_str()],
            )
            .unwrap_or_else(|error| panic!("insert containment state: {error}"));
        connection
            .execute(
                "INSERT INTO security_effect_contributions (tenant_id, target_id, effect_id, action_id, posture_rank, contribution_hash, expires_at) VALUES (?1, ?2, 'host-lifecycle-effect', 'host-lifecycle-action', 3, ?3, 120000)",
                rusqlite::params![tenant_id.as_str(), target.id.as_str(), vec![7_u8; 32]],
            )
            .unwrap_or_else(|error| panic!("insert containment contribution: {error}"));
    }

    fn security_event_count(&self) -> u64 {
        let connection = rusqlite::Connection::open(&self.security_path)
            .unwrap_or_else(|error| panic!("open event count connection: {error}"));
        let count = connection
            .query_row("SELECT COUNT(*) FROM security_event_ids", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or_else(|error| panic!("count security events: {error}"));
        u64::try_from(count).unwrap_or_else(|error| panic!("security event count: {error}"))
    }

    fn declassification_lifecycle(&self) -> (i64, i64, i64) {
        let connection = rusqlite::Connection::open(&self.security_path)
            .unwrap_or_else(|error| panic!("open lifecycle connection: {error}"));
        connection
            .query_row(
                "SELECT reconciliation_active, live_dispatch_sealed, compaction_active FROM security_declassification_lifecycle WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap_or_else(|error| panic!("read declassification lifecycle: {error}"))
    }

    fn clear_containment_row(&self) {
        let connection = rusqlite::Connection::open(&self.security_path)
            .unwrap_or_else(|error| panic!("open containment cleanup connection: {error}"));
        connection
            .execute("DELETE FROM security_effect_contributions", [])
            .unwrap_or_else(|error| panic!("delete containment contribution: {error}"));
        connection
            .execute(
                "UPDATE security_overlay_state SET effective_posture_rank = 0",
                [],
            )
            .unwrap_or_else(|error| panic!("clear containment posture: {error}"));
    }
}

fn unverified_event(event_id: &str) -> UnverifiedSecurityEvent {
    let canonical_body = CanonicalBody::new(b"{}".to_vec())
        .unwrap_or_else(|error| panic!("canonical event body: {error}"));
    UnverifiedSecurityEvent {
        tenant_id: TenantId::new("tenant-host-lifecycle")
            .unwrap_or_else(|error| panic!("tenant: {error}")),
        event_id: EventId::new(event_id).unwrap_or_else(|error| panic!("event id: {error}")),
        producer_id: ProducerId::new("host-lifecycle-producer")
            .unwrap_or_else(|error| panic!("producer id: {error}")),
        event_time_unix_ms: 50_000,
        received_at_unix_ms: 50_000,
        canonical_body,
        body_hash: Digest32::new([1_u8; 32]),
        source_evidence: CanonicalBody::new(b"{}".to_vec())
            .unwrap_or_else(|error| panic!("source evidence: {error}")),
    }
}

#[tokio::test]
async fn host_publishes_exact_instance_rejects_duplicate_and_shuts_down_in_order() {
    let fixture = HostFixture::new();
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    let installed = fixture
        .registry
        .snapshot()
        .unwrap_or_else(|| panic!("published services missing"));
    let exact: Arc<dyn ActiveDefenseServices> = host.orchestrator().clone();
    assert!(Arc::ptr_eq(&installed, &exact));
    assert!(matches!(
        host.worker_health().lifecycle,
        ResponseWorkerLifecycle::Running | ResponseWorkerLifecycle::Ready
    ));
    host.ensure_ready()
        .unwrap_or_else(|error| panic!("started host is not ready: {error}"));
    assert_eq!(fixture.declassification_lifecycle(), (0, 1, 0));

    assert!(ProductionActiveDefenseHost::start(
        Arc::clone(&fixture.registry),
        fixture.config.clone(),
    )
    .await
    .is_err());
    let still_installed = fixture
        .registry
        .snapshot()
        .unwrap_or_else(|| panic!("original services were replaced"));
    assert!(Arc::ptr_eq(&still_installed, &exact));

    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));
    assert_eq!(
        host.worker_health().lifecycle,
        ResponseWorkerLifecycle::Stopped
    );
    assert!(host.ensure_ready().is_err());
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn wedged_synchronous_worker_tick_fails_full_host_readiness() {
    let fixture = HostFixture::new();
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    host.orchestrator()
        .worker()
        .set_progress_deadline_for_test(Duration::from_millis(30));
    fixture.clock.block_next_read();
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while !fixture.clock.read_is_blocked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("worker tick did not wedge"));
    tokio::time::sleep(Duration::from_millis(40)).await;

    assert_eq!(
        host.worker_health().lifecycle,
        ResponseWorkerLifecycle::Running
    );
    assert!(host.ensure_ready().is_err());

    fixture.clock.release_read();
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown wedged host: {error}"));
}

#[tokio::test]
async fn consumer_dependency_failure_fails_full_host_readiness_with_live_worker() {
    let fixture = HostFixture::new();
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    fixture.response_coordinator.fail_readiness();

    assert!(matches!(
        host.worker_health().lifecycle,
        ResponseWorkerLifecycle::Running | ResponseWorkerLifecycle::Ready
    ));
    assert!(host.ensure_ready().is_err());

    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown dependency-failed host: {error}"));
}

#[tokio::test]
async fn cloned_authority_rejects_a_second_live_host_across_registries() {
    let fixture = HostFixture::new();
    let second_registry = Arc::new(ActiveDefenseServiceRegistry::default());
    let mut first =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start first host: {error}"));

    assert!(ProductionActiveDefenseHost::start(
        Arc::clone(&second_registry),
        fixture.config.clone(),
    )
    .await
    .is_err());
    first
        .ensure_ready()
        .unwrap_or_else(|error| panic!("first host lost readiness: {error}"));
    assert!(fixture.registry.snapshot().is_some());
    assert!(second_registry.snapshot().is_none());

    first
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown first host: {error}"));
    drop(first);

    let mut restarted =
        ProductionActiveDefenseHost::start(Arc::clone(&second_registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host after claim release: {error}"));
    restarted
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown restarted host: {error}"));
}

#[tokio::test]
async fn clean_shutdown_allows_restart_against_the_same_durable_stores() {
    let fixture = HostFixture::new();
    let mut first =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start first host: {error}"));
    first
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown first host: {error}"));
    drop(first);

    let mut restarted =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("restart host: {error}"));
    assert!(fixture.registry.snapshot().is_some());
    restarted
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown restarted host: {error}"));
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn closed_host_rejects_cloned_orchestrator_consumption_without_mutation() {
    let fixture = HostFixture::new();
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    let cloned_orchestrator = Arc::clone(host.orchestrator());
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown host: {error}"));
    let before = fixture.security_event_count();
    let event = unverified_event("closed-host-event");

    let error = match cloned_orchestrator.consume(&event) {
        Ok(_) => panic!("closed orchestrator accepted event consumption"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert_eq!(fixture.security_event_count(), before);
}

#[tokio::test]
async fn worker_start_failure_releases_the_registry_reservation() {
    let fixture = HostFixture::new();
    let mut invalid = fixture.config.clone();
    invalid.worker_loop.tick_interval = Duration::ZERO;

    assert!(
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), invalid)
            .await
            .is_err()
    );
    assert!(fixture.registry.snapshot().is_none());

    let mut recovered =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start after rollback: {error}"));
    recovered
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown recovered host: {error}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_startup_after_reservation_reclaims_exact_precommit_ownership() {
    let fixture = HostFixture::new();
    let (reservation_reached, release_reservation) =
        fixture.registry.pause_next_reservation_for_test();
    let registry = Arc::clone(&fixture.registry);
    let config = fixture.config.clone();
    let startup =
        tokio::spawn(async move { ProductionActiveDefenseHost::start(registry, config).await });
    tokio::task::spawn_blocking(move || {
        reservation_reached.wait();
    })
    .await
    .unwrap_or_else(|error| panic!("wait for reservation pause: {error}"));

    startup.abort();
    tokio::task::spawn_blocking(move || {
        release_reservation.wait();
    })
    .await
    .unwrap_or_else(|error| panic!("release reservation pause: {error}"));
    assert!(startup.await.is_err());

    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        fixture.registry.wait_until_vacant(),
    )
    .await
    .unwrap_or_else(|_| panic!("cancelled startup retained its exact reservation"))
    .unwrap_or_else(|error| panic!("wait for reservation cleanup: {error}"));
    let mut recovered =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("restart after precommit cancellation: {error}"));
    recovered
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown recovered host: {error}"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_postcommit_readiness_transfers_a_complete_host_to_teardown() {
    let fixture = HostFixture::new();
    fixture.clock.block_next_worker_read();
    let registry = Arc::clone(&fixture.registry);
    let config = fixture.config.clone();
    let startup =
        tokio::spawn(async move { ProductionActiveDefenseHost::start(registry, config).await });
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while !fixture.clock.read_is_blocked() || fixture.registry.snapshot().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("startup did not reach postcommit publication readiness"));

    startup.abort();
    fixture.clock.release_read();
    assert!(startup.await.is_err());

    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        fixture.registry.wait_until_vacant(),
    )
    .await
    .unwrap_or_else(|_| panic!("postcommit cancellation did not unpublish exact services"))
    .unwrap_or_else(|error| panic!("wait for postcommit teardown: {error}"));
    let mut recovered =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("restart after postcommit cancellation: {error}"));
    recovered
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown recovered host: {error}"));
}

#[tokio::test]
async fn production_host_refuses_ephemeral_authorities_before_publication() {
    use crate::security::AuthorityDurability;

    let fixture = HostFixture::new();
    let mut config = fixture.config.clone();
    config.durability = SecurityDurability::new(
        AuthorityDurability::Ephemeral,
        AuthorityDurability::FilesystemBacked,
        AuthorityDurability::FilesystemBacked,
        AuthorityDurability::FilesystemBacked,
        AuthorityDurability::FilesystemBacked,
        AuthorityDurability::FilesystemBacked,
    );

    assert!(
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), config)
            .await
            .is_err()
    );
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn production_host_rejects_future_skew_that_exceeds_bounded_lateness() {
    let fixture = HostFixture::new();
    let mut config = fixture.config.clone();
    config.active_defense.max_future_skew_ms = 1_001;

    assert!(
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), config)
            .await
            .is_err()
    );
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn production_host_rejects_a_trusted_producer_without_a_rule_policy() {
    let fixture = HostFixture::new();
    let mut config = fixture.config.clone();
    config.active_defense.trusted_event_producers[0].policy_version =
        RecordId::new("host-lifecycle-unmatched-policy")
            .unwrap_or_else(|error| panic!("event policy: {error}"));

    assert!(
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), config)
            .await
            .is_err()
    );
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn production_host_requires_the_exact_security_store_finding_batch_ledger() {
    let fixture = HostFixture::new();
    let connection = rusqlite::Connection::open(&fixture.security_path)
        .unwrap_or_else(|error| panic!("open finding ledger store: {error}"));
    connection
        .execute_batch(
            r#"
            DROP TABLE security_attested_finding_batch_items;
            "#,
        )
        .unwrap_or_else(|error| panic!("remove finding ledger: {error}"));
    drop(connection);

    let error = match ProductionActiveDefenseHost::start(
        Arc::clone(&fixture.registry),
        fixture.config.clone(),
    )
    .await
    {
        Ok(_) => panic!("host started without its durable finding batch ledger"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("active-defense service port failed"));
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn shutdown_refuses_to_unpublish_while_a_durable_overlay_remains() {
    let fixture = HostFixture::new();
    fixture.install_containment_row();
    let mut host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));

    let error = match host.shutdown().await {
        Ok(()) => panic!("active containment unexpectedly allowed unpublish"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("active overlay contributions"));
    assert!(fixture.registry.snapshot().is_some());
    assert_ne!(
        host.worker_health().lifecycle,
        ResponseWorkerLifecycle::Stopped
    );

    fixture.clear_containment_row();
    host.shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown after lift: {error}"));
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn dropping_a_host_reclaims_registry_ownership_and_allows_restart() {
    let fixture = HostFixture::new();
    let host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    let worker = Arc::clone(host.orchestrator().worker());
    drop(host);

    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        worker.wait_for_shutdown_completion(),
    )
    .await
    .unwrap_or_else(|_| panic!("dropped host worker did not stop"));
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        fixture.registry.wait_until_vacant(),
    )
    .await
    .unwrap_or_else(|_| panic!("dropped host registry was not reclaimed"))
    .unwrap_or_else(|error| panic!("wait for registry reclamation: {error}"));
    assert!(fixture.registry.snapshot().is_none());

    let mut restarted =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("restart host after detached teardown: {error}"));
    restarted
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown restarted host: {error}"));
}

#[tokio::test]
async fn dropping_a_host_keeps_the_worker_live_until_a_ttl_overlay_is_lifted() {
    let fixture = HostFixture::new();
    let expires_at_unix_ms = fixture.install_ttl_containment_plan();
    let host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while !fixture.has_active_overlay_contributions() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("TTL overlay was not applied"));
    let worker = Arc::clone(host.orchestrator().worker());

    drop(host);
    assert!(fixture.registry.snapshot().is_some());
    assert_ne!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);

    fixture.clock.set(expires_at_unix_ms.saturating_add(1));
    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        fixture.registry.wait_until_vacant(),
    )
    .await
    .unwrap_or_else(|_| panic!("dropped host did not drain its TTL overlay"))
    .unwrap_or_else(|error| panic!("wait for registry reclamation: {error}"));
    assert!(!fixture.has_active_overlay_contributions());
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Stopped);
}

#[tokio::test]
async fn dropping_after_primary_worker_crash_recovers_and_lifts_a_ttl_overlay() {
    let fixture = HostFixture::new();
    let expires_at_unix_ms = fixture.install_ttl_containment_plan();
    let host =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("start host: {error}"));
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while !fixture.has_active_overlay_contributions() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("TTL overlay was not applied"));
    let primary = Arc::clone(host.orchestrator().worker());
    let published = fixture
        .registry
        .snapshot()
        .unwrap_or_else(|| panic!("published services missing"));
    fixture.clock.panic_on_next_read();
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while primary.health().lifecycle != ResponseWorkerLifecycle::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("primary worker did not crash"));
    let still_published = fixture
        .registry
        .snapshot()
        .unwrap_or_else(|| panic!("crashed services were unpublished"));
    assert!(Arc::ptr_eq(&published, &still_published));
    let before = fixture.security_event_count();
    let error = match host.consume(&unverified_event("crashed-worker-event")) {
        Ok(_) => panic!("crashed worker accepted event consumption"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), PortErrorKind::Unavailable);
    assert_eq!(fixture.security_event_count(), before);

    drop(host);
    assert!(fixture.registry.snapshot().is_some());
    fixture.clock.set(expires_at_unix_ms.saturating_add(1));
    tokio::time::timeout(
        HOST_LIFECYCLE_TEST_TIMEOUT,
        fixture.registry.wait_until_vacant(),
    )
    .await
    .unwrap_or_else(|_| panic!("recovery worker did not lift the TTL overlay"))
    .unwrap_or_else(|error| panic!("wait for registry reclamation: {error}"));
    assert!(!fixture.has_active_overlay_contributions());

    let mut restarted =
        ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), fixture.config.clone())
            .await
            .unwrap_or_else(|error| panic!("restart after crash cleanup: {error}"));
    restarted
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown restarted host: {error}"));
}

#[tokio::test]
async fn awaited_shutdown_waits_for_an_in_flight_ttl_rollback_before_unpublishing() {
    let fixture = HostFixture::new();
    let expires_at_unix_ms = fixture.install_ttl_containment_plan();
    let mut config = fixture.config.clone();
    config.worker_loop.tick_interval = Duration::from_millis(50);
    let mut host = ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), config)
        .await
        .unwrap_or_else(|error| panic!("start host: {error}"));
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while host.worker_health().ticks_completed == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("initial worker tick did not complete"));
    fixture.clock.block_next_read();
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while !fixture.clock.read_is_blocked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("worker tick did not block before TTL rollback"));

    let (shutdown, ()) = tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        tokio::join!(host.shutdown(), async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            fixture.clock.set(expires_at_unix_ms.saturating_add(1));
            fixture.clock.release_read();
            while fixture.has_active_overlay_contributions() {
                tokio::task::yield_now().await;
            }
        })
    })
    .await
    .unwrap_or_else(|_| panic!("awaited shutdown did not recover its in-flight overlay race"));
    shutdown.unwrap_or_else(|error| panic!("awaited shutdown failed: {error}"));
    assert!(!fixture.has_active_overlay_contributions());
    assert!(fixture.registry.snapshot().is_none());
}

#[tokio::test]
async fn cancelling_shutdown_transfers_retained_teardown_to_host_drop() {
    let fixture = HostFixture::new();
    let expires_at_unix_ms = fixture.install_ttl_containment_plan();
    let mut config = fixture.config.clone();
    config.worker_loop.tick_interval = Duration::from_millis(50);
    let mut host = ProductionActiveDefenseHost::start(Arc::clone(&fixture.registry), config)
        .await
        .unwrap_or_else(|error| panic!("start host: {error}"));
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while host.worker_health().ticks_completed == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("initial worker tick did not complete"));
    fixture.clock.block_next_read();
    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while !fixture.clock.read_is_blocked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("worker tick did not block before shutdown"));

    let mut shutdown = Box::pin(host.shutdown());
    tokio::select! {
        result = &mut shutdown => panic!("shutdown completed before cancellation: {result:?}"),
        () = tokio::time::sleep(Duration::from_millis(20)) => {}
    }
    drop(shutdown);
    drop(host);
    fixture.clock.set(expires_at_unix_ms.saturating_add(1));
    fixture.clock.release_read();

    tokio::time::timeout(HOST_LIFECYCLE_TEST_TIMEOUT, async {
        while fixture.has_active_overlay_contributions() || fixture.registry.snapshot().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("cancelled shutdown did not finish detached teardown"));
}
