use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chio_control_plane::security::adapters::effect_port::ActiveResponseEffectPort;
use chio_quarantine::{
    CausalBlastRadiusResolver, ResponseExecutor, ResponseScheduler, SchedulerPolicy,
    SchedulerWorkOutcome,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
use chio_security_types::ports::{
    AlertDeliveryQuery, AlertDeliveryStatus, CausalLineageCommitMetadata, CausalLineageEdge,
    CausalLineageEdgeKind, CausalLineageEdges, CausalLineageFenceRequest, CausalLineageFenceStore,
    CausalLineageNode, CausalLineageNodeKind, CausalLineageNodes, CausalLineageSnapshot,
    CausalLineageSnapshotRequest, CausalLineageStore, LineageFenceStore, ReceiptAppendRequest,
    ResponseDispatchCommitOutcome, ResponseDispatchStore, SchedulerHealthPageRequest,
    SchedulerHealthPort, SecurityAlert, SecurityAlertPort, SecurityReceiptSink, TenantScopedId,
    LINEAGE_FENCE_MAX_LEASE_MS,
};
use chio_security_types::{ResponseEffectProgress, ResponseSnapshot};
use chio_store_sqlite::SqliteSecurityStateStore;

use super::*;

const PLAN_TTL_MS: u64 = 120_000;
const INITIAL_FENCE_MS: u64 = 15_000;
const SCHEDULER_LEASE_MS: u64 = 10_000;
const LAPSED_FENCE_CODE: &str = "response.lineage_fence_lapsed";

struct ManualClock(AtomicU64);

impl ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn set(&self, unix_ms: u64) {
        self.0.store(unix_ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        FixedClock::from_millis(self.now()).read()
    }
}

pub(super) struct StaticLineage(pub(super) CausalLineageSnapshot);

impl CausalLineageStore for StaticLineage {
    fn ensure_causal_lineage_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn load_causal_snapshot(
        &self,
        request: &CausalLineageSnapshotRequest,
    ) -> PortResult<CausalLineageSnapshot> {
        if request.tenant_id != self.0.tenant_id {
            return Err(PortError::invalid_data());
        }
        Ok(self.0.clone())
    }
}

pub(super) struct SqliteFences(pub(super) Arc<SqliteSecurityStateStore>);

impl LineageFenceStore for SqliteFences {
    fn acquire(&self, request: &LineageFenceRequest) -> PortResult<LineageFence> {
        LineageFenceStore::acquire(self.0.as_ref(), request)
    }

    fn query(&self, action: &TenantScopedId) -> PortResult<Option<LineageFence>> {
        LineageFenceStore::query(self.0.as_ref(), action)
    }

    fn renew(&self, renewal: &LineageFenceRenewal) -> PortResult<LineageFence> {
        LineageFenceStore::renew(self.0.as_ref(), renewal)
    }

    fn takeover(&self, takeover: &LineageFenceTakeover) -> PortResult<LineageFence> {
        LineageFenceStore::takeover(self.0.as_ref(), takeover)
    }

    fn release(&self, release: &LineageFenceRelease) -> PortResult<()> {
        LineageFenceStore::release(self.0.as_ref(), release)
    }
}

impl CausalLineageFenceStore for SqliteFences {
    fn ensure_causal_lineage_fences_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn acquire_causal_fence(
        &self,
        request: &CausalLineageFenceRequest,
    ) -> PortResult<LineageFence> {
        LineageFenceStore::acquire(self.0.as_ref(), &request.fence)
    }
}

/// SQLite issuance-freeze authority whose next fence-maintenance write fails
/// before it reaches the database, as a busy or lease-lost transaction does.
pub(super) struct PersistFaultFreezes {
    inner: Arc<SqliteSecurityStateStore>,
    fail_next_maintenance: AtomicBool,
    fail_next_apply: AtomicBool,
}

impl PersistFaultFreezes {
    pub(super) fn new(inner: Arc<SqliteSecurityStateStore>) -> Self {
        Self {
            inner,
            fail_next_maintenance: AtomicBool::new(false),
            fail_next_apply: AtomicBool::new(false),
        }
    }

    fn fail_next_maintenance(&self) {
        self.fail_next_maintenance.store(true, Ordering::SeqCst);
    }

    pub(super) fn fail_next_apply(&self) {
        self.fail_next_apply.store(true, Ordering::SeqCst);
    }
}

impl IssuanceFreezeStore for PersistFaultFreezes {
    fn ensure_issuance_freezes_ready(&self) -> PortResult<()> {
        self.inner.ensure_issuance_freezes_ready()
    }

    fn apply_issuance_freeze(
        &self,
        request: &IssuanceFreezeApplyRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        if self.fail_next_apply.swap(false, Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        self.inner.apply_issuance_freeze(request)
    }

    fn prepare_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeContribution> {
        self.inner.prepare_issuance_freeze_remove(request)
    }

    fn complete_issuance_freeze_remove(
        &self,
        request: &IssuanceFreezeRemoveRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        self.inner.complete_issuance_freeze_remove(request)
    }

    fn load_issuance_freezes(
        &self,
        key: &IssuanceFreezeKey,
    ) -> PortResult<Option<IssuanceFreezeSnapshot>> {
        self.inner.load_issuance_freezes(key)
    }

    fn evaluate_issuance_freeze(
        &self,
        query: &IssuanceFreezeAdmissionQuery,
    ) -> PortResult<IssuanceFreezeAdmissionDecision> {
        self.inner.evaluate_issuance_freeze(query)
    }

    fn load_issuance_freeze_operation(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<IssuanceFreezeOperationStatus> {
        self.inner.load_issuance_freeze_operation(query)
    }

    fn load_pending_issuance_freeze_release(
        &self,
        key: &IssuanceFreezeKey,
        action_id: &ActionId,
        effect_id: &EffectId,
    ) -> PortResult<Option<IssuanceFreezePendingRelease>> {
        self.inner
            .load_pending_issuance_freeze_release(key, action_id, effect_id)
    }

    fn load_completed_issuance_freeze_release(
        &self,
        key: &IssuanceFreezeKey,
        action_id: &ActionId,
        effect_id: &EffectId,
        plan_hash: Digest32,
    ) -> PortResult<Option<chio_security_types::ports::IssuanceFreezeCommand>> {
        self.inner
            .load_completed_issuance_freeze_release(key, action_id, effect_id, plan_hash)
    }

    fn maintain_issuance_freeze_fence(
        &self,
        request: &IssuanceFreezeFenceMaintenanceRequest,
    ) -> PortResult<IssuanceFreezeSnapshot> {
        if self.fail_next_maintenance.swap(false, Ordering::SeqCst) {
            return Err(PortError::unavailable());
        }
        self.inner.maintain_issuance_freeze_fence(request)
    }
}

struct AcceptedReceipts;

impl SecurityReceiptSink for AcceptedReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        Ok(request.evidence_id.clone())
    }
}

struct DeliveredAlerts;

impl SecurityAlertPort for DeliveredAlerts {
    fn ensure_alerts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
        Ok(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: alert.occurred_at_unix_ms.max(1),
        })
    }

    fn load_delivery(&self, _: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>> {
        Ok(None)
    }
}

struct DeliveredHealth;

impl SchedulerHealthPort for DeliveredHealth {
    fn ensure_scheduler_health_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn page_once(&self, request: &SchedulerHealthPageRequest) -> PortResult<AlertDeliveryStatus> {
        Ok(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: request.occurred_at_unix_ms.max(1),
        })
    }

    fn load_delivery(&self, _: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>> {
        Ok(None)
    }
}

type LapseExecutor = ResponseExecutor<
    SqliteSecurityStateStore,
    ActiveResponseEffectPort,
    AcceptedReceipts,
    DeliveredAlerts,
>;
type LapseScheduler = ResponseScheduler<SqliteSecurityStateStore, LapseExecutor, DeliveredHealth>;

pub(super) fn worker(value: &str) -> LeaseOwnerId {
    LeaseOwnerId::new(value).unwrap_or_else(|error| panic!("lease owner: {error}"))
}

pub(super) fn lineage_snapshot() -> CausalLineageSnapshot {
    let node = |id: &str| CausalLineageNode {
        tenant_id: tenant(),
        node_id: record(id),
        kind: CausalLineageNodeKind::Capability,
    };
    CausalLineageSnapshot {
        tenant_id: tenant(),
        metadata: CausalLineageCommitMetadata {
            source_lineage_version: 9,
            observed_commit_index: 21,
            authoritative_commit_index: 21,
            completeness_watermark: Some(21),
        },
        nodes: CausalLineageNodes::new(vec![node("capability-root"), node("capability-child")])
            .unwrap_or_else(|error| panic!("lineage nodes: {error}")),
        edges: CausalLineageEdges::new(vec![CausalLineageEdge {
            tenant_id: tenant(),
            parent_id: record("capability-root"),
            child_id: record("capability-child"),
            kind: CausalLineageEdgeKind::CapabilityDelegation,
        }])
        .unwrap_or_else(|error| panic!("lineage edges: {error}")),
        depth_truncated: false,
        nodes_truncated: false,
        edges_truncated: false,
    }
}

/// One live `FreezeIssuance` response over the real SQLite security store, the
/// real causal fence resolver, the real response executor and scheduler, and a
/// test-controlled trusted clock.
struct FenceLapseHarness {
    _directory: tempfile::TempDir,
    clock: Arc<ManualClock>,
    store: Arc<SqliteSecurityStateStore>,
    freezes: Arc<PersistFaultFreezes>,
    blast: Arc<dyn BlastRadiusPort>,
    plan: ResponsePlan,
    initial_work: ScheduledWork,
    claims: AtomicU64,
}

impl FenceLapseHarness {
    fn new() -> Self {
        let directory =
            chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let created_at_unix_ms = now_unix_ms();
        let clock = Arc::new(ManualClock(AtomicU64::new(created_at_unix_ms)));
        let trusted_clock: Arc<dyn Clock> = clock.clone();
        let store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                directory.path().join("fence-lapse.db"),
                trusted_clock,
            )
            .unwrap_or_else(|error| panic!("open SQLite security store: {error}")),
        );
        let resolver = Arc::new(CausalBlastRadiusResolver::new(
            Arc::new(StaticLineage(lineage_snapshot())),
            Arc::new(SqliteFences(Arc::clone(&store))),
        ));
        let blast_request = BlastRadiusRequest {
            tenant_id: tenant(),
            action_id: action(),
            seed_ids: BlastRadiusSeeds::new(vec![record(lineage().as_str())])
                .unwrap_or_else(|error| panic!("blast seeds: {error}")),
            query_bounds: BlastRadiusQueryBounds {
                max_depth: 8,
                max_nodes: 128,
                max_edges: 256,
            },
        };
        let approved_result = resolver.resolve(&blast_request);
        let BlastRadiusResult::Exact {
            sorted_affected_ids,
            ..
        } = &approved_result
        else {
            panic!("static lineage did not resolve exactly: {approved_result:?}");
        };
        let affected_ids = sorted_affected_ids.as_slice().to_vec();
        let spec = IssuanceFreezeSpec {
            lineage_id: lineage(),
            acquisition: BlastRadiusFenceAcquisition {
                request: blast_request,
                approved_result,
                expires_at_unix_ms: created_at_unix_ms.saturating_add(INITIAL_FENCE_MS),
            },
        };
        let body = canonical_json_bytes(&spec).unwrap_or_else(|error| panic!("spec: {error}"));
        let empty = empty_issuance_freeze_snapshot(key())
            .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
        let plan = build_response_plan(ResponsePlanInput {
            execution: chio_security_types::ResponseExecutionBinding::new(
                chio_security_types::ResponseExecutionMode::Live,
            ),
            action_id: action(),
            trigger_finding_id: record("fence-lapse-finding"),
            trigger_finding_hash: digest(b"fence-lapse-finding"),
            trigger_finding_receipt_id: OpaqueReceiptRef::new("fence-lapse-finding-receipt")
                .unwrap_or_else(|error| panic!("finding receipt: {error}")),
            tenant_id: tenant(),
            policy_version: record("fence-lapse-policy"),
            policy_hash: digest(b"fence-lapse-policy"),
            affected_ids,
            effects: vec![ResponseEffectSpec {
                kind: ResponseEffectKind::FreezeIssuance,
                target: ResponseTarget::Lineage {
                    lineage_id: lineage(),
                },
                canonical_contribution: CanonicalBody::new(body.clone())
                    .unwrap_or_else(|error| panic!("contribution: {error}")),
                contribution_hash: digest(&body),
                observed_base_version_hash: issuance_freeze_version_hash(&empty)
                    .unwrap_or_else(|error| panic!("empty version: {error}")),
            }],
            ttl_ms: PLAN_TTL_MS,
            created_at_unix_ms,
            operator_capability: OperatorCapabilityBinding {
                capability_id: record("fence-lapse-capability"),
                capability_digest: digest(b"fence-lapse-capability"),
                expires_at_unix_ms: created_at_unix_ms
                    .saturating_add(PLAN_TTL_MS)
                    .saturating_add(60_000),
                executor_subject: record("fence-lapse-executor"),
            },
            approval_requirement: ResponseApprovalRequirement::Automatic,
            submitter: record("fence-lapse-submitter"),
            reason_hash: digest(b"fence-lapse-reason"),
        })
        .unwrap_or_else(|error| panic!("build freeze plan: {error}"));
        let dispatch = prepare_response_dispatch(ResponseDispatchPreparationRequest {
            authorization_capability_hash: plan.operator_capability.capability_digest,
            plan: chio_security_types::FreshLiveAdmission::new(plan.clone())
                .unwrap_or_else(|error| panic!("live plan: {error}")),
            dispatch_id: record("fence-lapse-dispatch"),
            governed_intent_hash: digest(b"fence-lapse-intent"),
            policy_decision_hash: digest(b"fence-lapse-decision"),
            admission_artifact_fingerprint: Some(digest(b"fence-lapse-artifact")),
            executor_authority_id: record("fence-lapse-authority"),
            executor_authority_generation: 1,
            approval: ResponseDispatchApproval::Automatic,
            authorized_at_unix_ms: created_at_unix_ms,
            initial_lease: ResponseDispatchLease {
                lease_owner_id: worker("fence-lapse-worker"),
                lease_expires_at_unix_ms: created_at_unix_ms.saturating_add(SCHEDULER_LEASE_MS),
            },
        })
        .unwrap_or_else(|error| panic!("prepare dispatch: {error}"));
        claim_automatic_preparation(&store, &plan, &dispatch);
        let ResponseDispatchCommitOutcome::Committed(committed) = store
            .commit_dispatch(&dispatch)
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
        else {
            panic!("fresh dispatch unexpectedly existed");
        };
        let freezes = Arc::new(PersistFaultFreezes::new(Arc::clone(&store)));
        Self {
            _directory: directory,
            clock,
            store,
            freezes,
            blast: resolver,
            plan,
            initial_work: committed.initial_work,
            claims: AtomicU64::new(0),
        }
    }

    fn backend(&self) -> IssuanceFreezeBackend {
        let freezes: Arc<dyn IssuanceFreezeStore> = self.freezes.clone();
        let scheduler: Arc<dyn ResponseSchedulerStore> = self.store.clone();
        let clock: Arc<dyn Clock> = self.clock.clone();
        IssuanceFreezeBackend::new_with_scheduler(freezes, Arc::clone(&self.blast), scheduler)
            .with_clock(clock)
    }

    fn scheduler(&self) -> LapseScheduler {
        let backend: Arc<dyn ResponseEffectBackend> = Arc::new(self.backend());
        let effects = ActiveResponseEffectPort::from_backends(vec![backend])
            .unwrap_or_else(|error| panic!("effect router: {error}"));
        let executor = ResponseExecutor::new(
            Arc::clone(&self.store),
            Arc::new(effects),
            Arc::new(AcceptedReceipts),
            Arc::new(DeliveredAlerts),
        );
        ResponseScheduler::new(
            Arc::clone(&self.store),
            Arc::new(executor),
            Arc::new(DeliveredHealth),
            SchedulerPolicy {
                lease_duration_ms: SCHEDULER_LEASE_MS,
                base_backoff_ms: 1_000,
                max_backoff_ms: 1_000,
                operator_page_threshold_ms: 3_600_000,
                max_claims: 4,
            },
        )
        .unwrap_or_else(|error| panic!("response scheduler: {error}"))
    }

    fn created_at(&self) -> u64 {
        self.plan.created_at_unix_ms
    }

    fn claim(&self, at: u64, owner: &str) -> ScheduledWork {
        self.clock.set(at);
        let claim = self.claims.fetch_add(1, Ordering::SeqCst);
        let mut claimed = self
            .store
            .claim_due(&SchedulerClaimRequest {
                tenant_id: tenant(),
                claim_id: record(format!("fence-lapse-claim-{claim}")),
                lease_owner_id: worker(owner),
                now_unix_ms: at,
                lease_expires_at_unix_ms: at.saturating_add(SCHEDULER_LEASE_MS),
                max_claims: 4,
            })
            .unwrap_or_else(|error| panic!("claim at {at}: {error}"));
        assert_eq!(
            claimed.len(),
            1,
            "exactly the freeze response is due at {at}"
        );
        claimed.remove(0)
    }

    fn tick(
        &self,
        scheduler: &LapseScheduler,
        at: u64,
        owner: &str,
    ) -> (ScheduledWork, SchedulerWorkOutcome) {
        let work = self.claim(at, owner);
        let outcome = scheduler
            .process(&work, at)
            .unwrap_or_else(|error| panic!("process at {at}: {error}"));
        (work, outcome)
    }

    /// Drive the dispatched plan through the real executor until the freeze is
    /// installed, maintained once by a successor scheduler epoch, and active.
    fn activate(&self, scheduler: &LapseScheduler) -> ScheduledWork {
        let applied_at = self.created_at().saturating_add(1);
        self.clock.set(applied_at);
        let installed = scheduler
            .process(&self.initial_work, applied_at)
            .unwrap_or_else(|error| panic!("install freeze: {error}"));
        assert!(
            matches!(
                &installed,
                SchedulerWorkOutcome::RetryScheduled { error_code, .. }
                    if error_code.as_str() == "response.execution_incomplete"
            ),
            "freeze install returns to the scheduler for maintenance: {installed:?}"
        );
        assert_eq!(
            self.freeze_progress(),
            Some(ResponseEffectProgress::Applied)
        );
        let (work, outcome) = self.tick(
            scheduler,
            self.created_at().saturating_add(2_000),
            "fence-lapse-worker",
        );
        assert_eq!(
            outcome,
            SchedulerWorkOutcome::Completed {
                action_id: action(),
                state: ResponseState::Active,
            }
        );
        let local = self
            .local_fence()
            .unwrap_or_else(|| panic!("active freeze has no local fence"));
        assert_eq!(self.external_fence(), Some(local.clone()));
        assert_eq!(local.scheduler_fencing_token, work.fencing_token);
        work
    }

    fn external_fence(&self) -> Option<LineageFence> {
        LineageFenceStore::query(
            self.store.as_ref(),
            &TenantScopedId {
                tenant_id: tenant(),
                id: record(action().as_str()),
            },
        )
        .unwrap_or_else(|error| panic!("query external fence: {error}"))
    }

    fn local_contributions(&self) -> Vec<IssuanceFreezeContribution> {
        self.store
            .load_issuance_freezes(&key())
            .unwrap_or_else(|error| panic!("load local freeze: {error}"))
            .map(|snapshot| snapshot.contributions.into_vec())
            .unwrap_or_default()
    }

    fn local_fence(&self) -> Option<LineageFence> {
        self.local_contributions()
            .into_iter()
            .find(|entry| entry.action_id == action())
            .map(|entry| entry.external_fence)
    }

    fn response(&self) -> ResponseSnapshot {
        let record = self
            .store
            .load_plan(&ResponsePlanKey {
                tenant_id: tenant(),
                action_id: action(),
            })
            .unwrap_or_else(|error| panic!("load response: {error}"))
            .unwrap_or_else(|| panic!("response missing"));
        chio_quarantine::decode_response_record(&record)
            .unwrap_or_else(|error| panic!("decode response: {error}"))
    }

    fn freeze_progress(&self) -> Option<ResponseEffectProgress> {
        let effect = self
            .plan
            .effects
            .as_slice()
            .first()
            .unwrap_or_else(|| panic!("freeze effect missing"));
        self.response().effect_progress(&effect.effect_id)
    }

    fn maintenance(&self, work: &ScheduledWork, at: u64) -> LineageFenceMaintenanceRequest {
        let effect = self
            .plan
            .effects
            .as_slice()
            .first()
            .unwrap_or_else(|| panic!("freeze effect missing"));
        LineageFenceMaintenanceRequest {
            plan: self.plan.clone(),
            effect_ids: vec![effect.effect_id.clone()],
            scheduler_work: work.clone(),
            observed_at_unix_ms: at,
            renewed_expires_at_unix_ms: at.saturating_add(LINEAGE_FENCE_MAX_LEASE_MS),
        }
    }

    fn maintain(
        &self,
        backend: &IssuanceFreezeBackend,
        work: &ScheduledWork,
        at: u64,
    ) -> PortResult<LineageFenceMaintenanceResult> {
        self.clock.set(at);
        let effect = self
            .plan
            .effects
            .as_slice()
            .first()
            .unwrap_or_else(|| panic!("freeze effect missing"));
        backend.maintain_lineage_fence(effect, &self.maintenance(work, at))
    }
}

/// Claims the exact automatic preparation a fresh automatic dispatch must hold
/// before it commits.
pub(super) fn claim_automatic_preparation(
    store: &SqliteSecurityStateStore,
    plan: &ResponsePlan,
    dispatch: &chio_security_types::ports::ResponseDispatchCommitRequest,
) {
    use chio_security_types::ports::{
        AutomaticResponsePreparationClaimOutcome, AutomaticResponsePreparationClaimRequest,
        PreparedActiveResponseDispatchBinding,
    };
    let authorization = &dispatch.authorization.body;
    let binding = PreparedActiveResponseDispatchBinding {
        schema_version: authorization.schema_version,
        tenant_id: authorization.key.tenant_id.clone(),
        action_id: authorization.action_id.clone(),
        plan_hash: authorization.plan_hash,
        dispatch_id: authorization.key.dispatch_id.clone(),
        executor_authority_id: authorization.executor_authority_id.clone(),
        executor_authority_generation: authorization.executor_authority_generation,
        authorized_at_unix_ms: authorization.authorized_at_unix_ms,
        authorization_capability_hash: authorization.authorization_capability_hash,
        governed_intent_hash: authorization.governed_intent_hash,
        policy_decision_hash: authorization.policy_decision_hash,
        admission_artifact_fingerprint: authorization.admission_artifact_fingerprint,
        approval: authorization.approval.clone(),
    };
    let outcome = store
        .claim_automatic_preparation(&AutomaticResponsePreparationClaimRequest {
            response_plan: plan.clone(),
            prepared_dispatch_binding: binding.clone(),
        })
        .unwrap_or_else(|error| panic!("claim automatic preparation: {error}"));
    let claimed = match outcome {
        AutomaticResponsePreparationClaimOutcome::Created(claimed)
        | AutomaticResponsePreparationClaimOutcome::Existing(claimed) => claimed,
    };
    assert!(
        claimed.as_ref() == &binding,
        "the store claimed a different automatic preparation"
    );
}

fn outcome_label(outcome: &SchedulerWorkOutcome) -> String {
    match outcome {
        SchedulerWorkOutcome::Completed { state, .. } => format!("completed:{state:?}"),
        SchedulerWorkOutcome::RetryScheduled { error_code, .. } => {
            format!("retry:{}", error_code.as_str())
        }
        SchedulerWorkOutcome::LeaseLost { .. } => "lease_lost".to_owned(),
        SchedulerWorkOutcome::ProcessingFailed { error_code, .. } => {
            format!("failed:{}", error_code.as_str())
        }
    }
}

#[test]
fn lost_local_fence_persist_does_not_strand_the_freeze_past_expiry() {
    let harness = FenceLapseHarness::new();
    let scheduler = harness.scheduler();
    harness.activate(&scheduler);
    let synced = harness
        .local_fence()
        .unwrap_or_else(|| panic!("synced local fence missing"));

    let fault_at = synced.expires_at_unix_ms.saturating_sub(15_000);
    harness.freezes.fail_next_maintenance();
    let (fault_work, fault_outcome) = harness.tick(&scheduler, fault_at, "fence-lapse-worker");
    assert_eq!(outcome_label(&fault_outcome), "retry:store.unavailable");
    let external = harness
        .external_fence()
        .unwrap_or_else(|| panic!("external fence missing after the external takeover"));
    assert_eq!(
        (
            external.scheduler_lease_owner_id.clone(),
            external.scheduler_fencing_token,
            external.expires_at_unix_ms,
        ),
        (
            fault_work.lease_owner_id.clone(),
            fault_work.fencing_token,
            fault_at.saturating_add(LINEAGE_FENCE_MAX_LEASE_MS),
        ),
        "the external fence moved to the faulted scheduler epoch"
    );
    assert_eq!(
        harness.local_fence(),
        Some(synced.clone()),
        "the local projection kept the pre-maintenance fence"
    );

    let mutations_before_retry = harness.response().mutations.len();
    let (_, mismatch_outcome) = harness.tick(
        &scheduler,
        fault_at.saturating_add(2_000),
        "fence-lapse-worker",
    );
    assert_eq!(outcome_label(&mismatch_outcome), "retry:store.unavailable");
    assert_eq!(harness.response().mutations.len(), mutations_before_retry);
    assert_eq!(harness.response().state, ResponseState::Active);
    assert_eq!(harness.external_fence(), Some(external.clone()));
    assert_eq!(harness.local_fence(), Some(synced.clone()));

    let lapse_at = external.expires_at_unix_ms.saturating_add(1_000);
    assert!(lapse_at < harness.plan.expires_at_unix_ms);
    harness.clock.set(lapse_at);
    assert_eq!(harness.external_fence(), None, "the external fence lapsed");
    assert_eq!(
        harness.freeze_progress(),
        Some(ResponseEffectProgress::Applied)
    );
    let (_, lapse_outcome) = harness.tick(&scheduler, lapse_at, "fence-lapse-worker");

    let expiry_at = harness.plan.expires_at_unix_ms.saturating_add(1_000);
    let (_, expiry_outcome) = harness.tick(&scheduler, expiry_at, "fence-lapse-worker");
    let response = harness.response();
    assert_eq!(
        (
            outcome_label(&lapse_outcome),
            outcome_label(&expiry_outcome),
            response.state,
            harness.freeze_progress(),
            harness.local_contributions().len(),
            harness.external_fence(),
        ),
        (
            format!("retry:{LAPSED_FENCE_CODE}"),
            "completed:Lifted".to_owned(),
            ResponseState::Lifted,
            Some(ResponseEffectProgress::Restored),
            0,
            None,
        ),
        "a lapsed external fence must not stop the executor from expiring the freeze"
    );
}

#[test]
fn restart_after_a_fence_outage_still_expires_the_freeze() {
    let harness = FenceLapseHarness::new();
    let scheduler = harness.scheduler();
    harness.activate(&scheduler);
    let synced = harness
        .local_fence()
        .unwrap_or_else(|| panic!("synced local fence missing"));
    drop(scheduler);

    let restart_at = synced.expires_at_unix_ms.saturating_add(1_000);
    harness.clock.set(restart_at);
    assert_eq!(
        harness.external_fence(),
        None,
        "the outage outlived the fence"
    );
    assert_eq!(harness.local_fence(), Some(synced));
    assert_eq!(harness.response().state, ResponseState::Active);
    assert_eq!(
        harness
            .store
            .evaluate_issuance_freeze(&IssuanceFreezeAdmissionQuery {
                tenant_id: tenant(),
                lineage_id: lineage(),
                operation: CapabilityIssuanceOperation::Issue,
                parent_capability_id: None,
            })
            .err()
            .map(|error| error.kind()),
        Some(PortErrorKind::Unavailable),
        "issuance admission fails closed while the projected fence is stale"
    );

    let restarted = harness.scheduler();
    let (_, restart_outcome) = harness.tick(&restarted, restart_at, "fence-lapse-restarted-worker");
    let expiry_at = harness.plan.expires_at_unix_ms.saturating_add(1_000);
    let (_, expiry_outcome) = harness.tick(&restarted, expiry_at, "fence-lapse-restarted-worker");
    let response = harness.response();
    assert_eq!(
        (
            outcome_label(&restart_outcome),
            outcome_label(&expiry_outcome),
            response.state,
            harness.freeze_progress(),
            harness.local_contributions().len(),
            harness.external_fence(),
        ),
        (
            format!("retry:{LAPSED_FENCE_CODE}"),
            "completed:Lifted".to_owned(),
            ResponseState::Lifted,
            Some(ResponseEffectProgress::Restored),
            0,
            None,
        ),
        "a fence that expired during an outage must not stop the executor from expiring the freeze"
    );
}

#[test]
fn same_epoch_renewal_after_a_lost_local_persist_adopts_the_live_fence() {
    let harness = FenceLapseHarness::new();
    let scheduler = harness.scheduler();
    harness.activate(&scheduler);
    let synced = harness
        .local_fence()
        .unwrap_or_else(|| panic!("synced local fence missing"));
    let backend = harness.backend();

    let first_at = synced.expires_at_unix_ms.saturating_sub(15_000);
    let work = harness.claim(first_at, "fence-lapse-direct-worker");
    let rebound = maintained_fence(
        harness
            .maintain(&backend, &work, first_at)
            .unwrap_or_else(|error| panic!("healthy takeover maintenance: {error:?}")),
    );
    assert_eq!(harness.local_fence(), Some(rebound.clone()));
    assert_eq!(harness.external_fence(), Some(rebound.clone()));

    let fault_at = first_at.saturating_add(1_000);
    harness.freezes.fail_next_maintenance();
    let fault = harness
        .maintain(&backend, &work, fault_at)
        .err()
        .unwrap_or_else(|| panic!("injected local persist fault was not observed"));
    assert_eq!(fault.kind(), PortErrorKind::Unavailable);
    let drifted = harness
        .external_fence()
        .unwrap_or_else(|| panic!("renewed external fence missing"));
    assert_eq!(
        drifted,
        LineageFence {
            expires_at_unix_ms: fault_at.saturating_add(LINEAGE_FENCE_MAX_LEASE_MS),
            ..rebound.clone()
        },
        "the external renewal committed in the same scheduler epoch"
    );
    assert_eq!(harness.local_fence(), Some(rebound.clone()));

    let resync_at = fault_at.saturating_add(1_000);
    let resynced = harness.maintain(&backend, &work, resync_at);
    let expected = LineageFence {
        expires_at_unix_ms: resync_at.saturating_add(LINEAGE_FENCE_MAX_LEASE_MS),
        ..rebound
    };
    assert_eq!(
        (resynced, harness.local_fence(), harness.external_fence()),
        (
            Ok(LineageFenceMaintenanceResult::Maintained(expected.clone())),
            Some(expected.clone()),
            Some(expected),
        ),
        "the live same-epoch fence is renewed from its observed expiry and adopted locally"
    );
}

#[test]
fn successor_takeover_after_a_lost_local_persist_adopts_the_predecessor_fence() {
    let harness = FenceLapseHarness::new();
    let scheduler = harness.scheduler();
    harness.activate(&scheduler);
    let synced = harness
        .local_fence()
        .unwrap_or_else(|| panic!("synced local fence missing"));
    let backend = harness.backend();

    let first_at = synced.expires_at_unix_ms.saturating_sub(15_000);
    let predecessor = harness.claim(first_at, "fence-lapse-predecessor");
    let rebound = maintained_fence(
        harness
            .maintain(&backend, &predecessor, first_at)
            .unwrap_or_else(|error| panic!("healthy predecessor maintenance: {error:?}")),
    );
    let fault_at = first_at.saturating_add(1_000);
    harness.freezes.fail_next_maintenance();
    let fault = harness
        .maintain(&backend, &predecessor, fault_at)
        .err()
        .unwrap_or_else(|| panic!("injected local persist fault was not observed"));
    assert_eq!(fault.kind(), PortErrorKind::Unavailable);
    let drifted = harness
        .external_fence()
        .unwrap_or_else(|| panic!("renewed predecessor fence missing"));
    assert_eq!(drifted.fencing_token, rebound.fencing_token);
    assert_eq!(
        drifted.expires_at_unix_ms,
        fault_at.saturating_add(LINEAGE_FENCE_MAX_LEASE_MS)
    );
    assert_eq!(harness.local_fence(), Some(rebound.clone()));

    let successor_at = rebound.expires_at_unix_ms.saturating_sub(15_000);
    assert!(successor_at > first_at.saturating_add(SCHEDULER_LEASE_MS));
    assert!(successor_at < drifted.expires_at_unix_ms);
    let successor = harness.claim(successor_at, "fence-lapse-successor");
    assert!(successor.fencing_token > predecessor.fencing_token);
    let taken_over = harness.maintain(&backend, &successor, successor_at);
    let local = harness.local_fence();
    let external = harness.external_fence();
    assert_eq!(
        (
            taken_over
                .as_ref()
                .map(|result| matches!(result, LineageFenceMaintenanceResult::Maintained(_)))
                .map_err(PortError::kind),
            local.as_ref().map(|fence| (
                fence.scheduler_lease_owner_id.clone(),
                fence.scheduler_fencing_token,
                fence.expires_at_unix_ms,
            )),
            local == external,
        ),
        (
            Ok(true),
            Some((
                successor.lease_owner_id.clone(),
                successor.fencing_token,
                successor_at.saturating_add(LINEAGE_FENCE_MAX_LEASE_MS),
            )),
            true,
        ),
        "the successor takes over the live predecessor fence at its observed expiry"
    );
}

#[test]
fn healthy_maintenance_keeps_the_projection_and_external_fence_in_step() {
    let harness = FenceLapseHarness::new();
    let scheduler = harness.scheduler();
    harness.activate(&scheduler);
    let synced = harness
        .local_fence()
        .unwrap_or_else(|| panic!("synced local fence missing"));

    let horizon_at = synced.expires_at_unix_ms.saturating_sub(15_000);
    let (work, outcome) = harness.tick(&scheduler, horizon_at, "fence-lapse-worker");
    assert_eq!(
        outcome,
        SchedulerWorkOutcome::Completed {
            action_id: action(),
            state: ResponseState::Active,
        }
    );
    let taken_over = harness
        .local_fence()
        .unwrap_or_else(|| panic!("maintained local fence missing"));
    assert_eq!(harness.external_fence(), Some(taken_over.clone()));
    assert_eq!(
        (
            taken_over.scheduler_lease_owner_id.clone(),
            taken_over.scheduler_fencing_token,
            taken_over.expires_at_unix_ms,
        ),
        (
            work.lease_owner_id.clone(),
            work.fencing_token,
            horizon_at.saturating_add(LINEAGE_FENCE_MAX_LEASE_MS),
        )
    );
    assert!(taken_over.fencing_token > synced.fencing_token);

    let backend = harness.backend();
    let renewer_at = taken_over.expires_at_unix_ms.saturating_sub(15_000);
    let renewer = harness.claim(renewer_at, "fence-lapse-renewer");
    let first = maintained_fence(
        harness
            .maintain(&backend, &renewer, renewer_at)
            .unwrap_or_else(|error| panic!("healthy takeover: {error:?}")),
    );
    let renewed_at = renewer_at.saturating_add(1_000);
    let renewed = maintained_fence(
        harness
            .maintain(&backend, &renewer, renewed_at)
            .unwrap_or_else(|error| panic!("healthy same-epoch renewal: {error:?}")),
    );
    assert_eq!(
        renewed,
        LineageFence {
            expires_at_unix_ms: renewed_at.saturating_add(LINEAGE_FENCE_MAX_LEASE_MS),
            ..first
        }
    );
    assert_eq!(harness.local_fence(), Some(renewed.clone()));
    assert_eq!(harness.external_fence(), Some(renewed));
}

#[test]
fn lapsed_projection_rebind_is_refused_while_the_projected_fence_is_live() {
    let harness = FenceLapseHarness::new();
    let scheduler = harness.scheduler();
    harness.activate(&scheduler);
    let synced = harness
        .local_fence()
        .unwrap_or_else(|| panic!("synced local fence missing"));
    let effect = harness
        .plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("freeze effect missing"));

    let probe_at = synced.expires_at_unix_ms.saturating_sub(15_000);
    let successor = harness.claim(probe_at, "fence-lapse-rebind-probe");
    let rebind = IssuanceFreezeFenceMaintenanceRequest {
        key: key(),
        action_id: action(),
        effect_id: effect.effect_id.clone(),
        expected_external_fence: synced.clone(),
        maintained_external_fence: LineageFence {
            scheduler_lease_owner_id: successor.lease_owner_id.clone(),
            scheduler_fencing_token: successor.fencing_token,
            ..synced.clone()
        },
        scheduler_work: successor,
    };
    let refused = harness
        .store
        .maintain_issuance_freeze_fence(&rebind)
        .err()
        .unwrap_or_else(|| panic!("a live projection was rebound without a takeover"));
    assert_eq!(refused.kind(), PortErrorKind::InvalidData);
    assert_eq!(harness.local_fence(), Some(synced.clone()));
    assert_eq!(harness.external_fence(), Some(synced));
}

#[test]
fn foreign_live_fences_are_refused_and_left_untouched() {
    let freezes = Arc::new(FakeFreezeStore::default());
    let blast = Arc::new(FakeBlastRadius::default());
    let mut apply = apply_request();
    let plan = maintenance_plan(&mut apply);
    let work = scheduler_work(&apply);
    let scheduler = Arc::new(FakeSchedulerStore::new(
        work.clone(),
        response_plan_record(&plan, &work),
    ));
    let freeze_port: Arc<dyn IssuanceFreezeStore> = freezes.clone();
    let blast_port: Arc<dyn BlastRadiusPort> = blast.clone();
    let scheduler_port: Arc<dyn ResponseSchedulerStore> = scheduler.clone();
    let backend =
        IssuanceFreezeBackend::new_with_scheduler(freeze_port, blast_port, scheduler_port);
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply freeze: {error:?}"));
    scheduler.mark_effect_applied(&apply.effect_id, applied.resulting_version_hash);
    let installed = blast
        .model
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fence
        .clone()
        .unwrap_or_else(|| panic!("installed external fence missing"));
    let local = freezes
        .load_issuance_freezes(&key())
        .unwrap_or_else(|error| panic!("load installed freeze: {error:?}"));
    let effect = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("planned freeze effect missing"));
    let observed_at_unix_ms = now_unix_ms();
    let renewal = LineageFenceMaintenanceRequest {
        plan: plan.clone(),
        effect_ids: vec![effect.effect_id.clone()],
        scheduler_work: work.clone(),
        observed_at_unix_ms,
        renewed_expires_at_unix_ms: observed_at_unix_ms.saturating_add(40_000),
    };
    let successor = ScheduledWork {
        lease_owner_id: worker("freeze-foreign-successor"),
        fencing_token: work.fencing_token.saturating_add(2),
        ..work.clone()
    };
    let drifted_expiry = installed.expires_at_unix_ms.saturating_add(1_000);
    let cases = [
        (
            "re-acquired epoch under the same scheduler identity",
            LineageFence {
                fencing_token: installed.fencing_token.saturating_add(7),
                expires_at_unix_ms: drifted_expiry,
                ..installed.clone()
            },
            renewal.clone(),
        ),
        (
            "live fence for another commit index",
            LineageFence {
                commit_index: installed.commit_index.saturating_add(1),
                expires_at_unix_ms: drifted_expiry,
                ..installed.clone()
            },
            renewal.clone(),
        ),
        (
            "intermediate scheduler epoch the successor does not own",
            LineageFence {
                fencing_token: installed.fencing_token.saturating_add(1),
                scheduler_lease_owner_id: worker("freeze-foreign-intermediate"),
                scheduler_fencing_token: work.fencing_token.saturating_add(1),
                expires_at_unix_ms: drifted_expiry,
                ..installed.clone()
            },
            LineageFenceMaintenanceRequest {
                scheduler_work: successor.clone(),
                ..renewal.clone()
            },
        ),
    ];
    for (label, foreign, request) in cases {
        scheduler.install(request.scheduler_work.clone());
        blast
            .model
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .fence = Some(foreign.clone());
        let refused = backend
            .maintain_lineage_fence(effect, &request)
            .err()
            .unwrap_or_else(|| panic!("{label} was adopted"));
        assert_eq!(refused.kind(), PortErrorKind::IntegrityFailure, "{label}");
        assert_eq!(
            blast
                .model
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .fence,
            Some(foreign),
            "{label} was mutated"
        );
        assert_eq!(
            freezes
                .load_issuance_freezes(&key())
                .unwrap_or_else(|error| panic!("load local freeze: {error:?}")),
            local,
            "{label} changed the local projection"
        );
    }
}
