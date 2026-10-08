use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_kernel::{prepare_response_dispatch, ResponseDispatchPreparationRequest};
use chio_quarantine::{build_response_plan, CausalBlastRadiusResolver};
use chio_security_types::clock::{Clock, FixedClock};
use chio_security_types::ports::{
    capability_set_suspension_version_hash, empty_capability_set_suspension_snapshot,
    empty_issuance_freeze_snapshot, empty_session_throttle_snapshot, issuance_freeze_version_hash,
    response_affected_set_hash, session_throttle_version_hash, BlastRadiusFenceAcquisition,
    BlastRadiusPort, BlastRadiusQueryBounds, BlastRadiusRequest, BlastRadiusResult,
    BlastRadiusSeeds, CanonicalBody, CapabilitySetSuspensionKey, CapabilitySetSuspensionSpec,
    CausalLineageCommitMetadata, CausalLineageEdge, CausalLineageEdgeKind, CausalLineageEdges,
    CausalLineageFenceRequest, CausalLineageFenceStore, CausalLineageNode, CausalLineageNodeKind,
    CausalLineageNodes, CausalLineageSnapshot, CausalLineageSnapshotRequest, CausalLineageStore,
    Digest32, EffectOperation, EffectPort, EffectRequest, EffectResultQuery,
    EgressRestrictionSessionKey, IssuanceFreezeKey, IssuanceFreezeSpec, LeaseOwnerId, LineageFence,
    LineageFenceRelease, LineageFenceRenewal, LineageFenceRequest, LineageFenceStore,
    LineageFenceTakeover, LineageId, OpaqueReceiptRef, PortError, PortErrorKind, PortResult,
    RecordId, RecordIdSet, ResponseDispatchApproval, ResponseDispatchCommitOutcome,
    ResponseDispatchLease, ResponseDispatchStore, ScheduledWork, SessionId, SessionThrottleKey,
    SessionThrottleLimits, TenantId, TenantScopedId,
};
use chio_security_types::{
    FreshLiveAdmission, OperatorCapabilityBinding, PlannedResponseEffect,
    ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec, ResponseExecutionBinding,
    ResponseExecutionMode, ResponsePlan, ResponsePlanInput, ResponseTarget,
};
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::SqliteSecurityStateStore;

use super::production_response_effects;
use crate::security::adapters::effect_port::{
    egress_restriction_version_hash, session_containment_target, session_overlay_version_hash,
};
use crate::security::adapters::{AlertOutboxConfig, SqliteSiemOutbox};

mod finality;

/// Trusted time ten minutes ahead of the host wall clock.
const TRUSTED_SKEW_MS: u64 = 600_000;

fn wall_now_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before epoch: {error}"));
    u64::try_from(elapsed.as_millis()).unwrap_or_else(|error| panic!("clock range: {error}"))
}

fn tenant() -> TenantId {
    TenantId::new("tenant-production-effects").unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn lineage() -> LineageId {
    LineageId::new("capability-root").unwrap_or_else(|error| panic!("lineage: {error}"))
}

fn session(value: &str) -> SessionId {
    SessionId::new(value).unwrap_or_else(|error| panic!("session: {error}"))
}

fn record(value: impl Into<String>) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record: {error}"))
}

fn digest(value: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(value).as_bytes())
}

fn canonical(value: &impl serde::Serialize) -> (CanonicalBody, Digest32) {
    let bytes = canonical_json_bytes(value).unwrap_or_else(|error| panic!("canonical: {error}"));
    let hash = digest(&bytes);
    (
        CanonicalBody::new(bytes).unwrap_or_else(|error| panic!("canonical body: {error}")),
        hash,
    )
}

struct NoopAlertBackend;

impl AlertBackend for NoopAlertBackend {
    fn name(&self) -> &str {
        "production-effects-test-alert-backend"
    }

    fn dispatch<'a>(
        &'a self,
        _alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
    {
        Box::pin(async { Ok(()) })
    }
}

struct StaticLineage(CausalLineageSnapshot);

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

struct SqliteFences(Arc<SqliteSecurityStateStore>);

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

fn lineage_snapshot() -> CausalLineageSnapshot {
    let node = |id: &str| CausalLineageNode {
        tenant_id: tenant(),
        node_id: record(id),
        kind: CausalLineageNodeKind::Capability,
    };
    CausalLineageSnapshot {
        tenant_id: tenant(),
        metadata: CausalLineageCommitMetadata {
            source_lineage_version: 3,
            observed_commit_index: 12,
            authoritative_commit_index: 12,
            completeness_watermark: Some(12),
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

/// Production effect composition over a SQLite security store and alert
/// outbox whose trusted clock runs ahead of the host wall clock.
struct ProductionEffectsFixture {
    _directory: tempfile::TempDir,
    outbox_path: PathBuf,
    trusted_now: u64,
    trusted_clock: Arc<dyn Clock>,
    store: Arc<SqliteSecurityStateStore>,
    outbox: Arc<SqliteSiemOutbox>,
    resolver: Arc<CausalBlastRadiusResolver<StaticLineage, SqliteFences>>,
}

impl ProductionEffectsFixture {
    fn new() -> Self {
        Self::with_skew(TRUSTED_SKEW_MS)
    }

    fn with_skew(skew_ms: u64) -> Self {
        let directory =
            chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let trusted_now = wall_now_unix_ms().saturating_add(skew_ms);
        let trusted_clock: Arc<dyn Clock> = Arc::new(FixedClock::from_millis(trusted_now));
        let store = Arc::new(
            SqliteSecurityStateStore::open_with_trusted_clock(
                directory.path().join("production-effects.db"),
                Arc::clone(&trusted_clock),
            )
            .unwrap_or_else(|error| panic!("open security store: {error}")),
        );
        let outbox_path = directory.path().join("production-effects-alerts.db");
        let outbox = Arc::new(
            SqliteSiemOutbox::open(
                &outbox_path,
                vec![Arc::new(NoopAlertBackend) as Arc<dyn AlertBackend>],
                AlertOutboxConfig::default(),
            )
            .unwrap_or_else(|error| panic!("open alert outbox: {error}")),
        );
        let resolver = Arc::new(CausalBlastRadiusResolver::new(
            Arc::new(StaticLineage(lineage_snapshot())),
            Arc::new(SqliteFences(Arc::clone(&store))),
        ));
        Self {
            _directory: directory,
            outbox_path,
            trusted_now,
            trusted_clock,
            store,
            outbox,
            resolver,
        }
    }

    fn effects(&self) -> Arc<dyn EffectPort> {
        let blast: Arc<dyn BlastRadiusPort> = self.resolver.clone();
        production_response_effects(
            ResponseExecutionMode::Live,
            Arc::clone(&self.store),
            Arc::clone(&self.outbox),
            blast,
            Arc::clone(&self.trusted_clock),
        )
        .unwrap_or_else(|error| panic!("production response effects: {error}"))
    }

    fn freeze_spec(&self, action_id: &str) -> ResponseEffectSpec {
        self.freeze_spec_expiring(action_id, self.trusted_now.saturating_add(30_000))
    }

    fn freeze_spec_expiring(&self, action_id: &str, fence_expires_at: u64) -> ResponseEffectSpec {
        let request = BlastRadiusRequest {
            tenant_id: tenant(),
            action_id: chio_security_types::ports::ActionId::new(action_id)
                .unwrap_or_else(|error| panic!("action: {error}")),
            seed_ids: BlastRadiusSeeds::new(vec![record(lineage().as_str())])
                .unwrap_or_else(|error| panic!("blast seeds: {error}")),
            query_bounds: BlastRadiusQueryBounds {
                max_depth: 8,
                max_nodes: 128,
                max_edges: 256,
            },
        };
        let approved_result = self.resolver.resolve(&request);
        assert!(
            matches!(approved_result, BlastRadiusResult::Exact { .. }),
            "static lineage resolves exactly: {approved_result:?}"
        );
        let (canonical_contribution, contribution_hash) = canonical(&IssuanceFreezeSpec {
            lineage_id: lineage(),
            acquisition: BlastRadiusFenceAcquisition {
                request,
                approved_result,
                expires_at_unix_ms: fence_expires_at,
            },
        });
        let empty = empty_issuance_freeze_snapshot(IssuanceFreezeKey {
            tenant_id: tenant(),
            lineage_id: lineage(),
        })
        .unwrap_or_else(|error| panic!("empty freeze: {error}"));
        ResponseEffectSpec {
            kind: ResponseEffectKind::FreezeIssuance,
            target: ResponseTarget::Lineage {
                lineage_id: lineage(),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: issuance_freeze_version_hash(&empty)
                .unwrap_or_else(|error| panic!("empty freeze version: {error}")),
        }
    }

    /// A lineage freeze planned against the live issuance-freeze snapshot.
    fn live_freeze_spec(&self, action_id: &str) -> ResponseEffectSpec {
        let key = IssuanceFreezeKey {
            tenant_id: tenant(),
            lineage_id: lineage(),
        };
        let live = chio_security_types::ports::IssuanceFreezeStore::load_issuance_freezes(
            self.store.as_ref(),
            &key,
        )
        .unwrap_or_else(|error| panic!("load issuance freezes: {error}"))
        .map_or_else(|| empty_issuance_freeze_snapshot(key.clone()), Ok)
        .unwrap_or_else(|error| panic!("issuance freeze snapshot: {error}"));
        ResponseEffectSpec {
            observed_base_version_hash: issuance_freeze_version_hash(&live)
                .unwrap_or_else(|error| panic!("live freeze version: {error}")),
            ..self.freeze_spec(action_id)
        }
    }

    fn alert_spec(&self) -> ResponseEffectSpec {
        let (canonical_contribution, contribution_hash) =
            canonical(&serde_json::json!({ "channel": "security" }));
        ResponseEffectSpec {
            kind: ResponseEffectKind::EscalateAlert,
            target: ResponseTarget::Tenant {
                tenant_id: tenant(),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: digest(b"production-effects-alert-base"),
        }
    }

    fn egress_spec(&self, session_id: &SessionId, destinations: &[&str]) -> ResponseEffectSpec {
        let (canonical_contribution, contribution_hash) =
            canonical(&serde_json::json!({ "destinations": destinations }));
        ResponseEffectSpec {
            kind: ResponseEffectKind::RestrictEgress,
            target: ResponseTarget::Session {
                session_id: session_id.clone(),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: egress_restriction_version_hash(
                self.store.as_ref(),
                &EgressRestrictionSessionKey {
                    tenant_id: tenant(),
                    session_id: session_id.clone(),
                },
            )
            .unwrap_or_else(|error| panic!("egress base version: {error}")),
        }
    }

    fn throttle_spec(&self, session_id: &SessionId) -> ResponseEffectSpec {
        let (canonical_contribution, contribution_hash) = canonical(&SessionThrottleLimits {
            window_ms: 5_000,
            max_invocations: 3,
        });
        let empty = empty_session_throttle_snapshot(SessionThrottleKey {
            tenant_id: tenant(),
            session_id: session_id.clone(),
        })
        .unwrap_or_else(|error| panic!("empty throttle: {error}"));
        ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: session_id.clone(),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: session_throttle_version_hash(&empty)
                .unwrap_or_else(|error| panic!("empty throttle version: {error}")),
        }
    }

    fn capability_set_spec(&self, affected: &[&str]) -> ResponseEffectSpec {
        let affected_ids = RecordIdSet::new(affected.iter().map(|id| record(*id)).collect())
            .unwrap_or_else(|error| panic!("affected set: {error}"));
        let affected_set_hash = response_affected_set_hash(&tenant(), &affected_ids)
            .unwrap_or_else(|error| panic!("affected hash: {error}"));
        let (canonical_contribution, contribution_hash) =
            canonical(&CapabilitySetSuspensionSpec { affected_ids });
        let empty = empty_capability_set_suspension_snapshot(CapabilitySetSuspensionKey {
            tenant_id: tenant(),
            affected_set_hash,
        })
        .unwrap_or_else(|error| panic!("empty capability suspension: {error}"));
        ResponseEffectSpec {
            kind: ResponseEffectKind::SuspendCapabilitySet,
            target: ResponseTarget::CapabilitySet { affected_set_hash },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: capability_set_suspension_version_hash(&empty)
                .unwrap_or_else(|error| panic!("empty capability version: {error}")),
        }
    }

    fn session_suspension_spec(&self, session_id: &SessionId) -> ResponseEffectSpec {
        self.ranked_session_suspension_spec(session_id, 4)
    }

    fn ranked_session_suspension_spec(
        &self,
        session_id: &SessionId,
        posture_rank: u32,
    ) -> ResponseEffectSpec {
        let (canonical_contribution, contribution_hash) =
            canonical(&serde_json::json!({ "posture_rank": posture_rank }));
        let target = session_containment_target(&tenant(), session_id)
            .unwrap_or_else(|error| panic!("session target: {error}"));
        ResponseEffectSpec {
            kind: ResponseEffectKind::SuspendSession,
            target: ResponseTarget::Session {
                session_id: session_id.clone(),
            },
            canonical_contribution,
            contribution_hash,
            observed_base_version_hash: session_overlay_version_hash(self.store.as_ref(), &target)
                .unwrap_or_else(|error| panic!("session base version: {error}")),
        }
    }

    /// Commit a live automatic dispatch at trusted time and return the plan
    /// with the scheduler work that holds its lease.
    fn dispatch(
        &self,
        action_id: &str,
        affected_ids: Vec<RecordId>,
        effects: Vec<ResponseEffectSpec>,
    ) -> (ResponsePlan, ScheduledWork) {
        self.dispatch_with_ttl(action_id, affected_ids, effects, 120_000)
    }

    fn dispatch_with_ttl(
        &self,
        action_id: &str,
        affected_ids: Vec<RecordId>,
        effects: Vec<ResponseEffectSpec>,
        ttl_ms: u64,
    ) -> (ResponsePlan, ScheduledWork) {
        let plan = build_response_plan(ResponsePlanInput {
            execution: ResponseExecutionBinding::new(ResponseExecutionMode::Live),
            action_id: chio_security_types::ports::ActionId::new(action_id)
                .unwrap_or_else(|error| panic!("action: {error}")),
            trigger_finding_id: record(format!("{action_id}-finding")),
            trigger_finding_hash: digest(format!("{action_id}-finding").as_bytes()),
            trigger_finding_receipt_id: OpaqueReceiptRef::new(format!("{action_id}-receipt"))
                .unwrap_or_else(|error| panic!("finding receipt: {error}")),
            tenant_id: tenant(),
            policy_version: record("production-effects-policy"),
            policy_hash: digest(b"production-effects-policy"),
            affected_ids,
            effects,
            ttl_ms,
            created_at_unix_ms: self.trusted_now,
            operator_capability: OperatorCapabilityBinding {
                capability_id: record("production-effects-capability"),
                capability_digest: digest(b"production-effects-capability"),
                expires_at_unix_ms: self
                    .trusted_now
                    .saturating_add(ttl_ms)
                    .saturating_add(180_000),
                executor_subject: record("production-effects-executor"),
            },
            approval_requirement: ResponseApprovalRequirement::Automatic,
            submitter: record("production-effects-submitter"),
            reason_hash: digest(b"production-effects-reason"),
        })
        .unwrap_or_else(|error| panic!("build response plan: {error}"));
        let dispatch = prepare_response_dispatch(ResponseDispatchPreparationRequest {
            authorization_capability_hash: plan.operator_capability.capability_digest,
            plan: FreshLiveAdmission::new(plan.clone())
                .unwrap_or_else(|error| panic!("live plan: {error}")),
            dispatch_id: record(format!("{action_id}-dispatch")),
            governed_intent_hash: digest(format!("{action_id}-intent").as_bytes()),
            policy_decision_hash: digest(format!("{action_id}-decision").as_bytes()),
            admission_artifact_fingerprint: Some(digest(b"production-effects-artifact")),
            executor_authority_id: record("production-effects-authority"),
            executor_authority_generation: 1,
            approval: ResponseDispatchApproval::Automatic,
            authorized_at_unix_ms: self.trusted_now,
            initial_lease: ResponseDispatchLease {
                lease_owner_id: LeaseOwnerId::new("production-effects-worker")
                    .unwrap_or_else(|error| panic!("lease owner: {error}")),
                lease_expires_at_unix_ms: self.trusted_now.saturating_add(10_000),
            },
        })
        .unwrap_or_else(|error| panic!("prepare dispatch: {error}"));
        claim_automatic_preparation(&self.store, &plan, &dispatch);
        let ResponseDispatchCommitOutcome::Committed(committed) = self
            .store
            .commit_dispatch(&dispatch)
            .unwrap_or_else(|error| panic!("commit dispatch: {error}"))
        else {
            panic!("fresh dispatch unexpectedly existed");
        };
        (plan, committed.initial_work)
    }

    fn stored_alert_occurred_at(&self) -> Vec<u64> {
        let connection = rusqlite::Connection::open(&self.outbox_path)
            .unwrap_or_else(|error| panic!("open alert outbox: {error}"));
        let mut statement = connection
            .prepare("SELECT command_json FROM chio_security_alert_outbox")
            .unwrap_or_else(|error| panic!("prepare alert read: {error}"));
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap_or_else(|error| panic!("read alerts: {error}"));
        let mut occurred = Vec::new();
        for row in rows {
            let body = row.unwrap_or_else(|error| panic!("alert row: {error}"));
            let value: serde_json::Value = serde_json::from_slice(&body)
                .unwrap_or_else(|error| panic!("alert command json: {error}"));
            occurred.extend(find_u64(&value, "occurred_at_unix_ms"));
        }
        occurred
    }
}

/// Claims the exact automatic preparation a fresh automatic dispatch must hold
/// before it commits.
fn claim_automatic_preparation(
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

fn find_u64(value: &serde_json::Value, key: &str) -> Vec<u64> {
    match value {
        serde_json::Value::Object(map) => map
            .iter()
            .flat_map(|(name, nested)| {
                if name == key {
                    nested.as_u64().into_iter().collect::<Vec<_>>()
                } else {
                    find_u64(nested, key)
                }
            })
            .collect(),
        serde_json::Value::Array(items) => {
            items.iter().flat_map(|item| find_u64(item, key)).collect()
        }
        _ => Vec::new(),
    }
}

fn effect_request(
    plan: &ResponsePlan,
    effect: &PlannedResponseEffect,
    work: &ScheduledWork,
    command: &str,
) -> EffectRequest {
    EffectRequest {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        effect_id: effect.effect_id.clone(),
        effect_kind: effect.kind,
        target: effect.target.clone(),
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{command}")),
        expected_version_hash: effect.observed_base_version_hash,
        scheduler_lease_owner_id: work.lease_owner_id.clone(),
        scheduler_fencing_token: work.fencing_token,
        canonical_contribution: effect.canonical_contribution.clone(),
        contribution_hash: effect.contribution_hash,
    }
}

fn unplanned_request(
    plan: &ResponsePlan,
    spec: ResponseEffectSpec,
    work: &ScheduledWork,
    command: &str,
) -> EffectRequest {
    EffectRequest {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        effect_id: chio_security_types::ports::EffectId::new(format!("unplanned-{command}"))
            .unwrap_or_else(|error| panic!("effect id: {error}")),
        effect_kind: spec.kind,
        target: spec.target,
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{command}")),
        expected_version_hash: spec.observed_base_version_hash,
        scheduler_lease_owner_id: work.lease_owner_id.clone(),
        scheduler_fencing_token: work.fencing_token,
        canonical_contribution: spec.canonical_contribution,
        contribution_hash: spec.contribution_hash,
    }
}

fn query(request: &EffectRequest) -> EffectResultQuery {
    EffectResultQuery {
        tenant_id: request.tenant_id.clone(),
        action_id: request.action_id.clone(),
        plan_hash: request.plan_hash,
        effect_id: request.effect_id.clone(),
        effect_kind: request.effect_kind,
        target: request.target.clone(),
        plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
        operation: request.operation,
        idempotency_key: request.idempotency_key.clone(),
        expected_version_hash: request.expected_version_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
        contribution_hash: request.contribution_hash,
    }
}

#[test]
fn production_effects_use_the_trusted_clock_for_freeze_leases_and_alert_time() {
    let fixture = ProductionEffectsFixture::new();
    let freeze = fixture.freeze_spec("production-effects-clock-action");
    let alert = fixture.alert_spec();
    let (plan, work) = fixture.dispatch(
        "production-effects-clock-action",
        vec![record("capability-child"), record("capability-root")],
        vec![freeze, alert],
    );
    let effects = fixture.effects();
    let planned = plan.effects.as_slice();
    let [freeze_effect, alert_effect] = planned else {
        panic!("plan has exactly the freeze and alert effects");
    };
    assert_eq!(
        fixture
            .trusted_clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)
            .ok(),
        Some(fixture.trusted_now)
    );
    assert!(
        fixture.trusted_now > wall_now_unix_ms().saturating_add(60_000),
        "trusted time runs ahead of the wall clock by more than one fence lease"
    );

    let freeze_outcome = effects
        .execute(&effect_request(&plan, freeze_effect, &work, "clock-freeze"))
        .map(|result| result.applied)
        .map_err(|error| error.kind());
    effects
        .execute(&effect_request(&plan, alert_effect, &work, "clock-alert"))
        .unwrap_or_else(|error| panic!("escalate alert: {error}"));
    assert_eq!(
        (freeze_outcome, fixture.stored_alert_occurred_at()),
        (Ok(true), vec![fixture.trusted_now]),
        "production effects judge the freeze lease and stamp the alert with trusted time"
    );
}

#[test]
fn production_effects_refuse_a_freeze_lease_already_stale_in_trusted_time() {
    let fixture = ProductionEffectsFixture::with_skew(20_000);
    let stale_expiry = fixture.trusted_now.saturating_sub(1_000);
    assert!(
        stale_expiry > wall_now_unix_ms(),
        "the wall clock alone would still accept this lease"
    );
    let freeze = fixture.freeze_spec_expiring("production-effects-stale-action", stale_expiry);
    let (plan, work) = fixture.dispatch(
        "production-effects-stale-action",
        vec![record("capability-child"), record("capability-root")],
        vec![freeze],
    );
    let effects = fixture.effects();
    let freeze_effect = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("planned freeze effect missing"));
    let refused = effects
        .execute(&effect_request(&plan, freeze_effect, &work, "stale-freeze"))
        .err()
        .unwrap_or_else(|| panic!("a lease stale in trusted time was accepted"));
    assert_eq!(
        refused.kind(),
        chio_security_types::ports::PortErrorKind::InvalidData
    );
    assert_eq!(
        LineageFenceStore::query(
            fixture.store.as_ref(),
            &TenantScopedId {
                tenant_id: tenant(),
                id: record("production-effects-stale-action"),
            },
        )
        .unwrap_or_else(|error| panic!("query fence: {error}")),
        None
    );
    assert_eq!(
        chio_security_types::ports::IssuanceFreezeStore::load_issuance_freezes(
            fixture.store.as_ref(),
            &IssuanceFreezeKey {
                tenant_id: tenant(),
                lineage_id: lineage(),
            },
        )
        .unwrap_or_else(|error| panic!("load freezes: {error}"))
        .map(|snapshot| snapshot.contributions.len())
        .unwrap_or(0),
        0
    );
}

#[test]
fn production_effects_refuse_effects_outside_the_live_plan() {
    let fixture = ProductionEffectsFixture::new();
    let planned_session = session("production-effects-planned-session");
    let other_session = session("production-effects-other-session");
    let (plan, work) = fixture.dispatch(
        "production-effects-plan-action",
        vec![record(planned_session.as_str())],
        vec![fixture.egress_spec(&planned_session, &["server-a"])],
    );
    let effects = fixture.effects();
    let planned = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("planned egress effect missing"));
    let planned_request = effect_request(&plan, planned, &work, "planned-egress");
    let unplanned = [
        (
            "egress",
            unplanned_request(
                &plan,
                fixture.egress_spec(&other_session, &["server-b"]),
                &work,
                "unplanned-egress",
            ),
        ),
        (
            "throttle",
            unplanned_request(
                &plan,
                fixture.throttle_spec(&planned_session),
                &work,
                "unplanned-throttle",
            ),
        ),
        (
            "capability-set suspension",
            unplanned_request(
                &plan,
                fixture.capability_set_spec(&["capability-other"]),
                &work,
                "unplanned-capability-set",
            ),
        ),
        (
            "session suspension",
            unplanned_request(
                &plan,
                fixture.session_suspension_spec(&planned_session),
                &work,
                "unplanned-session-suspension",
            ),
        ),
        (
            "alert",
            unplanned_request(&plan, fixture.alert_spec(), &work, "unplanned-alert"),
        ),
    ];
    let mut observed = vec![(
        "planned egress",
        effects
            .execute(&planned_request)
            .map(|result| result.applied)
            .map_err(|error| error.kind()),
        effects
            .load_result(&query(&planned_request))
            .map(|status| {
                matches!(
                    status,
                    chio_security_types::ports::EffectExecutionStatus::Completed { .. }
                )
            })
            .map_err(|error| error.kind()),
    )];
    for (label, request) in &unplanned {
        observed.push((
            *label,
            effects
                .execute(request)
                .map(|result| result.applied)
                .map_err(|error| error.kind()),
            effects
                .load_result(&query(request))
                .map(|status| {
                    matches!(
                        status,
                        chio_security_types::ports::EffectExecutionStatus::Completed { .. }
                    )
                })
                .map_err(|error| error.kind()),
        ));
    }
    let mut expected = vec![("planned egress", Ok(true), Ok(true))];
    for (label, _) in &unplanned {
        expected.push((
            *label,
            Err(PortErrorKind::IntegrityFailure),
            Err(PortErrorKind::IntegrityFailure),
        ));
    }
    assert_eq!(
        observed, expected,
        "a live lease for one action cannot execute or read effects outside its durable plan"
    );
}

fn effective_posture_rank(store: &SqliteSecurityStateStore, session_id: &SessionId) -> u32 {
    let target = session_containment_target(&tenant(), session_id)
        .unwrap_or_else(|error| panic!("session target: {error}"));
    chio_security_types::ports::ContainmentOverlayStore::load_effective(store, &target)
        .unwrap_or_else(|error| panic!("load session overlay: {error}"))
        .map_or(0, |snapshot| snapshot.effective_posture_rank)
}

#[test]
fn session_suspensions_planned_on_one_base_both_hold() {
    let fixture = ProductionEffectsFixture::new();
    let shared_session = session("production-effects-shared-base-session");
    let first_spec = fixture.ranked_session_suspension_spec(&shared_session, 3);
    let second_spec = fixture.ranked_session_suspension_spec(&shared_session, 8);
    assert_eq!(
        first_spec.observed_base_version_hash, second_spec.observed_base_version_hash,
        "both plans observed the same overlay base"
    );
    let (first_plan, first_work) = fixture.dispatch_with_ttl(
        "production-effects-shared-base-first",
        vec![record(shared_session.as_str())],
        vec![first_spec],
        600_000,
    );
    let (second_plan, second_work) = fixture.dispatch_with_ttl(
        "production-effects-shared-base-second",
        vec![record(shared_session.as_str())],
        vec![second_spec],
        3_600_000,
    );
    let effects = fixture.effects();
    let first_effect = first_plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("first suspension missing"));
    let second_effect = second_plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("second suspension missing"));

    let first_applied = effects
        .execute(&effect_request(
            &first_plan,
            first_effect,
            &first_work,
            "shared-base-first",
        ))
        .unwrap_or_else(|error| panic!("apply first suspension: {error}"));
    assert_eq!(
        effective_posture_rank(&fixture.store, &shared_session),
        3,
        "the first suspension holds alone"
    );

    let second = effect_request(
        &second_plan,
        second_effect,
        &second_work,
        "shared-base-second",
    );
    let second_apply = effects
        .execute(&second)
        .map(|result| result.applied)
        .map_err(|error| error.kind());
    let second_retry = effects
        .execute(&second)
        .map(|result| result.applied)
        .map_err(|error| error.kind());
    let rank_with_both = effective_posture_rank(&fixture.store, &shared_session);

    let mut lift_first = effect_request(
        &first_plan,
        first_effect,
        &first_work,
        "shared-base-lift-first",
    );
    lift_first.operation = EffectOperation::Remove;
    lift_first.expected_version_hash = first_applied.resulting_version_hash;
    let lifted = effects
        .execute(&lift_first)
        .unwrap_or_else(|error| panic!("lift first suspension: {error}"));
    assert!(!lifted.applied);
    let rank_after_lift = effective_posture_rank(&fixture.store, &shared_session);

    assert_eq!(
        (second_apply, second_retry, rank_with_both, rank_after_lift),
        (Ok(true), Ok(true), 8, 8),
        "a suspension planned on the same base must compose with the first and outlive its lift"
    );
}

/// One planned effect under the live lease of its dispatched plan.
struct LeasedEffect<'a> {
    plan: &'a ResponsePlan,
    work: &'a ScheduledWork,
    ordinal: usize,
}

impl LeasedEffect<'_> {
    fn effect(&self) -> &PlannedResponseEffect {
        self.plan
            .effects
            .as_slice()
            .get(self.ordinal)
            .unwrap_or_else(|| panic!("planned effect {} missing", self.ordinal))
    }

    fn id(&self) -> String {
        self.effect().effect_id.as_str().to_owned()
    }

    fn request(&self, command: &str) -> EffectRequest {
        effect_request(self.plan, self.effect(), self.work, command)
    }
}

/// Live reads of the one effect key that two plans contribute to.
struct SharedKey<'a> {
    version: &'a dyn Fn() -> Digest32,
    installed: &'a dyn Fn() -> Vec<String>,
}

/// What a second contribution planned on the first one's base does.
#[derive(Debug, Eq, PartialEq)]
struct SharedBaseOutcome {
    second_apply: Result<bool, PortErrorKind>,
    second_retry: Result<bool, PortErrorKind>,
    installed_with_both: Vec<String>,
    installed_after_lift: Vec<String>,
}

impl SharedBaseOutcome {
    /// Both contributions hold together and the second outlives the first.
    fn composed(first: &LeasedEffect<'_>, second: &LeasedEffect<'_>) -> Self {
        let mut both = vec![first.id(), second.id()];
        both.sort();
        Self {
            second_apply: Ok(true),
            second_retry: Ok(true),
            installed_with_both: both,
            installed_after_lift: vec![second.id()],
        }
    }
}

/// Apply the first contribution, then apply and retry the second, which was
/// planned on the same base, and finally lift the first.
fn shared_base_outcome(
    effects: &dyn EffectPort,
    key: &SharedKey<'_>,
    first: &LeasedEffect<'_>,
    second: &LeasedEffect<'_>,
) -> SharedBaseOutcome {
    let base = first.effect().observed_base_version_hash;
    assert_eq!(
        second.effect().observed_base_version_hash,
        base,
        "both plans observed the same base"
    );
    assert_eq!(
        (key.version)(),
        base,
        "the observed base is the live version"
    );
    let first_applied = effects
        .execute(&first.request("shared-base-first"))
        .unwrap_or_else(|error| panic!("apply first contribution: {error}"));
    assert_eq!(
        (key.installed)(),
        vec![first.id()],
        "the first contribution holds alone"
    );
    assert_ne!(
        (key.version)(),
        base,
        "the second plan's observed base is no longer the live version"
    );
    let second_request = second.request("shared-base-second");
    let second_apply = effects
        .execute(&second_request)
        .map(|result| result.applied)
        .map_err(|error| error.kind());
    let second_retry = effects
        .execute(&second_request)
        .map(|result| result.applied)
        .map_err(|error| error.kind());
    let installed_with_both = (key.installed)();
    let mut lift = first.request("shared-base-lift-first");
    lift.operation = EffectOperation::Remove;
    lift.expected_version_hash = first_applied.resulting_version_hash;
    let lifted = effects
        .execute(&lift)
        .unwrap_or_else(|error| panic!("lift first contribution: {error}"));
    assert!(!lifted.applied);
    SharedBaseOutcome {
        second_apply,
        second_retry,
        installed_with_both,
        installed_after_lift: (key.installed)(),
    }
}

fn egress_effect_ids(
    store: &SqliteSecurityStateStore,
    key: &EgressRestrictionSessionKey,
) -> Vec<String> {
    chio_security_types::ports::EgressRestrictionStore::load_egress_restrictions(store, key)
        .unwrap_or_else(|error| panic!("load egress restrictions: {error}"))
        .map(|snapshot| {
            snapshot
                .contributions
                .as_slice()
                .iter()
                .map(|entry| entry.effect_id.as_str().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn egress_restrictions_planned_on_one_base_both_hold() {
    let fixture = ProductionEffectsFixture::new();
    let shared_session = session("production-effects-shared-egress-session");
    let (first_plan, first_work) = fixture.dispatch_with_ttl(
        "production-effects-shared-egress-first",
        vec![record(shared_session.as_str())],
        vec![fixture.egress_spec(&shared_session, &["server-a"])],
        600_000,
    );
    let (second_plan, second_work) = fixture.dispatch_with_ttl(
        "production-effects-shared-egress-second",
        vec![record(shared_session.as_str())],
        vec![fixture.egress_spec(&shared_session, &["server-b"])],
        3_600_000,
    );
    let first = LeasedEffect {
        plan: &first_plan,
        work: &first_work,
        ordinal: 0,
    };
    let second = LeasedEffect {
        plan: &second_plan,
        work: &second_work,
        ordinal: 0,
    };
    let egress_key = EgressRestrictionSessionKey {
        tenant_id: tenant(),
        session_id: shared_session.clone(),
    };
    let version = || {
        egress_restriction_version_hash(fixture.store.as_ref(), &egress_key)
            .unwrap_or_else(|error| panic!("egress version: {error}"))
    };
    let installed = || egress_effect_ids(&fixture.store, &egress_key);
    let effects = fixture.effects();
    assert_eq!(
        shared_base_outcome(
            effects.as_ref(),
            &SharedKey {
                version: &version,
                installed: &installed,
            },
            &first,
            &second,
        ),
        SharedBaseOutcome::composed(&first, &second),
        "an egress restriction planned on the same base must compose with the first and outlive its lift"
    );
}

fn throttle_effect_ids(store: &SqliteSecurityStateStore, key: &SessionThrottleKey) -> Vec<String> {
    chio_security_types::ports::SessionThrottleStore::load_session_throttles(store, key)
        .unwrap_or_else(|error| panic!("load session throttles: {error}"))
        .map(|snapshot| {
            snapshot
                .contributions
                .as_slice()
                .iter()
                .map(|entry| entry.effect_id.as_str().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn throttle_version(store: &SqliteSecurityStateStore, key: &SessionThrottleKey) -> Digest32 {
    let snapshot =
        chio_security_types::ports::SessionThrottleStore::load_session_throttles(store, key)
            .unwrap_or_else(|error| panic!("load session throttles: {error}"))
            .map_or_else(|| empty_session_throttle_snapshot(key.clone()), Ok)
            .unwrap_or_else(|error| panic!("throttle snapshot: {error}"));
    session_throttle_version_hash(&snapshot)
        .unwrap_or_else(|error| panic!("throttle version: {error}"))
}

#[test]
fn session_throttles_planned_on_one_base_both_hold() {
    let fixture = ProductionEffectsFixture::new();
    let shared_session = session("production-effects-shared-throttle-session");
    let throttle = |max_invocations: u32| {
        let mut spec = fixture.throttle_spec(&shared_session);
        let (canonical_contribution, contribution_hash) = canonical(&SessionThrottleLimits {
            window_ms: 5_000,
            max_invocations,
        });
        spec.canonical_contribution = canonical_contribution;
        spec.contribution_hash = contribution_hash;
        spec
    };
    let (first_plan, first_work) = fixture.dispatch_with_ttl(
        "production-effects-shared-throttle-first",
        vec![record(shared_session.as_str())],
        vec![throttle(10)],
        600_000,
    );
    let (second_plan, second_work) = fixture.dispatch_with_ttl(
        "production-effects-shared-throttle-second",
        vec![record(shared_session.as_str())],
        vec![throttle(3)],
        3_600_000,
    );
    let first = LeasedEffect {
        plan: &first_plan,
        work: &first_work,
        ordinal: 0,
    };
    let second = LeasedEffect {
        plan: &second_plan,
        work: &second_work,
        ordinal: 0,
    };
    let throttle_key = SessionThrottleKey {
        tenant_id: tenant(),
        session_id: shared_session.clone(),
    };
    let version = || throttle_version(&fixture.store, &throttle_key);
    let installed = || throttle_effect_ids(&fixture.store, &throttle_key);
    let effects = fixture.effects();
    assert_eq!(
        shared_base_outcome(
            effects.as_ref(),
            &SharedKey {
                version: &version,
                installed: &installed,
            },
            &first,
            &second,
        ),
        SharedBaseOutcome::composed(&first, &second),
        "a session throttle planned on the same base must compose with the first and outlive its lift"
    );
}

/// Installed effect ids in effect-id order. The store lists contributions by
/// action first.
fn capability_set_effect_ids(
    store: &SqliteSecurityStateStore,
    key: &CapabilitySetSuspensionKey,
) -> Vec<String> {
    let mut ids: Vec<String> =
        chio_security_types::ports::CapabilitySetSuspensionStore::load_capability_set_suspensions(
            store, key,
        )
        .unwrap_or_else(|error| panic!("load capability-set suspensions: {error}"))
        .map(|snapshot| {
            snapshot
                .contributions
                .as_slice()
                .iter()
                .map(|entry| entry.effect_id.as_str().to_owned())
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

fn capability_set_version(
    store: &SqliteSecurityStateStore,
    key: &CapabilitySetSuspensionKey,
) -> Digest32 {
    let snapshot =
        chio_security_types::ports::CapabilitySetSuspensionStore::load_capability_set_suspensions(
            store, key,
        )
        .unwrap_or_else(|error| panic!("load capability-set suspensions: {error}"))
        .map_or_else(|| empty_capability_set_suspension_snapshot(key.clone()), Ok)
        .unwrap_or_else(|error| panic!("capability-set snapshot: {error}"));
    capability_set_suspension_version_hash(&snapshot)
        .unwrap_or_else(|error| panic!("capability-set version: {error}"))
}

/// Two plans that suspend one capability set. The executor applies a plan's
/// lineage freeze and its suspension in separate steps, so the second plan is
/// built after the first plan's freeze and before its suspension: it observes
/// the live freeze and the still empty suspension base, and its own freeze
/// applies before the first suspension does.
struct SharedCapabilitySet {
    first_plan: ResponsePlan,
    first_work: ScheduledWork,
    second_plan: ResponsePlan,
    second_work: ScheduledWork,
    key: CapabilitySetSuspensionKey,
}

impl SharedCapabilitySet {
    fn frozen(fixture: &ProductionEffectsFixture, effects: &dyn EffectPort, label: &str) -> Self {
        let affected = ["capability-child", "capability-root"];
        let affected_ids = || affected.iter().map(|id| record(*id)).collect::<Vec<_>>();
        let first_action = format!("production-effects-{label}-first");
        let second_action = format!("production-effects-{label}-second");
        let (first_plan, first_work) = fixture.dispatch_with_ttl(
            &first_action,
            affected_ids(),
            vec![
                fixture.freeze_spec(&first_action),
                fixture.capability_set_spec(&affected),
            ],
            600_000,
        );
        let first_freeze = effects
            .execute(
                &LeasedEffect {
                    plan: &first_plan,
                    work: &first_work,
                    ordinal: 0,
                }
                .request(&format!("{label}-first-freeze")),
            )
            .unwrap_or_else(|error| panic!("first lineage freeze: {error}"));
        assert!(first_freeze.applied);
        let (second_plan, second_work) = fixture.dispatch_with_ttl(
            &second_action,
            affected_ids(),
            vec![
                fixture.live_freeze_spec(&second_action),
                fixture.capability_set_spec(&affected),
            ],
            3_600_000,
        );
        let second_freeze = effects
            .execute(
                &LeasedEffect {
                    plan: &second_plan,
                    work: &second_work,
                    ordinal: 0,
                }
                .request(&format!("{label}-second-freeze")),
            )
            .map(|result| result.applied)
            .map_err(|error| error.kind());
        assert_eq!(
            second_freeze,
            Ok(true),
            "the second plan's freeze observed the live freeze and applies"
        );
        let ResponseTarget::CapabilitySet { affected_set_hash } = first_plan
            .effects
            .as_slice()
            .get(1)
            .unwrap_or_else(|| panic!("first suspension missing"))
            .target
        else {
            panic!("capability-set suspension targets a capability set");
        };
        Self {
            first_plan,
            first_work,
            second_plan,
            second_work,
            key: CapabilitySetSuspensionKey {
                tenant_id: tenant(),
                affected_set_hash,
            },
        }
    }

    fn first(&self) -> LeasedEffect<'_> {
        LeasedEffect {
            plan: &self.first_plan,
            work: &self.first_work,
            ordinal: 1,
        }
    }

    fn second(&self) -> LeasedEffect<'_> {
        LeasedEffect {
            plan: &self.second_plan,
            work: &self.second_work,
            ordinal: 1,
        }
    }
}

#[test]
fn capability_set_suspensions_planned_on_one_base_both_hold() {
    let fixture = ProductionEffectsFixture::new();
    let effects = fixture.effects();
    let shared = SharedCapabilitySet::frozen(&fixture, effects.as_ref(), "shared-capability");
    let (first, second) = (shared.first(), shared.second());
    let version = || capability_set_version(&fixture.store, &shared.key);
    let installed = || capability_set_effect_ids(&fixture.store, &shared.key);
    assert_eq!(
        shared_base_outcome(
            effects.as_ref(),
            &SharedKey {
                version: &version,
                installed: &installed,
            },
            &first,
            &second,
        ),
        SharedBaseOutcome::composed(&first, &second),
        "a capability-set suspension planned on the same base must compose with the first and outlive its lift"
    );
}

#[test]
fn production_plan_binding_admits_exact_rollback_and_refuses_rebound_commitments() {
    let fixture = ProductionEffectsFixture::new();
    let planned_session = session("production-effects-binding-session");
    let other_session = session("production-effects-binding-other-session");
    let (plan, work) = fixture.dispatch(
        "production-effects-binding-action",
        vec![record(planned_session.as_str())],
        vec![fixture.egress_spec(&planned_session, &["server-a"])],
    );
    let effects = fixture.effects();
    let planned = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("planned egress effect missing"));
    let apply = effect_request(&plan, planned, &work, "binding-apply");
    let applied = effects
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply planned egress: {error}"));
    assert!(applied.applied);

    let other_contribution = fixture.egress_spec(&planned_session, &["server-b"]);
    let rebound: Vec<(&str, EffectRequest)> = vec![
        ("plan hash", {
            let mut request = effect_request(&plan, planned, &work, "binding-plan-hash");
            request.plan_hash = digest(b"another-plan");
            request
        }),
        ("plan expiry", {
            let mut request = effect_request(&plan, planned, &work, "binding-plan-expiry");
            request.plan_expires_at_unix_ms = plan.expires_at_unix_ms.saturating_add(1);
            request
        }),
        ("contribution", {
            let mut request = effect_request(&plan, planned, &work, "binding-contribution");
            request.canonical_contribution = other_contribution.canonical_contribution.clone();
            request.contribution_hash = other_contribution.contribution_hash;
            request
        }),
        ("target", {
            let mut request = effect_request(&plan, planned, &work, "binding-target");
            request.target = ResponseTarget::Session {
                session_id: other_session.clone(),
            };
            request
        }),
        ("apply base", {
            let mut request = effect_request(&plan, planned, &work, "binding-apply-base");
            request.expected_version_hash = applied.resulting_version_hash;
            request
        }),
    ];
    for (label, request) in &rebound {
        let refused = effects
            .execute(request)
            .err()
            .unwrap_or_else(|| panic!("rebound {label} was accepted"));
        assert_eq!(refused.kind(), PortErrorKind::IntegrityFailure, "{label}");
        let unreadable = effects
            .load_result(&query(request))
            .err()
            .unwrap_or_else(|| panic!("rebound {label} result was readable"));
        assert_eq!(
            unreadable.kind(),
            PortErrorKind::IntegrityFailure,
            "{label}"
        );
    }

    let mut remove = effect_request(&plan, planned, &work, "binding-remove");
    remove.operation = EffectOperation::Remove;
    remove.expected_version_hash = applied.resulting_version_hash;
    let removed = effects
        .execute(&remove)
        .unwrap_or_else(|error| panic!("remove planned egress: {error}"));
    assert!(!removed.applied);
    assert_eq!(
        effects
            .load_result(&query(&remove))
            .unwrap_or_else(|error| panic!("load planned removal: {error}")),
        chio_security_types::ports::EffectExecutionStatus::Completed { result: removed }
    );
}

#[test]
fn unbound_effect_router_never_reports_ready() {
    use crate::security::adapters::effect_port::{
        ActiveResponseEffectPort, CapabilitySetSuspensionBackend, EscalateAlertBackend,
        EscalateAlertStore, IssuanceFreezeBackend, ResponseEffectBackend,
        RestrictEgressOverlayBackend, SessionSuspensionOverlayBackend, SessionThrottleBackend,
    };
    let fixture = ProductionEffectsFixture::new();
    let alerts: Arc<dyn EscalateAlertStore> = fixture.outbox.clone();
    let blast: Arc<dyn BlastRadiusPort> = fixture.resolver.clone();
    let backends: Vec<Arc<dyn ResponseEffectBackend>> = vec![
        Arc::new(EscalateAlertBackend::with_clock(
            alerts,
            Arc::clone(&fixture.trusted_clock),
        )),
        Arc::new(SessionThrottleBackend::new(fixture.store.clone())),
        Arc::new(RestrictEgressOverlayBackend::new(fixture.store.clone())),
        Arc::new(SessionSuspensionOverlayBackend::new(fixture.store.clone())),
        Arc::new(CapabilitySetSuspensionBackend::new(fixture.store.clone())),
        Arc::new(
            IssuanceFreezeBackend::new_with_scheduler(
                fixture.store.clone(),
                blast,
                fixture.store.clone(),
            )
            .with_clock(Arc::clone(&fixture.trusted_clock)),
        ),
    ];
    let unbound = ActiveResponseEffectPort::from_backends(backends)
        .unwrap_or_else(|error| panic!("unbound router: {error}"));
    let unready = unbound
        .ensure_effects_ready()
        .err()
        .unwrap_or_else(|| panic!("an unbound router reported ready"));
    assert_eq!(unready.kind(), PortErrorKind::Unavailable);
    let bound = unbound.with_plan_authority(fixture.store.clone());
    bound
        .ensure_effects_ready()
        .unwrap_or_else(|error| panic!("bound router readiness: {error}"));
}

#[test]
fn session_suspension_composition_keeps_its_refusals() {
    let fixture = ProductionEffectsFixture::new();
    let shared_session = session("production-effects-suspension-controls-session");
    let first_spec = fixture.ranked_session_suspension_spec(&shared_session, 3);
    let second_spec = fixture.ranked_session_suspension_spec(&shared_session, 8);
    let (first_plan, first_work) = fixture.dispatch(
        "production-effects-suspension-controls-first",
        vec![record(shared_session.as_str())],
        vec![first_spec],
    );
    let (second_plan, second_work) = fixture.dispatch(
        "production-effects-suspension-controls-second",
        vec![record(shared_session.as_str())],
        vec![second_spec],
    );
    let effects = fixture.effects();
    let first_effect = first_plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("first suspension missing"));
    let second_effect = second_plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("second suspension missing"));

    let first_applied = effects
        .execute(&effect_request(
            &first_plan,
            first_effect,
            &first_work,
            "suspension-controls-first",
        ))
        .unwrap_or_else(|error| panic!("healthy single suspension: {error}"));
    assert!(first_applied.applied);
    assert_eq!(effective_posture_rank(&fixture.store, &shared_session), 3);

    let reissued = effects
        .execute(&effect_request(
            &first_plan,
            first_effect,
            &first_work,
            "suspension-controls-first-reissued",
        ))
        .err()
        .unwrap_or_else(|| panic!("an installed suspension accepted a second command"));
    assert_eq!(reissued.kind(), PortErrorKind::Conflict);

    let tamper =
        rusqlite::Connection::open(fixture._directory.path().join("production-effects.db"))
            .unwrap_or_else(|error| panic!("open tamper connection: {error}"));
    let tampered = tamper
        .execute(
            "UPDATE security_effect_contributions SET posture_rank = 7 WHERE effect_id = ?1",
            rusqlite::params![first_effect.effect_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("tamper first contribution: {error}"));
    assert_eq!(tampered, 1);
    let refused = effects
        .execute(&effect_request(
            &second_plan,
            second_effect,
            &second_work,
            "suspension-controls-second",
        ))
        .err()
        .unwrap_or_else(|| panic!("a suspension composed onto a tampered overlay"));
    assert_eq!(refused.kind(), PortErrorKind::IntegrityFailure);
    let restored = tamper
        .execute(
            "UPDATE security_effect_contributions SET posture_rank = 3 WHERE effect_id = ?1",
            rusqlite::params![first_effect.effect_id.as_str()],
        )
        .unwrap_or_else(|error| panic!("restore first contribution: {error}"));
    assert_eq!(restored, 1);
    assert_eq!(effective_posture_rank(&fixture.store, &shared_session), 3);
}

/// Refusals and removal scope a composed second contribution must keep.
#[derive(Debug, Eq, PartialEq)]
struct CompositionRefusals {
    rebased_onto_live_version: Result<bool, PortErrorKind>,
    stale_scheduler_fence: Result<bool, PortErrorKind>,
    installed_after_refusals: Vec<String>,
    composed: Result<bool, PortErrorKind>,
    installed_after_second_lift: Vec<String>,
}

impl CompositionRefusals {
    fn kept(first: &LeasedEffect<'_>) -> Self {
        Self {
            rebased_onto_live_version: Err(PortErrorKind::IntegrityFailure),
            stale_scheduler_fence: Err(PortErrorKind::Conflict),
            installed_after_refusals: vec![first.id()],
            composed: Ok(true),
            installed_after_second_lift: vec![first.id()],
        }
    }
}

/// With the first contribution installed, send the second plan's command
/// rebased onto the live version and under a stale scheduler fence, then
/// compose it and lift it again.
fn composition_refusals(
    effects: &dyn EffectPort,
    key: &SharedKey<'_>,
    first: &LeasedEffect<'_>,
    second: &LeasedEffect<'_>,
) -> CompositionRefusals {
    let outcome = |request: &EffectRequest| {
        effects
            .execute(request)
            .map(|result| result.applied)
            .map_err(|error| error.kind())
    };
    let first_applied = effects
        .execute(&first.request("composition-controls-first"))
        .unwrap_or_else(|error| panic!("healthy single contribution: {error}"));
    assert!(first_applied.applied);
    assert_eq!((key.installed)(), vec![first.id()]);

    let mut rebased = second.request("composition-controls-rebased");
    rebased.expected_version_hash = (key.version)();
    let rebased_onto_live_version = outcome(&rebased);
    let mut stale_fence = second.request("composition-controls-stale-fence");
    stale_fence.scheduler_fencing_token = second.work.fencing_token.saturating_add(1);
    let stale_scheduler_fence = outcome(&stale_fence);
    let installed_after_refusals = (key.installed)();

    let composed = effects.execute(&second.request("composition-controls-second"));
    if let Ok(result) = &composed {
        let mut lift = second.request("composition-controls-lift-second");
        lift.operation = EffectOperation::Remove;
        lift.expected_version_hash = result.resulting_version_hash;
        let lifted = effects
            .execute(&lift)
            .unwrap_or_else(|error| panic!("lift the second contribution: {error}"));
        assert!(!lifted.applied);
    }
    CompositionRefusals {
        rebased_onto_live_version,
        stale_scheduler_fence,
        installed_after_refusals,
        composed: composed
            .map(|result| result.applied)
            .map_err(|error| error.kind()),
        installed_after_second_lift: (key.installed)(),
    }
}

#[test]
fn egress_restriction_composition_keeps_its_refusals() {
    let fixture = ProductionEffectsFixture::new();
    let shared_session = session("production-effects-egress-controls-session");
    let (first_plan, first_work) = fixture.dispatch(
        "production-effects-egress-controls-first",
        vec![record(shared_session.as_str())],
        vec![fixture.egress_spec(&shared_session, &["server-a"])],
    );
    let (second_plan, second_work) = fixture.dispatch(
        "production-effects-egress-controls-second",
        vec![record(shared_session.as_str())],
        vec![fixture.egress_spec(&shared_session, &["server-b"])],
    );
    let first = LeasedEffect {
        plan: &first_plan,
        work: &first_work,
        ordinal: 0,
    };
    let second = LeasedEffect {
        plan: &second_plan,
        work: &second_work,
        ordinal: 0,
    };
    let egress_key = EgressRestrictionSessionKey {
        tenant_id: tenant(),
        session_id: shared_session.clone(),
    };
    let version = || {
        egress_restriction_version_hash(fixture.store.as_ref(), &egress_key)
            .unwrap_or_else(|error| panic!("egress version: {error}"))
    };
    let installed = || egress_effect_ids(&fixture.store, &egress_key);
    let effects = fixture.effects();
    assert_eq!(
        composition_refusals(
            effects.as_ref(),
            &SharedKey {
                version: &version,
                installed: &installed,
            },
            &first,
            &second,
        ),
        CompositionRefusals::kept(&first)
    );
}

#[test]
fn session_throttle_composition_keeps_its_refusals() {
    let fixture = ProductionEffectsFixture::new();
    let shared_session = session("production-effects-throttle-controls-session");
    let throttle = |max_invocations: u32| {
        let mut spec = fixture.throttle_spec(&shared_session);
        let (canonical_contribution, contribution_hash) = canonical(&SessionThrottleLimits {
            window_ms: 5_000,
            max_invocations,
        });
        spec.canonical_contribution = canonical_contribution;
        spec.contribution_hash = contribution_hash;
        spec
    };
    let (first_plan, first_work) = fixture.dispatch(
        "production-effects-throttle-controls-first",
        vec![record(shared_session.as_str())],
        vec![throttle(10)],
    );
    let (second_plan, second_work) = fixture.dispatch(
        "production-effects-throttle-controls-second",
        vec![record(shared_session.as_str())],
        vec![throttle(3)],
    );
    let first = LeasedEffect {
        plan: &first_plan,
        work: &first_work,
        ordinal: 0,
    };
    let second = LeasedEffect {
        plan: &second_plan,
        work: &second_work,
        ordinal: 0,
    };
    let throttle_key = SessionThrottleKey {
        tenant_id: tenant(),
        session_id: shared_session.clone(),
    };
    let version = || throttle_version(&fixture.store, &throttle_key);
    let installed = || throttle_effect_ids(&fixture.store, &throttle_key);
    let effects = fixture.effects();
    assert_eq!(
        composition_refusals(
            effects.as_ref(),
            &SharedKey {
                version: &version,
                installed: &installed,
            },
            &first,
            &second,
        ),
        CompositionRefusals::kept(&first)
    );
}

#[test]
fn capability_set_suspension_composition_keeps_its_refusals() {
    let fixture = ProductionEffectsFixture::new();
    let effects = fixture.effects();
    let shared = SharedCapabilitySet::frozen(&fixture, effects.as_ref(), "capability-controls");
    let (first, second) = (shared.first(), shared.second());
    let version = || capability_set_version(&fixture.store, &shared.key);
    let installed = || capability_set_effect_ids(&fixture.store, &shared.key);
    assert_eq!(
        composition_refusals(
            effects.as_ref(),
            &SharedKey {
                version: &version,
                installed: &installed,
            },
            &first,
            &second,
        ),
        CompositionRefusals::kept(&first)
    );
}

#[test]
fn effect_router_without_plan_authority_refuses_commands_and_result_queries() {
    use crate::security::adapters::effect_port::{
        ActiveResponseEffectPort, ResponseEffectBackend, RestrictEgressOverlayBackend,
    };
    let fixture = ProductionEffectsFixture::new();
    let planned_session = session("production-effects-unbound-planned-session");
    let unplanned_session = session("production-effects-unbound-unplanned-session");
    let (plan, work) = fixture.dispatch(
        "production-effects-unbound-action",
        vec![record(planned_session.as_str())],
        vec![fixture.egress_spec(&planned_session, &["server-a"])],
    );
    let request = unplanned_request(
        &plan,
        fixture.egress_spec(&unplanned_session, &["server-b"]),
        &work,
        "unbound-unplanned-egress",
    );
    let outside_plan = fixture
        .effects()
        .execute(&request)
        .err()
        .unwrap_or_else(|| panic!("the bound router accepted an effect outside the plan"));
    assert_eq!(
        outside_plan.kind(),
        PortErrorKind::IntegrityFailure,
        "the request names no effect of the durable plan"
    );
    let backend: Arc<dyn ResponseEffectBackend> =
        Arc::new(RestrictEgressOverlayBackend::new(fixture.store.clone()));
    let unbound = ActiveResponseEffectPort::from_backends(vec![backend])
        .unwrap_or_else(|error| panic!("unbound router: {error}"));
    let unready = unbound
        .ensure_effects_ready()
        .err()
        .unwrap_or_else(|| panic!("an unbound router reported ready"));
    assert_eq!(unready.kind(), PortErrorKind::Unavailable);
    let unplanned_key = EgressRestrictionSessionKey {
        tenant_id: tenant(),
        session_id: unplanned_session.clone(),
    };
    assert_eq!(
        egress_effect_ids(&fixture.store, &unplanned_key),
        Vec::<String>::new()
    );

    let refusal = |error: PortError| (error.kind(), error.code().as_str().to_owned());
    let missing_authority = (
        PortErrorKind::Unavailable,
        "response.effect_plan_authority_missing".to_owned(),
    );
    assert_eq!(
        (
            unbound
                .execute(&request)
                .map(|result| result.applied)
                .map_err(refusal),
            unbound
                .load_result(&query(&request))
                .map(|status| {
                    matches!(
                        status,
                        chio_security_types::ports::EffectExecutionStatus::Completed { .. }
                    )
                })
                .map_err(refusal),
            egress_effect_ids(&fixture.store, &unplanned_key),
        ),
        (
            Err(missing_authority.clone()),
            Err(missing_authority),
            Vec::<String>::new()
        ),
        "a router without the durable plan authority must refuse every command and result query"
    );
}

#[test]
fn bound_effect_router_keeps_plan_binding_and_routing_refusals() {
    use crate::security::adapters::effect_port::{
        ActiveResponseEffectPort, ResponseEffectBackend, RestrictEgressOverlayBackend,
    };
    let fixture = ProductionEffectsFixture::new();
    let planned_session = session("production-effects-bound-planned-session");
    let unplanned_session = session("production-effects-bound-unplanned-session");
    let (plan, work) = fixture.dispatch(
        "production-effects-bound-action",
        vec![record(planned_session.as_str())],
        vec![fixture.egress_spec(&planned_session, &["server-a"])],
    );
    let router = || {
        let backend: Arc<dyn ResponseEffectBackend> =
            Arc::new(RestrictEgressOverlayBackend::new(fixture.store.clone()));
        ActiveResponseEffectPort::from_backends(vec![backend])
            .unwrap_or_else(|error| panic!("egress router: {error}"))
    };
    let refusal = |error: PortError| (error.kind(), error.code().as_str().to_owned());

    let unrouted = unplanned_request(
        &plan,
        fixture.throttle_spec(&planned_session),
        &work,
        "bound-unrouted-throttle",
    );
    assert_eq!(
        router()
            .execute(&unrouted)
            .map(|result| result.applied)
            .map_err(refusal),
        Err((PortErrorKind::Unavailable, "store.unavailable".to_owned())),
        "a kind without a backend keeps its routing refusal"
    );

    let bound = router().with_plan_authority(fixture.store.clone());
    let planned = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("planned egress effect missing"));
    let planned_request = effect_request(&plan, planned, &work, "bound-planned-egress");
    let applied = bound
        .execute(&planned_request)
        .unwrap_or_else(|error| panic!("bound router applies the planned egress: {error}"));
    assert!(applied.applied);
    assert_eq!(
        bound
            .load_result(&query(&planned_request))
            .unwrap_or_else(|error| panic!("bound router reads the planned result: {error}")),
        chio_security_types::ports::EffectExecutionStatus::Completed { result: applied }
    );

    let unplanned = unplanned_request(
        &plan,
        fixture.egress_spec(&unplanned_session, &["server-b"]),
        &work,
        "bound-unplanned-egress",
    );
    assert_eq!(
        (
            bound
                .execute(&unplanned)
                .map(|result| result.applied)
                .map_err(|error| error.kind()),
            bound
                .load_result(&query(&unplanned))
                .map(|status| {
                    matches!(
                        status,
                        chio_security_types::ports::EffectExecutionStatus::Completed { .. }
                    )
                })
                .map_err(|error| error.kind()),
            egress_effect_ids(
                &fixture.store,
                &EgressRestrictionSessionKey {
                    tenant_id: tenant(),
                    session_id: unplanned_session.clone(),
                },
            ),
        ),
        (
            Err(PortErrorKind::IntegrityFailure),
            Err(PortErrorKind::IntegrityFailure),
            Vec::<String>::new()
        ),
        "a bound router still refuses effects outside the durable plan"
    );
}
