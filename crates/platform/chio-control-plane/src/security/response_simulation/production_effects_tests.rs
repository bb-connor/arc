use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_kernel::{prepare_response_dispatch, ResponseDispatchPreparationRequest};
use chio_quarantine::{build_response_plan, CausalBlastRadiusResolver};
use chio_security_types::clock::{Clock, FixedClock};
use chio_security_types::ports::{
    empty_issuance_freeze_snapshot, issuance_freeze_version_hash, BlastRadiusFenceAcquisition,
    BlastRadiusPort, BlastRadiusQueryBounds, BlastRadiusRequest, BlastRadiusResult,
    BlastRadiusSeeds, CanonicalBody, CausalLineageCommitMetadata, CausalLineageEdge,
    CausalLineageEdgeKind, CausalLineageEdges, CausalLineageFenceRequest, CausalLineageFenceStore,
    CausalLineageNode, CausalLineageNodeKind, CausalLineageNodes, CausalLineageSnapshot,
    CausalLineageSnapshotRequest, CausalLineageStore, Digest32, EffectOperation, EffectPort,
    EffectRequest, IssuanceFreezeKey, IssuanceFreezeSpec, LeaseOwnerId, LineageFence,
    LineageFenceRelease, LineageFenceRenewal, LineageFenceRequest, LineageFenceStore,
    LineageFenceTakeover, LineageId, OpaqueReceiptRef, PortError, PortResult, RecordId,
    ResponseDispatchApproval, ResponseDispatchCommitOutcome, ResponseDispatchLease,
    ResponseDispatchStore, ScheduledWork, TenantId, TenantScopedId,
};
use chio_security_types::{
    FreshLiveAdmission, OperatorCapabilityBinding, PlannedResponseEffect,
    ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec, ResponseExecutionBinding,
    ResponseExecutionMode, ResponsePlan, ResponsePlanInput, ResponseTarget,
};
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::SqliteSecurityStateStore;

use super::production_response_effects;
use crate::security::adapters::{AlertOutboxConfig, SqliteSiemOutbox};

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
        let directory =
            chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let trusted_now = wall_now_unix_ms().saturating_add(TRUSTED_SKEW_MS);
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
                expires_at_unix_ms: self.trusted_now.saturating_add(30_000),
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

    /// Commit a live automatic dispatch at trusted time and return the plan
    /// with the scheduler work that holds its lease.
    fn dispatch(
        &self,
        action_id: &str,
        affected_ids: Vec<RecordId>,
        effects: Vec<ResponseEffectSpec>,
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
            ttl_ms: 120_000,
            created_at_unix_ms: self.trusted_now,
            operator_capability: OperatorCapabilityBinding {
                capability_id: record("production-effects-capability"),
                capability_digest: digest(b"production-effects-capability"),
                expires_at_unix_ms: self.trusted_now.saturating_add(300_000),
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
