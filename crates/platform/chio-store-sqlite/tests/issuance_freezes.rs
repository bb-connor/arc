use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_quarantine::{
    build_response_plan, prepare_response_dispatch, EffectMutation, EffectMutationRequest,
    EffectReceiptContext, ExecutorError, ResponseDispatchPreparationRequest, ResponseScheduler,
    ResponseStateMachine, ResponseTransitionRequest, ScheduledResponseExecutor, SchedulerPolicy,
    SchedulerTickRequest,
};
use chio_security_types::ports::{
    empty_issuance_freeze_snapshot, issuance_freeze_installed_version_hash,
    issuance_freeze_version_hash, predict_issuance_freeze_apply, predict_issuance_freeze_remove,
    response_affected_set_hash, ActionId, AlertDeliveryQuery, AlertDeliveryStatus,
    BlastRadiusFenceAcquisition, BlastRadiusQueryBounds, BlastRadiusRequest, BlastRadiusResult,
    BlastRadiusSeeds, BlastRadiusSnapshotMetadata, CanonicalBody, CapabilityIssuanceOperation,
    Digest32, EffectId, EffectOperation, EffectRequest, EffectResult, EffectResultQuery,
    IssuanceFreezeAdmissionQuery, IssuanceFreezeApplyRequest, IssuanceFreezeCommand,
    IssuanceFreezeContribution, IssuanceFreezeFenceMaintenanceRequest, IssuanceFreezeKey,
    IssuanceFreezeOperationStatus, IssuanceFreezePendingRelease, IssuanceFreezeRemoveRequest,
    IssuanceFreezeSnapshot, IssuanceFreezeSpec, IssuanceFreezeStore, LeaseOwnerId, LineageFence,
    LineageFenceMaintenanceOutcome, LineageFenceMaintenanceRequest, LineageId,
    MaintainedLineageFence, OpaqueReceiptRef, PortError, PortErrorKind, PortResult, RecordId,
    RecordIdSet, ResponseDispatchApproval, ResponseDispatchCommitOutcome, ResponseDispatchLease,
    ResponseDispatchStore, ResponsePlanRecord, ResponseSchedulerStore, ResponseStore,
    ScheduledWork, SchedulerClaimRequest, SchedulerHealthPageRequest, SchedulerHealthPort,
    SchedulerLeaseReleaseRequest, SchedulerWorkKey, SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec,
    ResponsePlan, ResponsePlanInput, ResponseState, ResponseTarget,
};
use chio_store_sqlite::SqliteSecurityStateStore;
use tempfile::tempdir;

fn now_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before epoch: {error}"));
    u64::try_from(elapsed.as_millis()).unwrap_or_else(|error| panic!("clock range: {error}"))
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn tenant() -> TenantId {
    TenantId::new("tenant-issuance-freeze").unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn lineage() -> LineageId {
    LineageId::new("capability-root").unwrap_or_else(|error| panic!("lineage id: {error}"))
}

fn action(value: &str) -> ActionId {
    ActionId::new(value).unwrap_or_else(|error| panic!("action id: {error}"))
}

fn effect(value: &str) -> EffectId {
    EffectId::new(value).unwrap_or_else(|error| panic!("effect id: {error}"))
}

fn record(value: impl Into<String>) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn affected() -> RecordIdSet {
    RecordIdSet::new(vec![record("capability-child"), record("capability-root")])
        .unwrap_or_else(|error| panic!("affected set: {error}"))
}

fn key() -> IssuanceFreezeKey {
    IssuanceFreezeKey {
        tenant_id: tenant(),
        lineage_id: lineage(),
    }
}

fn open_claimed_store(
    path: &Path,
    actions: &[&str],
) -> (SqliteSecurityStateStore, Vec<ScheduledWork>) {
    let store = SqliteSecurityStateStore::open(path)
        .unwrap_or_else(|error| panic!("open SQLite store: {error}"));
    let now = now_unix_ms();
    for action_name in actions {
        let canonical_body =
            CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan: {error}"));
        store
            .create(&ResponsePlanRecord {
                tenant_id: tenant(),
                action_id: action(action_name),
                generation: 0,
                state: record("active"),
                body_hash: digest(canonical_body.as_bytes()),
                canonical_body,
                due_at_unix_ms: Some(now.saturating_sub(1)),
            })
            .unwrap_or_else(|error| panic!("create response plan: {error}"));
    }
    let work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant(),
            claim_id: record("issuance-freeze-claim"),
            lease_owner_id: LeaseOwnerId::new("issuance-freeze-worker")
                .unwrap_or_else(|error| panic!("lease owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(120_000),
            max_claims: u32::try_from(actions.len())
                .unwrap_or_else(|error| panic!("claim count: {error}")),
        })
        .unwrap_or_else(|error| panic!("claim response plans: {error}"));
    assert_eq!(work.len(), actions.len());
    (store, work)
}

fn work_for<'a>(work: &'a [ScheduledWork], action_id: &ActionId) -> &'a ScheduledWork {
    work.iter()
        .find(|entry| &entry.action_id == action_id)
        .unwrap_or_else(|| panic!("scheduled work missing for {action_id:?}"))
}

fn wait_until_retry_due(store: &SqliteSecurityStateStore, action_id: &ActionId) {
    let retry = store
        .load_retry(&SchedulerWorkKey {
            tenant_id: tenant(),
            action_id: action_id.clone(),
        })
        .unwrap_or_else(|error| panic!("load scheduler retry: {error}"))
        .unwrap_or_else(|| panic!("scheduler retry missing"));
    let wait_ms = retry
        .not_before_unix_ms
        .saturating_sub(now_unix_ms())
        .saturating_add(25);
    assert!(wait_ms <= 1_000, "scheduler retry wait exceeded test bound");
    std::thread::sleep(std::time::Duration::from_millis(wait_ms));
}

#[derive(Default)]
struct FenceMaintenanceExecutor {
    events: Mutex<Vec<&'static str>>,
}

impl FenceMaintenanceExecutor {
    fn events(&self) -> Vec<&'static str> {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl ScheduledResponseExecutor for FenceMaintenanceExecutor {
    fn execute_scheduled(
        &self,
        current: &ResponsePlanRecord,
        _work: &ScheduledWork,
        _now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| ExecutorError::Store(PortError::unavailable()))?;
        if events.last() != Some(&"maintenance") {
            return Err(ExecutorError::InvalidEffectJournal);
        }
        events.push("active");
        Ok(current.clone())
    }

    fn maintain_lineage_fences(
        &self,
        request: &LineageFenceMaintenanceRequest,
    ) -> PortResult<LineageFenceMaintenanceOutcome> {
        self.events
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push("maintenance");
        let maintained = request
            .effect_ids
            .iter()
            .map(|effect_id| {
                let effect = request
                    .plan
                    .effect(effect_id)
                    .filter(|effect| effect.kind == ResponseEffectKind::FreezeIssuance)
                    .ok_or_else(PortError::invalid_data)?;
                let spec: IssuanceFreezeSpec =
                    serde_json::from_slice(effect.canonical_contribution.as_bytes())
                        .map_err(|_| PortError::integrity_failure())?;
                let BlastRadiusResult::Exact {
                    metadata,
                    affected_set_hash,
                    ..
                } = spec.acquisition.approved_result
                else {
                    return Err(PortError::integrity_failure());
                };
                Ok(MaintainedLineageFence {
                    effect_id: effect.effect_id.clone(),
                    fence: LineageFence {
                        tenant_id: request.plan.tenant_id.clone(),
                        action_id: request.plan.action_id.clone(),
                        commit_index: metadata.commit_index,
                        affected_set_hash,
                        fencing_token: 901,
                        scheduler_lease_owner_id: request.scheduler_work.lease_owner_id.clone(),
                        scheduler_fencing_token: request.scheduler_work.fencing_token,
                        expires_at_unix_ms: request.renewed_expires_at_unix_ms,
                    },
                })
            })
            .collect::<PortResult<Vec<_>>>()?;
        Ok(LineageFenceMaintenanceOutcome {
            maintained,
            completed_releases: Vec::new(),
        })
    }
}

struct NoopSchedulerHealth;

impl SchedulerHealthPort for NoopSchedulerHealth {
    fn ensure_scheduler_health_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn page_once(&self, request: &SchedulerHealthPageRequest) -> PortResult<AlertDeliveryStatus> {
        Ok(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: request.occurred_at_unix_ms,
        })
    }

    fn load_delivery(
        &self,
        _query: &AlertDeliveryQuery,
    ) -> PortResult<Option<AlertDeliveryStatus>> {
        Ok(None)
    }
}

fn scheduler_plan(
    action_id: ActionId,
    created_at_unix_ms: u64,
    ttl_ms: u64,
    effect: ResponseEffectSpec,
) -> ResponsePlan {
    build_response_plan(ResponsePlanInput {
        action_id,
        trigger_finding_id: record("issuance-freeze-horizon-finding"),
        trigger_finding_hash: digest(b"issuance-freeze-horizon-finding"),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("issuance-freeze-horizon-receipt")
            .unwrap_or_else(|error| panic!("finding receipt: {error}")),
        tenant_id: tenant(),
        policy_version: record("issuance-freeze-horizon-policy"),
        policy_hash: digest(b"issuance-freeze-horizon-policy"),
        affected_ids: vec![record("capability-child"), record("capability-root")],
        effects: vec![effect],
        ttl_ms,
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record("issuance-freeze-horizon-capability"),
            capability_digest: digest(b"issuance-freeze-horizon-capability"),
            expires_at_unix_ms: created_at_unix_ms
                .saturating_add(ttl_ms)
                .saturating_add(30_000),
            executor_subject: record("issuance-freeze-horizon-executor"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record("issuance-freeze-horizon-submitter"),
        reason_hash: digest(b"issuance-freeze-horizon-reason"),
    })
    .unwrap_or_else(|error| panic!("build scheduler plan: {error}"))
}

fn commit_applying_plan(
    store: &Arc<SqliteSecurityStateStore>,
    plan: ResponsePlan,
    dispatch_id: &str,
) -> (ResponsePlanRecord, ScheduledWork) {
    let authorized_at_unix_ms = plan.created_at_unix_ms;
    let request = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        authorization_capability_hash: plan.operator_capability.capability_digest,
        plan,
        dispatch_id: record(dispatch_id),
        governed_intent_hash: digest(format!("intent:{dispatch_id}").as_bytes()),
        policy_decision_hash: digest(format!("decision:{dispatch_id}").as_bytes()),
        executor_authority_id: record("issuance-freeze-horizon-authority"),
        executor_authority_generation: 1,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: LeaseOwnerId::new("issuance-freeze-worker")
                .unwrap_or_else(|error| panic!("initial lease owner: {error}")),
            lease_expires_at_unix_ms: authorized_at_unix_ms.saturating_add(5_000),
        },
        commit_mode: chio_security_types::ports::ResponseDispatchCommitMode::Fresh,
    })
    .unwrap_or_else(|error| panic!("prepare response dispatch: {error}"));
    let outcome = store
        .commit_dispatch(&request)
        .unwrap_or_else(|error| panic!("commit response dispatch: {error}"));
    let ResponseDispatchCommitOutcome::Committed(committed) = outcome else {
        panic!("new dispatch unexpectedly existed");
    };
    (committed.response_plan, committed.initial_work)
}

fn mark_plan_effect_applied(
    store: &Arc<SqliteSecurityStateStore>,
    applying: ResponsePlanRecord,
    work: &ScheduledWork,
) -> ResponsePlanRecord {
    let machine = ResponseStateMachine::new(Arc::clone(store));
    let snapshot = chio_quarantine::decode_response_record(&applying)
        .unwrap_or_else(|error| panic!("decode applying plan: {error}"));
    let planned_effect = snapshot
        .plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("planned effect missing"));
    let requested = machine
        .record_effect_with_receipt_scheduled(
            &applying,
            work,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: planned_effect.effect_id.clone(),
                occurred_at_unix_ms: snapshot.plan.created_at_unix_ms.saturating_add(1),
                mutation: EffectMutation::Requested,
            },
            &EffectReceiptContext {
                effect_generation: 1,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("record effect request: {error}"));
    let applied = machine
        .record_effect_with_receipt_scheduled(
            &requested,
            work,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: planned_effect.effect_id.clone(),
                occurred_at_unix_ms: snapshot.plan.created_at_unix_ms.saturating_add(2),
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(b"issuance-freeze-horizon-installed"),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: Some(work.lease_owner_id.clone()),
                scheduler_fencing_token: work.fencing_token,
                effect_transition_id: Some(record(format!(
                    "issuance-freeze-effect-applied:{}",
                    planned_effect.effect_id.as_str()
                ))),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("record effect application: {error}"));
    applied
}

fn mark_plan_active(
    store: &Arc<SqliteSecurityStateStore>,
    applying: ResponsePlanRecord,
    work: &ScheduledWork,
) -> ResponsePlanRecord {
    let applied = mark_plan_effect_applied(store, applying, work);
    let machine = ResponseStateMachine::new(Arc::clone(store));
    let snapshot = chio_quarantine::decode_response_record(&applied)
        .unwrap_or_else(|error| panic!("decode applied plan: {error}"));
    let active = machine
        .transition_scheduled(
            &applied,
            work,
            &ResponseTransitionRequest {
                expected_generation: applied.generation,
                target_state: ResponseState::Active,
                occurred_at_unix_ms: snapshot.plan.created_at_unix_ms.saturating_add(3),
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("activate response plan: {error}"));
    store
        .release_lease(&SchedulerLeaseReleaseRequest {
            work: work.clone(),
            clear_retry_state: true,
            transition_id: record(format!(
                "issuance-freeze-release-initial:{}",
                work.action_id.as_str()
            )),
        })
        .unwrap_or_else(|error| panic!("release initial response lease: {error}"));
    active
}

fn apply_request(
    action_id: ActionId,
    effect_id: EffectId,
    current: &IssuanceFreezeSnapshot,
    scheduler_fencing_token: u64,
    external_fencing_token: u64,
    suffix: &str,
) -> IssuanceFreezeApplyRequest {
    let frozen_affected_ids = affected();
    let affected_set_hash = response_affected_set_hash(&tenant(), &frozen_affected_ids)
        .unwrap_or_else(|error| panic!("affected set hash: {error}"));
    let plan_expires_at_unix_ms = now_unix_ms().saturating_add(30_000);
    let external_fence_expires_at_unix_ms = plan_expires_at_unix_ms.saturating_sub(10_000);
    let bounds = BlastRadiusQueryBounds {
        max_depth: 8,
        max_nodes: 128,
        max_edges: 256,
    };
    let blast_request = BlastRadiusRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        seed_ids: BlastRadiusSeeds::new(vec![record(lineage().as_str())])
            .unwrap_or_else(|error| panic!("blast seeds: {error}")),
        query_bounds: bounds.clone(),
    };
    let approved_result = BlastRadiusResult::Exact {
        metadata: BlastRadiusSnapshotMetadata {
            query_bounds: bounds,
            source_lineage_version: 5,
            commit_index: 17,
            authoritative_commit_index: 17,
            completeness_watermark: Some(17),
        },
        sorted_affected_ids: frozen_affected_ids.clone(),
        affected_set_hash,
        graph_slice_hash: Digest32::new([7_u8; 32]),
    };
    let spec = IssuanceFreezeSpec {
        lineage_id: lineage(),
        acquisition: BlastRadiusFenceAcquisition {
            request: blast_request,
            approved_result,
            expires_at_unix_ms: external_fence_expires_at_unix_ms,
        },
    };
    let canonical =
        canonical_json_bytes(&spec).unwrap_or_else(|error| panic!("freeze spec: {error}"));
    let contribution_hash = digest(&canonical);
    let request = EffectRequest {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        plan_hash: digest(format!("plan:{suffix}").as_bytes()),
        effect_id: effect_id.clone(),
        effect_kind: ResponseEffectKind::FreezeIssuance,
        target: ResponseTarget::Lineage {
            lineage_id: lineage(),
        },
        plan_expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!("response_effect_command:{suffix}")),
        expected_version_hash: issuance_freeze_version_hash(current)
            .unwrap_or_else(|error| panic!("base freeze version: {error}")),
        scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
            "issuance-freeze-worker",
        )
        .unwrap_or_else(|error| panic!("lease owner: {error}")),
        scheduler_fencing_token,
        canonical_contribution: CanonicalBody::new(canonical)
            .unwrap_or_else(|error| panic!("freeze contribution: {error}")),
        contribution_hash,
    };
    let external_fence = LineageFence {
        tenant_id: tenant(),
        action_id: action_id.clone(),
        commit_index: 17,
        affected_set_hash,
        fencing_token: external_fencing_token,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token,
        expires_at_unix_ms: external_fence_expires_at_unix_ms,
    };
    let contribution = IssuanceFreezeContribution {
        action_id,
        effect_id: effect_id.clone(),
        commit_index: 17,
        affected_set_hash,
        frozen_affected_ids,
        graph_slice_hash: Digest32::new([7_u8; 32]),
        external_fence,
        contribution_hash,
        expires_at_unix_ms: plan_expires_at_unix_ms,
    };
    let resulting_snapshot =
        predict_issuance_freeze_apply(current, &contribution, scheduler_fencing_token)
            .unwrap_or_else(|error| panic!("predict freeze apply: {error}"));
    IssuanceFreezeApplyRequest {
        key: current.key.clone(),
        contribution: contribution.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: IssuanceFreezeCommand {
            request,
            result: EffectResult {
                effect_id,
                resulting_version_hash: issuance_freeze_installed_version_hash(
                    &current.key,
                    &contribution,
                )
                .unwrap_or_else(|error| panic!("installed freeze version: {error}")),
                applied: true,
            },
            resulting_snapshot,
        },
    }
}

fn bind_apply_to_plan_and_work(
    mut apply: IssuanceFreezeApplyRequest,
    current: &IssuanceFreezeSnapshot,
    plan: &ResponsePlan,
    work: &ScheduledWork,
) -> IssuanceFreezeApplyRequest {
    let planned_effect = plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("freeze plan effect missing"));
    apply.contribution.action_id = plan.action_id.clone();
    apply.contribution.effect_id = planned_effect.effect_id.clone();
    apply.contribution.external_fence.action_id = plan.action_id.clone();
    apply.contribution.external_fence.scheduler_lease_owner_id = work.lease_owner_id.clone();
    apply.contribution.external_fence.scheduler_fencing_token = work.fencing_token;
    apply.scheduler_fencing_token = work.fencing_token;
    apply.command.request.action_id = plan.action_id.clone();
    apply.command.request.plan_hash = plan.plan_hash;
    apply.command.request.effect_id = planned_effect.effect_id.clone();
    apply.command.request.scheduler_lease_owner_id = work.lease_owner_id.clone();
    apply.command.request.scheduler_fencing_token = work.fencing_token;
    apply.command.result = EffectResult {
        effect_id: planned_effect.effect_id.clone(),
        resulting_version_hash: issuance_freeze_installed_version_hash(
            &apply.key,
            &apply.contribution,
        )
        .unwrap_or_else(|error| panic!("bound installed freeze version: {error}")),
        applied: true,
    };
    apply.command.resulting_snapshot =
        predict_issuance_freeze_apply(current, &apply.contribution, work.fencing_token)
            .unwrap_or_else(|error| panic!("predict bound freeze apply: {error}"));
    apply
}

fn remove_request(
    apply: &IssuanceFreezeApplyRequest,
    current: &IssuanceFreezeSnapshot,
    scheduler_fencing_token: u64,
    suffix: &str,
) -> IssuanceFreezeRemoveRequest {
    let mut request = apply.command.request.clone();
    request.operation = EffectOperation::Remove;
    request.idempotency_key = record(format!("response_effect_command:{suffix}"));
    request.expected_version_hash = apply.command.result.resulting_version_hash;
    request.scheduler_fencing_token = scheduler_fencing_token;
    let resulting_snapshot = predict_issuance_freeze_remove(
        current,
        &apply.contribution.action_id,
        &apply.contribution.effect_id,
        scheduler_fencing_token,
    )
    .unwrap_or_else(|error| panic!("predict freeze remove: {error}"));
    IssuanceFreezeRemoveRequest {
        key: apply.key.clone(),
        action_id: apply.contribution.action_id.clone(),
        effect_id: apply.contribution.effect_id.clone(),
        expected_generation: current.generation,
        scheduler_fencing_token,
        command: IssuanceFreezeCommand {
            request,
            result: EffectResult {
                effect_id: apply.contribution.effect_id.clone(),
                resulting_version_hash: issuance_freeze_version_hash(&resulting_snapshot)
                    .unwrap_or_else(|error| panic!("removed freeze version: {error}")),
                applied: false,
            },
            resulting_snapshot,
        },
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
        contribution_hash: request.contribution_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
    }
}

fn require_error<T>(result: Result<T, PortError>) -> PortError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn overlapping_freezes_remain_active_until_each_release_completes() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("issuance-freeze-overlap.db");
    let first_action = action("issuance-freeze-action-first");
    let second_action = action("issuance-freeze-action-second");
    let (store, work) = open_claimed_store(&path, &[first_action.as_str(), second_action.as_str()]);
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    let first = apply_request(
        first_action.clone(),
        effect("issuance-freeze-effect-first"),
        &empty,
        work_for(&work, &first_action).fencing_token,
        101,
        "issuance-freeze-apply-first",
    );
    let after_first = store
        .apply_issuance_freeze(&first)
        .unwrap_or_else(|error| panic!("apply first freeze: {error}"));
    let second = apply_request(
        second_action.clone(),
        effect("issuance-freeze-effect-second"),
        &after_first,
        work_for(&work, &second_action).fencing_token,
        102,
        "issuance-freeze-apply-second",
    );
    let after_second = store
        .apply_issuance_freeze(&second)
        .unwrap_or_else(|error| panic!("apply second freeze: {error}"));
    let admission = IssuanceFreezeAdmissionQuery {
        tenant_id: tenant(),
        lineage_id: lineage(),
        operation: CapabilityIssuanceOperation::Delegate,
        parent_capability_id: Some(record("capability-root")),
    };
    assert_eq!(
        store
            .evaluate_issuance_freeze(&admission)
            .unwrap_or_else(|error| panic!("evaluate overlapping freeze: {error}"))
            .active_matches
            .len(),
        2
    );

    let remove_first = remove_request(
        &first,
        &after_second,
        work_for(&work, &first_action).fencing_token,
        "issuance-freeze-remove-first",
    );
    assert_eq!(
        store
            .prepare_issuance_freeze_remove(&remove_first)
            .unwrap_or_else(|error| panic!("prepare first release: {error}")),
        first.contribution
    );
    assert_eq!(
        store
            .evaluate_issuance_freeze(&admission)
            .unwrap_or_else(|error| panic!("evaluate pending release: {error}"))
            .active_matches
            .len(),
        2
    );
    let after_remove_first = store
        .complete_issuance_freeze_remove(&remove_first)
        .unwrap_or_else(|error| panic!("complete first release: {error}"));
    assert_eq!(after_remove_first.contributions.len(), 1);
    assert_eq!(
        store
            .evaluate_issuance_freeze(&admission)
            .unwrap_or_else(|error| panic!("evaluate remaining freeze: {error}"))
            .active_matches
            .len(),
        1
    );

    let remove_second = remove_request(
        &second,
        &after_remove_first,
        work_for(&work, &second_action).fencing_token,
        "issuance-freeze-remove-second",
    );
    store
        .prepare_issuance_freeze_remove(&remove_second)
        .unwrap_or_else(|error| panic!("prepare second release: {error}"));
    store
        .complete_issuance_freeze_remove(&remove_second)
        .unwrap_or_else(|error| panic!("complete second release: {error}"));
    assert!(
        !store
            .evaluate_issuance_freeze(&admission)
            .unwrap_or_else(|error| panic!("evaluate lifted freeze: {error}"))
            .frozen
    );
}

#[test]
fn pending_release_and_completed_journal_survive_restart() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("issuance-freeze-restart.db");
    let action_id = action("issuance-freeze-action-restart");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect("issuance-freeze-effect-restart"),
        &empty,
        work_for(&work, &action_id).fencing_token,
        201,
        "issuance-freeze-apply-restart",
    );
    let after_apply = store
        .apply_issuance_freeze(&apply)
        .unwrap_or_else(|error| panic!("apply restart freeze: {error}"));
    let remove = remove_request(
        &apply,
        &after_apply,
        work_for(&work, &action_id).fencing_token,
        "issuance-freeze-remove-restart",
    );
    store
        .prepare_issuance_freeze_remove(&remove)
        .unwrap_or_else(|error| panic!("prepare restart release: {error}"));
    drop(store);

    let reopened = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen freeze store: {error}"));
    assert_eq!(
        reopened.load_issuance_freeze_operation(&query(&remove.command.request)),
        Ok(IssuanceFreezeOperationStatus::ReleasePending {
            contribution: Box::new(apply.contribution.clone())
        })
    );
    assert_eq!(
        reopened.load_pending_issuance_freeze_release(
            &remove.key,
            &remove.action_id,
            &remove.effect_id,
        ),
        Ok(Some(IssuanceFreezePendingRelease {
            request: remove.clone(),
            contribution: apply.contribution.clone(),
        }))
    );
    let lifted = reopened
        .complete_issuance_freeze_remove(&remove)
        .unwrap_or_else(|error| panic!("complete release after restart: {error}"));
    assert!(lifted.contributions.is_empty());
    assert_eq!(
        reopened.load_issuance_freeze_operation(&query(&remove.command.request)),
        Ok(IssuanceFreezeOperationStatus::Completed {
            result: remove.command.result.clone()
        })
    );
    assert_eq!(
        reopened.complete_issuance_freeze_remove(&remove),
        Ok(lifted)
    );
    assert_eq!(
        reopened.load_pending_issuance_freeze_release(
            &remove.key,
            &remove.action_id,
            &remove.effect_id,
        ),
        Ok(None)
    );
    assert_eq!(
        reopened.load_completed_issuance_freeze_release(
            &remove.key,
            &remove.action_id,
            &remove.effect_id,
            remove.command.request.plan_hash,
        ),
        Ok(Some(remove.command))
    );
}

#[test]
fn stale_scheduler_rebinding_and_journal_tamper_fail_closed() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("issuance-freeze-hostile.db");
    let action_id = action("issuance-freeze-action-hostile");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect("issuance-freeze-effect-hostile"),
        &empty,
        work_for(&work, &action_id).fencing_token,
        301,
        "issuance-freeze-apply-hostile",
    );
    store
        .apply_issuance_freeze(&apply)
        .unwrap_or_else(|error| panic!("apply hostile freeze: {error}"));

    let stale = apply_request(
        action_id,
        effect("issuance-freeze-effect-hostile-stale"),
        &empty,
        apply.scheduler_fencing_token.saturating_add(1),
        302,
        "issuance-freeze-apply-hostile-stale",
    );
    assert_eq!(
        require_error(store.apply_issuance_freeze(&stale)).kind(),
        PortErrorKind::Conflict
    );
    let mut rebound = apply.clone();
    rebound.key.lineage_id = LineageId::new("capability-other")
        .unwrap_or_else(|error| panic!("rebound lineage: {error}"));
    assert_eq!(
        require_error(store.apply_issuance_freeze(&rebound)).kind(),
        PortErrorKind::InvalidData
    );

    let tamper = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("open freeze tamper connection: {error}"));
    tamper
        .execute(
            "UPDATE security_issuance_freeze_commands SET request_body = ?1",
            rusqlite::params![b"{}".as_slice()],
        )
        .unwrap_or_else(|error| panic!("tamper freeze command: {error}"));
    assert_eq!(
        require_error(store.load_issuance_freeze_operation(&query(&apply.command.request))).kind(),
        PortErrorKind::IntegrityFailure
    );
    assert_eq!(
        require_error(store.ensure_issuance_freezes_ready()).kind(),
        PortErrorKind::IntegrityFailure
    );
}

#[test]
fn apply_journal_reports_completed_not_generic_failure() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("issuance-freeze-apply-journal.db");
    let action_id = action("issuance-freeze-action-journal");
    let (store, work) = open_claimed_store(&path, &[action_id.as_str()]);
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect("issuance-freeze-effect-journal"),
        &empty,
        work_for(&work, &action_id).fencing_token,
        401,
        "issuance-freeze-apply-journal",
    );
    store
        .apply_issuance_freeze(&apply)
        .unwrap_or_else(|error| panic!("apply journal freeze: {error}"));
    let status = store
        .load_issuance_freeze_operation(&query(&apply.command.request))
        .unwrap_or_else(|error| panic!("load apply journal: {error}"));
    assert_eq!(
        status,
        IssuanceFreezeOperationStatus::Completed {
            result: apply.command.result
        }
    );
    assert!(!matches!(
        status,
        IssuanceFreezeOperationStatus::ReleasePending { .. }
    ));
}

#[test]
fn fence_maintenance_is_scheduler_fenced_idempotent_and_lifts_after_takeover() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("issuance-freeze-maintenance.db");
    let action_id = action("issuance-freeze-action-maintenance");
    let effect_id = effect("issuance-freeze-effect-maintenance");
    let (store, first_claim) = open_claimed_store(&path, &[action_id.as_str()]);
    let first_work = work_for(&first_claim, &action_id).clone();
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    let apply = apply_request(
        action_id.clone(),
        effect_id.clone(),
        &empty,
        first_work.fencing_token,
        501,
        "issuance-freeze-apply-maintenance",
    );
    let applied = store
        .apply_issuance_freeze(&apply)
        .unwrap_or_else(|error| panic!("apply maintained freeze: {error}"));
    let initial = applied.contributions.as_slice()[0].external_fence.clone();
    let mut renewed_fence = initial.clone();
    renewed_fence.expires_at_unix_ms = apply.contribution.expires_at_unix_ms.saturating_add(10_000);
    let renewal = IssuanceFreezeFenceMaintenanceRequest {
        key: key(),
        action_id: action_id.clone(),
        effect_id: effect_id.clone(),
        expected_external_fence: initial.clone(),
        maintained_external_fence: renewed_fence.clone(),
        scheduler_work: first_work.clone(),
    };
    let renewed = store
        .maintain_issuance_freeze_fence(&renewal)
        .unwrap_or_else(|error| panic!("persist periodic renewal: {error}"));
    assert_eq!(
        renewed.contributions.as_slice()[0].external_fence,
        renewed_fence
    );
    assert!(
        renewed.contributions.as_slice()[0]
            .external_fence
            .expires_at_unix_ms
            > renewed.contributions.as_slice()[0].expires_at_unix_ms
    );
    assert_eq!(
        store
            .maintain_issuance_freeze_fence(&renewal)
            .unwrap_or_else(|error| panic!("reconcile renewal acknowledgement: {error}")),
        renewed
    );

    store
        .release_lease(&SchedulerLeaseReleaseRequest {
            work: first_work.clone(),
            clear_retry_state: false,
            transition_id: record("issuance-freeze-release-first-worker"),
        })
        .unwrap_or_else(|error| panic!("release first scheduler lease: {error}"));
    let now = now_unix_ms();
    let second_work = store
        .claim_due(&SchedulerClaimRequest {
            tenant_id: tenant(),
            claim_id: record("issuance-freeze-takeover-claim"),
            lease_owner_id: LeaseOwnerId::new("issuance-freeze-takeover-worker")
                .unwrap_or_else(|error| panic!("takeover owner: {error}")),
            now_unix_ms: now,
            lease_expires_at_unix_ms: now.saturating_add(120_000),
            max_claims: 1,
        })
        .unwrap_or_else(|error| panic!("claim takeover work: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("takeover work missing"));
    assert!(second_work.fencing_token > first_work.fencing_token);
    let mut taken_over_fence = renewed_fence.clone();
    taken_over_fence.fencing_token = renewed_fence.fencing_token.saturating_add(1);
    taken_over_fence.scheduler_lease_owner_id = second_work.lease_owner_id.clone();
    taken_over_fence.scheduler_fencing_token = second_work.fencing_token;
    let takeover = IssuanceFreezeFenceMaintenanceRequest {
        key: key(),
        action_id: action_id.clone(),
        effect_id: effect_id.clone(),
        expected_external_fence: renewed_fence,
        maintained_external_fence: taken_over_fence.clone(),
        scheduler_work: second_work.clone(),
    };
    let taken_over = store
        .maintain_issuance_freeze_fence(&takeover)
        .unwrap_or_else(|error| panic!("persist scheduler takeover: {error}"));
    assert_eq!(
        taken_over.contributions.as_slice()[0].external_fence,
        taken_over_fence
    );
    assert_eq!(
        require_error(store.maintain_issuance_freeze_fence(&renewal)).kind(),
        PortErrorKind::Conflict
    );

    let mut remove = remove_request(
        &apply,
        &taken_over,
        second_work.fencing_token,
        "issuance-freeze-remove-maintenance",
    );
    remove.command.request.scheduler_lease_owner_id = second_work.lease_owner_id;
    let pending = store
        .prepare_issuance_freeze_remove(&remove)
        .unwrap_or_else(|error| panic!("prepare maintained freeze lift: {error}"));
    assert_eq!(pending.external_fence, taken_over_fence);
    let lifted = store
        .complete_issuance_freeze_remove(&remove)
        .unwrap_or_else(|error| panic!("complete maintained freeze lift: {error}"));
    assert!(lifted.contributions.is_empty());
}

#[test]
fn active_freeze_is_claimed_only_in_renewal_horizon_and_maintained_before_active() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("freeze-renewal-horizon.db"))
            .unwrap_or_else(|error| panic!("open horizon store: {error}")),
    );
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    let freeze_action = action("issuance-freeze-horizon-action");
    let provisional = apply_request(
        freeze_action.clone(),
        effect("issuance-freeze-horizon-provisional-effect"),
        &empty,
        1,
        77,
        "issuance-freeze-horizon-apply",
    );
    let freeze_created_at_unix_ms = provisional
        .contribution
        .expires_at_unix_ms
        .checked_sub(30_000)
        .unwrap_or_else(|| panic!("freeze plan TTL underflow"));
    let freeze_plan = scheduler_plan(
        freeze_action.clone(),
        freeze_created_at_unix_ms,
        30_000,
        ResponseEffectSpec {
            kind: ResponseEffectKind::FreezeIssuance,
            target: provisional.command.request.target.clone(),
            canonical_contribution: provisional.command.request.canonical_contribution.clone(),
            contribution_hash: provisional.command.request.contribution_hash,
            observed_base_version_hash: provisional.command.request.expected_version_hash,
        },
    );
    let (freeze_applying, freeze_initial_work) = commit_applying_plan(
        &store,
        freeze_plan.clone(),
        "issuance-freeze-horizon-dispatch",
    );
    let bound_apply =
        bind_apply_to_plan_and_work(provisional, &empty, &freeze_plan, &freeze_initial_work);
    store
        .apply_issuance_freeze(&bound_apply)
        .unwrap_or_else(|error| panic!("apply horizon freeze: {error}"));
    let freeze_active = mark_plan_active(&store, freeze_applying, &freeze_initial_work);

    let non_freeze_created_at_unix_ms = now_unix_ms();
    let non_freeze_body = CanonicalBody::new(b"{\"requests_per_minute\":1}".to_vec())
        .unwrap_or_else(|error| panic!("non-freeze contribution: {error}"));
    let non_freeze_plan = scheduler_plan(
        action("issuance-non-freeze-horizon-action"),
        non_freeze_created_at_unix_ms,
        30_000,
        ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: SessionId::new("issuance-non-freeze-horizon-session")
                    .unwrap_or_else(|error| panic!("non-freeze session: {error}")),
            },
            contribution_hash: digest(non_freeze_body.as_bytes()),
            canonical_contribution: non_freeze_body,
            observed_base_version_hash: digest(b"issuance-non-freeze-observed"),
        },
    );
    let (non_freeze_applying, non_freeze_initial_work) = commit_applying_plan(
        &store,
        non_freeze_plan,
        "issuance-non-freeze-horizon-dispatch",
    );
    let non_freeze_active = mark_plan_active(&store, non_freeze_applying, &non_freeze_initial_work);

    let trusted_now = now_unix_ms();
    assert!(freeze_active
        .due_at_unix_ms
        .is_some_and(|due_at| due_at > trusted_now));
    assert!(non_freeze_active
        .due_at_unix_ms
        .is_some_and(|due_at| due_at > trusted_now));
    assert!(
        bound_apply.contribution.external_fence.expires_at_unix_ms
            <= trusted_now.saturating_add(20_000)
    );

    let executor = Arc::new(FenceMaintenanceExecutor::default());
    let scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::clone(&executor),
        Arc::new(NoopSchedulerHealth),
        SchedulerPolicy {
            lease_duration_ms: 5_000,
            base_backoff_ms: 100,
            max_backoff_ms: 1_000,
            operator_page_threshold_ms: 5_000,
            max_claims: 4,
        },
    )
    .unwrap_or_else(|error| panic!("construct horizon scheduler: {error}"));
    let claimed = scheduler
        .claim(&SchedulerTickRequest {
            tenant_id: tenant(),
            claim_id: record("issuance-freeze-horizon-claim"),
            lease_owner_id: LeaseOwnerId::new("issuance-freeze-horizon-worker")
                .unwrap_or_else(|error| panic!("horizon worker: {error}")),
            now_unix_ms: trusted_now,
        })
        .unwrap_or_else(|error| panic!("claim horizon work: {error}"));
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].action_id, freeze_action);

    let outcome = scheduler
        .process(&claimed[0], trusted_now)
        .unwrap_or_else(|error| panic!("process horizon maintenance: {error}"));
    assert!(matches!(
        outcome,
        chio_quarantine::SchedulerWorkOutcome::Completed {
            state: ResponseState::Active,
            ..
        }
    ));
    assert_eq!(executor.events(), vec!["maintenance", "active"]);
}

#[test]
fn installed_freeze_is_maintained_while_applying_and_rolling_back_but_not_after_restore() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("freeze-installed-states.db"))
            .unwrap_or_else(|error| panic!("open installed-state store: {error}")),
    );
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    let freeze_action = action("issuance-freeze-installed-state-action");
    let provisional = apply_request(
        freeze_action.clone(),
        effect("issuance-freeze-installed-state-provisional-effect"),
        &empty,
        1,
        88,
        "issuance-freeze-installed-state-apply",
    );
    let created_at_unix_ms = provisional
        .contribution
        .expires_at_unix_ms
        .checked_sub(30_000)
        .unwrap_or_else(|| panic!("installed-state plan TTL underflow"));
    let plan = scheduler_plan(
        freeze_action,
        created_at_unix_ms,
        30_000,
        ResponseEffectSpec {
            kind: ResponseEffectKind::FreezeIssuance,
            target: provisional.command.request.target.clone(),
            canonical_contribution: provisional.command.request.canonical_contribution.clone(),
            contribution_hash: provisional.command.request.contribution_hash,
            observed_base_version_hash: provisional.command.request.expected_version_hash,
        },
    );
    let (applying, initial_work) = commit_applying_plan(
        &store,
        plan.clone(),
        "issuance-freeze-installed-state-dispatch",
    );
    let bound_apply = bind_apply_to_plan_and_work(provisional, &empty, &plan, &initial_work);
    store
        .apply_issuance_freeze(&bound_apply)
        .unwrap_or_else(|error| panic!("apply installed-state freeze: {error}"));
    let applied = mark_plan_effect_applied(&store, applying, &initial_work);

    let executor = Arc::new(FenceMaintenanceExecutor::default());
    let scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::clone(&executor),
        Arc::new(NoopSchedulerHealth),
        SchedulerPolicy {
            lease_duration_ms: 5_000,
            base_backoff_ms: 100,
            max_backoff_ms: 100,
            operator_page_threshold_ms: 5_000,
            max_claims: 1,
        },
    )
    .unwrap_or_else(|error| panic!("construct installed-state scheduler: {error}"));

    scheduler
        .process(&initial_work, now_unix_ms())
        .unwrap_or_else(|error| panic!("maintain applying freeze: {error}"));
    assert_eq!(executor.events(), vec!["maintenance", "active"]);
    wait_until_retry_due(&store, &initial_work.action_id);

    let rollback_now = now_unix_ms();
    let rollback_work = scheduler
        .claim(&SchedulerTickRequest {
            tenant_id: tenant(),
            claim_id: record("issuance-freeze-installed-state-rollback-claim"),
            lease_owner_id: LeaseOwnerId::new("issuance-freeze-installed-state-worker")
                .unwrap_or_else(|error| panic!("rollback worker: {error}")),
            now_unix_ms: rollback_now,
        })
        .unwrap_or_else(|error| panic!("claim rolling freeze: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("rolling freeze work missing"));

    let machine = ResponseStateMachine::new(Arc::clone(&store));
    let rolling_back = machine
        .handle_due_scheduled(
            &applied,
            &rollback_work,
            applied.generation,
            initial_work.lease_expires_at_unix_ms,
        )
        .unwrap_or_else(|error| panic!("expire applying freeze: {error}"));
    let rolling_snapshot = chio_quarantine::decode_response_record(&rolling_back)
        .unwrap_or_else(|error| panic!("decode rolling freeze: {error}"));
    let freeze_effect = rolling_snapshot
        .plan
        .effects
        .as_slice()
        .first()
        .unwrap_or_else(|| panic!("rolling freeze effect missing"));
    let rollback_requested = machine
        .record_effect_with_receipt_scheduled(
            &rolling_back,
            &rollback_work,
            &EffectMutationRequest {
                expected_generation: rolling_back.generation,
                effect_id: freeze_effect.effect_id.clone(),
                occurred_at_unix_ms: initial_work.lease_expires_at_unix_ms.saturating_add(1),
                mutation: EffectMutation::RollbackRequested,
            },
            &EffectReceiptContext {
                effect_generation: 3,
                scheduler_lease_owner_id: Some(rollback_work.lease_owner_id.clone()),
                scheduler_fencing_token: rollback_work.fencing_token,
                effect_transition_id: Some(record(
                    "issuance-freeze-installed-state-rollback-requested",
                )),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("record freeze rollback request: {error}"));
    scheduler
        .process(&rollback_work, now_unix_ms())
        .unwrap_or_else(|error| panic!("maintain rolling freeze: {error}"));
    assert_eq!(
        executor.events(),
        vec!["maintenance", "active", "maintenance", "active"]
    );
    wait_until_retry_due(&store, &rollback_work.action_id);
    let restoration_now = now_unix_ms();
    let restoration_work = scheduler
        .claim(&SchedulerTickRequest {
            tenant_id: tenant(),
            claim_id: record("issuance-freeze-installed-state-restoration-claim"),
            lease_owner_id: LeaseOwnerId::new("issuance-freeze-installed-state-restoration-worker")
                .unwrap_or_else(|error| panic!("restoration worker: {error}")),
            now_unix_ms: restoration_now,
        })
        .unwrap_or_else(|error| panic!("claim restored freeze: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("restored freeze work missing"));

    let restored = machine
        .record_effect_with_receipt_scheduled(
            &rollback_requested,
            &restoration_work,
            &EffectMutationRequest {
                expected_generation: rollback_requested.generation,
                effect_id: freeze_effect.effect_id.clone(),
                occurred_at_unix_ms: initial_work.lease_expires_at_unix_ms.saturating_add(2),
                mutation: EffectMutation::RollbackRestored {
                    resulting_version_hash: bound_apply.command.request.expected_version_hash,
                },
            },
            &EffectReceiptContext {
                effect_generation: 4,
                scheduler_lease_owner_id: Some(restoration_work.lease_owner_id.clone()),
                scheduler_fencing_token: restoration_work.fencing_token,
                effect_transition_id: Some(record(
                    "issuance-freeze-installed-state-rollback-restored",
                )),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|error| panic!("record restored freeze: {error}"));
    assert_eq!(
        chio_quarantine::decode_response_record(&restored)
            .unwrap_or_else(|error| panic!("decode restored freeze: {error}"))
            .state,
        ResponseState::RollingBack
    );
    scheduler
        .process(&restoration_work, now_unix_ms())
        .unwrap_or_else(|error| panic!("process restored freeze: {error}"));
    assert_eq!(
        executor.events(),
        vec!["maintenance", "active", "maintenance", "active"]
    );
}
