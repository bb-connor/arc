use chio_quarantine::CausalBlastRadiusResolver;
use chio_security_types::ports::{
    LineageFenceStore, ResponseDispatchCommitOutcome, ResponseDispatchStore, TenantScopedId,
};
use chio_store_sqlite::SqliteSecurityStateStore;

use super::fence_lapse::{
    lineage_snapshot, worker, PersistFaultFreezes, SqliteFences, StaticLineage,
};
use super::*;

const DUPLICATE_FENCE_REFUSAL: &str =
    "response plan shape is invalid: response plan contains more than one issuance fence";

/// What a dispatched two-freeze plan does to the one fence its action owns.
#[derive(Debug, Eq, PartialEq)]
struct SharedFenceObservation {
    dispatch_committed: bool,
    first_freeze_applied: bool,
    second_freeze_apply: Result<bool, PortErrorKind>,
    fence_live_after_second_failure: bool,
    first_freeze_still_installed: bool,
}

fn freeze_effect(spec: &IssuanceFreezeSpec) -> ResponseEffectSpec {
    let body = canonical_json_bytes(spec).unwrap_or_else(|error| panic!("freeze spec: {error}"));
    let empty = empty_issuance_freeze_snapshot(IssuanceFreezeKey {
        tenant_id: tenant(),
        lineage_id: spec.lineage_id.clone(),
    })
    .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    ResponseEffectSpec {
        kind: ResponseEffectKind::FreezeIssuance,
        target: ResponseTarget::Lineage {
            lineage_id: spec.lineage_id.clone(),
        },
        canonical_contribution: CanonicalBody::new(body.clone())
            .unwrap_or_else(|error| panic!("freeze body: {error}")),
        contribution_hash: digest(&body),
        observed_base_version_hash: issuance_freeze_version_hash(&empty)
            .unwrap_or_else(|error| panic!("empty freeze version: {error}")),
    }
}

fn planned_apply(plan: &ResponsePlan, ordinal: usize, work: &ScheduledWork) -> EffectRequest {
    let effect = plan
        .effects
        .as_slice()
        .get(ordinal)
        .unwrap_or_else(|| panic!("planned freeze {ordinal} missing"));
    EffectRequest {
        tenant_id: plan.tenant_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        effect_id: effect.effect_id.clone(),
        effect_kind: effect.kind,
        target: effect.target.clone(),
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        operation: EffectOperation::Apply,
        idempotency_key: record(format!(
            "response_effect_command:duplicate-freeze-{ordinal}"
        )),
        expected_version_hash: effect.observed_base_version_hash,
        scheduler_lease_owner_id: work.lease_owner_id.clone(),
        scheduler_fencing_token: work.fencing_token,
        canonical_contribution: effect.canonical_contribution.clone(),
        contribution_hash: effect.contribution_hash,
    }
}

fn shared_fence_consequence(
    store: &Arc<SqliteSecurityStateStore>,
    blast: Arc<dyn BlastRadiusPort>,
    plan: ResponsePlan,
) -> SharedFenceObservation {
    let dispatch = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        authorization_capability_hash: plan.operator_capability.capability_digest,
        plan: chio_security_types::FreshLiveAdmission::new(plan.clone())
            .unwrap_or_else(|error| panic!("live plan: {error}")),
        dispatch_id: record("duplicate-freeze-dispatch"),
        governed_intent_hash: digest(b"duplicate-freeze-intent"),
        policy_decision_hash: digest(b"duplicate-freeze-decision"),
        admission_artifact_fingerprint: Some(digest(b"duplicate-freeze-artifact")),
        executor_authority_id: record("duplicate-freeze-authority"),
        executor_authority_generation: 1,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms: plan.created_at_unix_ms,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: worker("duplicate-freeze-worker"),
            lease_expires_at_unix_ms: plan.created_at_unix_ms.saturating_add(10_000),
        },
    })
    .unwrap_or_else(|error| panic!("prepare two-freeze dispatch: {error}"));
    super::fence_lapse::claim_automatic_preparation(store, &plan, &dispatch);
    let ResponseDispatchCommitOutcome::Committed(committed) = store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("commit two-freeze dispatch: {error}"))
    else {
        panic!("fresh two-freeze dispatch unexpectedly existed");
    };
    let work = committed.initial_work;
    let freezes = Arc::new(PersistFaultFreezes::new(Arc::clone(store)));
    let freeze_port: Arc<dyn IssuanceFreezeStore> = freezes.clone();
    let scheduler_port: Arc<dyn ResponseSchedulerStore> = store.clone();
    let backend = IssuanceFreezeBackend::new_with_scheduler(freeze_port, blast, scheduler_port);

    let first = planned_apply(&plan, 0, &work);
    let first_freeze_applied = backend
        .execute(&first)
        .unwrap_or_else(|error| panic!("apply first freeze: {error:?}"))
        .applied;
    freezes.fail_next_apply();
    let second_freeze_apply = backend
        .execute(&planned_apply(&plan, 1, &work))
        .map(|result| result.applied)
        .map_err(|error| error.kind());
    let fence_live_after_second_failure = LineageFenceStore::query(
        store.as_ref(),
        &TenantScopedId {
            tenant_id: tenant(),
            id: record(action().as_str()),
        },
    )
    .unwrap_or_else(|error| panic!("query action fence: {error}"))
    .is_some();
    let first_freeze_still_installed = store
        .load_issuance_freezes(&key())
        .unwrap_or_else(|error| panic!("load first freeze: {error}"))
        .is_some_and(|snapshot| {
            snapshot
                .contributions
                .as_slice()
                .iter()
                .any(|entry| entry.effect_id == first.effect_id)
        });
    SharedFenceObservation {
        dispatch_committed: true,
        first_freeze_applied,
        second_freeze_apply,
        fence_live_after_second_failure,
        first_freeze_still_installed,
    }
}

#[test]
fn a_plan_with_two_issuance_freezes_is_refused_before_it_can_share_one_fence() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("duplicate-freeze.db"))
            .unwrap_or_else(|error| panic!("open SQLite security store: {error}")),
    );
    let resolver = Arc::new(CausalBlastRadiusResolver::new(
        Arc::new(StaticLineage(lineage_snapshot())),
        Arc::new(SqliteFences(Arc::clone(&store))),
    ));
    let created_at_unix_ms = now_unix_ms();
    let root_request = BlastRadiusRequest {
        tenant_id: tenant(),
        action_id: action(),
        seed_ids: BlastRadiusSeeds::new(vec![record(lineage().as_str())])
            .unwrap_or_else(|error| panic!("root seeds: {error}")),
        query_bounds: BlastRadiusQueryBounds {
            max_depth: 8,
            max_nodes: 128,
            max_edges: 256,
        },
    };
    let approved_result = resolver.resolve(&root_request);
    let BlastRadiusResult::Exact {
        sorted_affected_ids,
        ..
    } = &approved_result
    else {
        panic!("static lineage did not resolve exactly: {approved_result:?}");
    };
    let affected_ids = sorted_affected_ids.as_slice().to_vec();
    let fence_expires_at_unix_ms = created_at_unix_ms.saturating_add(30_000);
    let root_freeze = IssuanceFreezeSpec {
        lineage_id: lineage(),
        acquisition: BlastRadiusFenceAcquisition {
            request: root_request.clone(),
            approved_result: approved_result.clone(),
            expires_at_unix_ms: fence_expires_at_unix_ms,
        },
    };
    let child_lineage =
        LineageId::new("capability-child").unwrap_or_else(|error| panic!("child: {error}"));
    let child_freeze = IssuanceFreezeSpec {
        lineage_id: child_lineage.clone(),
        acquisition: BlastRadiusFenceAcquisition {
            request: BlastRadiusRequest {
                seed_ids: BlastRadiusSeeds::new(vec![record(child_lineage.as_str())])
                    .unwrap_or_else(|error| panic!("child seeds: {error}")),
                ..root_request
            },
            approved_result,
            expires_at_unix_ms: fence_expires_at_unix_ms,
        },
    };
    let input = ResponsePlanInput {
        execution: chio_security_types::ResponseExecutionBinding::new(
            chio_security_types::ResponseExecutionMode::Live,
        ),
        action_id: action(),
        trigger_finding_id: record("duplicate-freeze-finding"),
        trigger_finding_hash: digest(b"duplicate-freeze-finding"),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("duplicate-freeze-receipt")
            .unwrap_or_else(|error| panic!("finding receipt: {error}")),
        tenant_id: tenant(),
        policy_version: record("duplicate-freeze-policy"),
        policy_hash: digest(b"duplicate-freeze-policy"),
        affected_ids,
        effects: vec![freeze_effect(&root_freeze), freeze_effect(&child_freeze)],
        ttl_ms: 120_000,
        created_at_unix_ms,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record("duplicate-freeze-capability"),
            capability_digest: digest(b"duplicate-freeze-capability"),
            expires_at_unix_ms: created_at_unix_ms.saturating_add(300_000),
            executor_subject: record("duplicate-freeze-executor"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record("duplicate-freeze-submitter"),
        reason_hash: digest(b"duplicate-freeze-reason"),
    };

    let blast: Arc<dyn BlastRadiusPort> = resolver;
    let (refusal, consequence) = match build_response_plan(input) {
        Err(error) => (Some(error.to_string()), None),
        Ok(plan) => (None, Some(shared_fence_consequence(&store, blast, plan))),
    };
    assert_eq!(
        (refusal.as_deref(), consequence),
        (Some(DUPLICATE_FENCE_REFUSAL), None),
        "a second FreezeIssuance must be refused at plan validation, before its failure can \
         release the fence the first freeze still holds"
    );
}
