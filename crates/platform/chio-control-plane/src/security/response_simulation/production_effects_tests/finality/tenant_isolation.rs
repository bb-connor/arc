use chio_security_types::ports::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    predict_capability_set_suspension_apply, predict_capability_set_suspension_remove,
    CapabilitySetSuspensionApplyRequest, CapabilitySetSuspensionCommand,
    CapabilitySetSuspensionContribution, CapabilitySetSuspensionRemoveRequest,
    CapabilitySetSuspensionSnapshot, CapabilitySetSuspensionStore,
};

use super::*;

fn dispatch_other_tenant(case: &FinalityCase, other: &TenantId) -> (ResponsePlan, ScheduledWork) {
    let original = &case.plan;
    let ids = original.affected_ids.clone();
    let affected_set_hash = response_affected_set_hash(other, &ids)
        .unwrap_or_else(|error| panic!("other tenant affected set: {error}"));
    let mut freeze: IssuanceFreezeSpec = serde_json::from_slice(
        original.effects.as_slice()[0]
            .canonical_contribution
            .as_bytes(),
    )
    .unwrap_or_else(|error| panic!("original freeze spec: {error}"));
    freeze.acquisition.request.tenant_id = other.clone();
    if let BlastRadiusResult::Exact {
        affected_set_hash: hash,
        ..
    } = &mut freeze.acquisition.approved_result
    {
        *hash = affected_set_hash;
    } else {
        panic!("real exact freeze descriptor missing");
    }
    let (freeze_body, freeze_hash) = canonical(&freeze);
    let empty_freeze = empty_issuance_freeze_snapshot(IssuanceFreezeKey {
        tenant_id: other.clone(),
        lineage_id: lineage(),
    })
    .unwrap_or_else(|error| panic!("other empty freeze: {error}"));
    let empty = empty_capability_set_suspension_snapshot(CapabilitySetSuspensionKey {
        tenant_id: other.clone(),
        affected_set_hash,
    })
    .unwrap_or_else(|error| panic!("other empty suspension: {error}"));
    let original_suspend = &original.effects.as_slice()[1];
    let plan = build_response_plan(ResponsePlanInput {
        execution: original.execution,
        action_id: original.action_id.clone(),
        trigger_finding_id: original.trigger_finding_id.clone(),
        trigger_finding_hash: original.trigger_finding_hash,
        trigger_finding_receipt_id: original.trigger_finding_receipt_id.clone(),
        tenant_id: other.clone(),
        policy_version: original.policy_version.clone(),
        policy_hash: original.policy_hash,
        affected_ids: ids.as_slice().to_vec(),
        effects: vec![
            ResponseEffectSpec {
                kind: ResponseEffectKind::FreezeIssuance,
                target: ResponseTarget::Lineage {
                    lineage_id: lineage(),
                },
                canonical_contribution: freeze_body,
                contribution_hash: freeze_hash,
                observed_base_version_hash: issuance_freeze_version_hash(&empty_freeze)
                    .unwrap_or_else(|error| panic!("other freeze base: {error}")),
            },
            ResponseEffectSpec {
                kind: original_suspend.kind,
                target: ResponseTarget::CapabilitySet { affected_set_hash },
                canonical_contribution: original_suspend.canonical_contribution.clone(),
                contribution_hash: original_suspend.contribution_hash,
                observed_base_version_hash: capability_set_suspension_version_hash(&empty)
                    .unwrap_or_else(|error| panic!("other suspension base: {error}")),
            },
        ],
        ttl_ms: original.ttl_ms,
        created_at_unix_ms: original.created_at_unix_ms,
        operator_capability: original.operator_capability.clone(),
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: original.submitter.clone(),
        reason_hash: original.reason_hash,
    })
    .unwrap_or_else(|error| panic!("real other tenant plan: {error}"));
    assert_ne!(plan.plan_hash, original.plan_hash);
    let dispatch = prepare_response_dispatch(ResponseDispatchPreparationRequest {
        authorization_capability_hash: plan.operator_capability.capability_digest,
        plan: FreshLiveAdmission::new(plan.clone())
            .unwrap_or_else(|error| panic!("other live plan: {error}")),
        dispatch_id: record("tenant-isolation-dispatch"),
        governed_intent_hash: digest(b"tenant-isolation-intent"),
        policy_decision_hash: digest(b"tenant-isolation-decision"),
        admission_artifact_fingerprint: Some(digest(b"tenant-isolation-artifact")),
        executor_authority_id: record("tenant-isolation-authority"),
        executor_authority_generation: 1,
        approval: ResponseDispatchApproval::Automatic,
        authorized_at_unix_ms: case.fixture.trusted_now,
        initial_lease: ResponseDispatchLease {
            lease_owner_id: case.work.lease_owner_id.clone(),
            lease_expires_at_unix_ms: case.work.lease_expires_at_unix_ms,
        },
    })
    .unwrap_or_else(|error| panic!("other exact preparation: {error}"));
    claim_automatic_preparation(&case.fixture.store, &plan, &dispatch);
    let ResponseDispatchCommitOutcome::Committed(committed) = case
        .fixture
        .store
        .commit_dispatch(&dispatch)
        .unwrap_or_else(|error| panic!("other real dispatch: {error}"))
    else {
        panic!("other dispatch existed");
    };
    (plan, committed.initial_work)
}

fn apply_request(plan: &ResponsePlan, work: &ScheduledWork) -> EffectRequest {
    let mut request = effect_request(
        plan,
        &plan.effects.as_slice()[1],
        work,
        "tenant-shared-apply",
    );
    // This explicitly exercises the trusted STORE port's tenant-scoped keys.
    // It does not claim colliding kernel-derived effect IDs or route through
    // the kernel plan binding with a substituted ID.
    request.effect_id = chio_security_types::ports::EffectId::new("tenant-shared-effect")
        .unwrap_or_else(|error| panic!("shared store effect key: {error}"));
    request
}

fn key(request: &EffectRequest) -> CapabilitySetSuspensionKey {
    let ResponseTarget::CapabilitySet { affected_set_hash } = request.target else {
        panic!("capset target missing");
    };
    CapabilitySetSuspensionKey {
        tenant_id: request.tenant_id.clone(),
        affected_set_hash,
    }
}

fn current(
    store: &SqliteSecurityStateStore,
    request: &EffectRequest,
) -> CapabilitySetSuspensionSnapshot {
    store
        .load_capability_set_suspensions(&key(request))
        .unwrap_or_else(|error| panic!("tenant snapshot: {error}"))
        .map_or_else(
            || empty_capability_set_suspension_snapshot(key(request)),
            Ok,
        )
        .unwrap_or_else(|error| panic!("tenant empty snapshot: {error}"))
}

fn apply(store: &SqliteSecurityStateStore, request: &EffectRequest) -> EffectResult {
    let spec: CapabilitySetSuspensionSpec =
        serde_json::from_slice(request.canonical_contribution.as_bytes())
            .unwrap_or_else(|error| panic!("real contribution spec: {error}"));
    let desired = CapabilitySetSuspensionContribution {
        action_id: request.action_id.clone(),
        effect_id: request.effect_id.clone(),
        affected_ids: spec.affected_ids,
        contribution_hash: request.contribution_hash,
        expires_at_unix_ms: request.plan_expires_at_unix_ms,
    };
    let before = current(store, request);
    let predicted =
        predict_capability_set_suspension_apply(&before, &desired, request.scheduler_fencing_token)
            .unwrap_or_else(|error| panic!("typed predicted Apply: {error}"));
    let result = EffectResult {
        effect_id: request.effect_id.clone(),
        applied: true,
        resulting_version_hash: capability_set_suspension_installed_version_hash(
            &key(request),
            &desired,
        )
        .unwrap_or_else(|error| panic!("typed installed hash: {error}")),
    };
    let actual = store
        .apply_capability_set_suspension(&CapabilitySetSuspensionApplyRequest {
            key: key(request),
            contribution: desired,
            expected_generation: before.generation,
            scheduler_fencing_token: request.scheduler_fencing_token,
            command: CapabilitySetSuspensionCommand {
                request: request.clone(),
                result: result.clone(),
                resulting_snapshot: predicted.clone(),
            },
        })
        .unwrap_or_else(|error| panic!("real tenant Apply: {error}"));
    assert_eq!(actual, predicted);
    result
}

fn remove(
    store: &SqliteSecurityStateStore,
    apply: &EffectRequest,
    installed: &EffectResult,
) -> EffectRequest {
    let mut request = apply.clone();
    request.operation = EffectOperation::Remove;
    request.idempotency_key = record("response_effect_command:tenant-shared-remove");
    request.expected_version_hash = installed.resulting_version_hash;
    let before = current(store, &request);
    let predicted = predict_capability_set_suspension_remove(
        &before,
        &request.action_id,
        &request.effect_id,
        request.scheduler_fencing_token,
    )
    .unwrap_or_else(|error| panic!("typed predicted Remove: {error}"));
    let result = EffectResult {
        effect_id: request.effect_id.clone(),
        applied: false,
        resulting_version_hash: capability_set_suspension_version_hash(&predicted)
            .unwrap_or_else(|error| panic!("typed removal hash: {error}")),
    };
    let actual = store
        .remove_capability_set_suspension(&CapabilitySetSuspensionRemoveRequest {
            key: key(&request),
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            expected_generation: before.generation,
            scheduler_fencing_token: request.scheduler_fencing_token,
            command: CapabilitySetSuspensionCommand {
                request: request.clone(),
                result,
                resulting_snapshot: predicted.clone(),
            },
        })
        .unwrap_or_else(|error| panic!("real tenant Remove: {error}"));
    assert_eq!(actual, predicted);
    request
}

#[test]
fn finality_and_historical_witness_keep_identical_store_ids_isolated_across_tenants_and_restart() {
    let case = FinalityCase::new(ResponseEffectKind::SuspendCapabilitySet, "tenant-isolation");
    let tenant_b = TenantId::new("tenant-production-effects-b")
        .unwrap_or_else(|error| panic!("other tenant: {error}"));
    let (plan_b, work_b) = dispatch_other_tenant(&case, &tenant_b);
    let (a, b) = (
        apply_request(&case.plan, &case.work),
        apply_request(&plan_b, &work_b),
    );
    assert_ne!(a.tenant_id, b.tenant_id);
    assert_ne!(a.plan_hash, b.plan_hash);
    assert_eq!(a.action_id, b.action_id);
    assert_eq!(a.effect_id, b.effect_id);
    assert_eq!(a.idempotency_key, b.idempotency_key);
    let applied_a = apply(&case.fixture.store, &a);
    let removed_a = remove(&case.fixture.store, &a, &applied_a);
    let applied_b = apply(&case.fixture.store, &b);
    let reopened = SqliteSecurityStateStore::open_with_trusted_clock(
        case.fixture._directory.path().join("production-effects.db"),
        Arc::clone(&case.fixture.trusted_clock),
    )
    .unwrap_or_else(|error| panic!("real tenant restart: {error}"));
    let before = case.snapshot();
    let witness_a = reopened
        .load_completed_capability_set_suspension_remove(&query(&a))
        .unwrap_or_else(|error| panic!("tenant A witness: {error}"))
        .unwrap_or_else(|| panic!("tenant A authentic Remove absent"));
    assert_eq!(witness_a.request, removed_a);
    assert_eq!(
        reopened
            .load_completed_capability_set_suspension_remove(&query(&b))
            .unwrap_or_else(|error| panic!("active tenant B witness: {error}")),
        None
    );
    assert_eq!(current(&reopened, &b).contributions.len(), 1);
    assert_eq!(
        reopened
            .load_capability_set_suspension_result(&query(&b))
            .unwrap_or_else(|error| panic!("tenant B historical Apply: {error}")),
        EffectExecutionStatus::Completed {
            result: applied_b.clone()
        }
    );
    let mut foreign = query(&a);
    foreign.tenant_id = tenant_b;
    let error = reopened
        .load_completed_capability_set_suspension_remove(&foreign)
        .err()
        .unwrap_or_else(|| panic!("foreign tenant query authenticated the other removal"));
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(error.code().as_str(), "store.conflict");
    assert_eq!(case.snapshot(), before);
    let mut fresh_a = a.clone();
    fresh_a.idempotency_key = record("response_effect_command:tenant-shared-fresh");
    let spec: CapabilitySetSuspensionSpec =
        serde_json::from_slice(a.canonical_contribution.as_bytes())
            .unwrap_or_else(|error| panic!("original spec: {error}"));
    let desired = CapabilitySetSuspensionContribution {
        action_id: a.action_id.clone(),
        effect_id: a.effect_id.clone(),
        affected_ids: spec.affected_ids,
        contribution_hash: a.contribution_hash,
        expires_at_unix_ms: a.plan_expires_at_unix_ms,
    };
    let empty = current(&reopened, &a);
    let predicted =
        predict_capability_set_suspension_apply(&empty, &desired, a.scheduler_fencing_token)
            .unwrap_or_else(|error| panic!("fresh prediction: {error}"));
    let error = reopened
        .apply_capability_set_suspension(&CapabilitySetSuspensionApplyRequest {
            key: key(&a),
            contribution: desired,
            expected_generation: empty.generation,
            scheduler_fencing_token: a.scheduler_fencing_token,
            command: CapabilitySetSuspensionCommand {
                request: fresh_a,
                result: applied_a.clone(),
                resulting_snapshot: predicted,
            },
        })
        .err()
        .unwrap_or_else(|| panic!("tenant A finality was lost on restart"));
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(error.code().as_str(), "store.conflict");
    assert_eq!(case.snapshot(), before);
    let removed_b = remove(&reopened, &b, &applied_b);
    let before = case.snapshot();
    let witness_b = reopened
        .load_completed_capability_set_suspension_remove(&query(&b))
        .unwrap_or_else(|error| panic!("removed tenant B witness: {error}"))
        .unwrap_or_else(|| panic!("tenant B authentic Remove absent"));
    assert_eq!(witness_b.request, removed_b);
    assert_ne!(witness_b.request.plan_hash, witness_a.request.plan_hash);
    assert_eq!(
        reopened
            .load_completed_capability_set_suspension_remove(&query(&a))
            .unwrap_or_else(|error| panic!("unchanged tenant A witness: {error}")),
        Some(witness_a)
    );
    assert_eq!(case.snapshot(), before);
}
