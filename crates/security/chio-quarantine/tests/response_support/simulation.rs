use chio_core_types::{canonical_json_bytes, sha256};
use chio_quarantine::build_response_plan;
use chio_security_types::{ports::*, response_simulation::*, *};
use serde_json::json;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn id(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|e| panic!("identifier: {e}"))
}
fn digest(value: u8) -> Digest32 {
    Digest32::new([value; 32])
}

pub fn fixture(
    overlap_expiry: Option<u64>,
) -> TestResult<(ResponsePlan, ResponseSimulationSnapshot)> {
    let tenant_id = TenantId::new("simulation-tenant")?;
    let action_id = ActionId::new("simulation-action")?;
    let session_id = SessionId::new("session")?;
    let lineage_id = LineageId::new("root")?;
    let affected_ids = RecordIdSet::new(vec![id("root")])?;
    let affected_set_hash = response_affected_set_hash(&tenant_id, &affected_ids)?;
    let target = containment_session_target(&tenant_id, &session_id)?;
    let overlay = OverlaySnapshot {
        target,
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: BoundedVec::new(vec![])?,
        highest_fencing_token: 0,
    };
    let throttle = empty_session_throttle_snapshot(SessionThrottleKey {
        tenant_id: tenant_id.clone(),
        session_id: session_id.clone(),
    })?;
    let egress = empty_egress_restriction_snapshot(EgressRestrictionSessionKey {
        tenant_id: tenant_id.clone(),
        session_id: session_id.clone(),
    })?;
    let caps = empty_capability_set_suspension_snapshot(CapabilitySetSuspensionKey {
        tenant_id: tenant_id.clone(),
        affected_set_hash,
    })?;
    let issuance = empty_issuance_freeze_snapshot(IssuanceFreezeKey {
        tenant_id: tenant_id.clone(),
        lineage_id: lineage_id.clone(),
    })?;
    let mut states = vec![
        ResponseSimulationState::Suspension(overlay),
        ResponseSimulationState::Throttle(throttle),
        ResponseSimulationState::Egress(egress),
        ResponseSimulationState::CapabilitySet(caps),
        ResponseSimulationState::Issuance(issuance),
    ];
    let bounds = BlastRadiusQueryBounds {
        max_depth: 8,
        max_nodes: 16,
        max_edges: 16,
    };
    let scope = BlastRadiusResult::Exact {
        metadata: BlastRadiusSnapshotMetadata {
            query_bounds: bounds.clone(),
            source_lineage_version: 1,
            commit_index: 1,
            authoritative_commit_index: 1,
            completeness_watermark: Some(1),
        },
        sorted_affected_ids: affected_ids.clone(),
        affected_set_hash,
        graph_slice_hash: digest(8),
    };
    if let Some(expiry) = overlap_expiry {
        let other_effect = EffectId::new("overlapping-effect")?;
        let other_action = ActionId::new("overlapping-action")?;
        for state in &mut states {
            use ResponseSimulationState as S;
            *state = match state {
                S::Suspension(s) => S::Suspension(predict_containment_overlay_apply(
                    s,
                    &OverlayContribution {
                        effect_id: other_effect.clone(),
                        posture_rank: 9,
                        contribution_hash: digest(9),
                        expires_at_unix_ms: Some(expiry),
                    },
                    1,
                )?),
                S::Throttle(s) => S::Throttle(predict_session_throttle_apply(
                    s,
                    &SessionThrottleContribution {
                        effect_id: other_effect.clone(),
                        limits: SessionThrottleLimits {
                            window_ms: 1000,
                            max_invocations: 2,
                        },
                        contribution_hash: digest(9),
                        expires_at_unix_ms: expiry,
                    },
                    1,
                )?),
                S::Egress(s) => S::Egress(predict_egress_apply(
                    s,
                    &EgressRestrictionContribution {
                        effect_id: other_effect.clone(),
                        destinations: EgressDestinationSet::new(vec![DestinationId::new(
                            "shared",
                        )?])?,
                        contribution_hash: digest(9),
                        expires_at_unix_ms: expiry,
                    },
                    1,
                )?),
                S::CapabilitySet(s) => S::CapabilitySet(predict_capability_set_suspension_apply(
                    s,
                    &CapabilitySetSuspensionContribution {
                        action_id: other_action.clone(),
                        effect_id: other_effect.clone(),
                        affected_ids: affected_ids.clone(),
                        contribution_hash: digest(9),
                        expires_at_unix_ms: expiry,
                    },
                    1,
                )?),
                S::Issuance(s) => S::Issuance(predict_issuance_freeze_apply(
                    s,
                    &IssuanceFreezeContribution {
                        action_id: other_action.clone(),
                        effect_id: other_effect.clone(),
                        commit_index: 1,
                        affected_set_hash,
                        frozen_affected_ids: affected_ids.clone(),
                        graph_slice_hash: digest(8),
                        external_fence: LineageFence {
                            tenant_id: tenant_id.clone(),
                            action_id: other_action.clone(),
                            commit_index: 1,
                            affected_set_hash,
                            fencing_token: 1,
                            scheduler_lease_owner_id: LeaseOwnerId::new("other-worker")?,
                            scheduler_fencing_token: 1,
                            expires_at_unix_ms: expiry,
                        },
                        contribution_hash: digest(9),
                        expires_at_unix_ms: expiry,
                    },
                    1,
                )?),
            };
        }
    }
    let specs = [
        (
            ResponseEffectKind::SuspendSession,
            ResponseTarget::Session {
                session_id: session_id.clone(),
            },
            json!({"posture_rank": 3}),
        ),
        (
            ResponseEffectKind::ThrottleSession,
            ResponseTarget::Session {
                session_id: session_id.clone(),
            },
            json!({"window_ms": 1000, "max_invocations": 5}),
        ),
        (
            ResponseEffectKind::RestrictEgress,
            ResponseTarget::Session { session_id },
            json!({"destinations": ["shared", "target"]}),
        ),
        (
            ResponseEffectKind::SuspendCapabilitySet,
            ResponseTarget::CapabilitySet { affected_set_hash },
            json!({"affected_ids": affected_ids}),
        ),
        (
            ResponseEffectKind::FreezeIssuance,
            ResponseTarget::Lineage {
                lineage_id: lineage_id.clone(),
            },
            serde_json::to_value(IssuanceFreezeSpec {
                lineage_id,
                acquisition: BlastRadiusFenceAcquisition {
                    request: BlastRadiusRequest {
                        tenant_id: tenant_id.clone(),
                        action_id: action_id.clone(),
                        seed_ids: BoundedVec::new(vec![id("root")])?,
                        query_bounds: bounds,
                    },
                    approved_result: scope.clone(),
                    expires_at_unix_ms: 3000,
                },
            })?,
        ),
        (
            ResponseEffectKind::EscalateAlert,
            ResponseTarget::Tenant {
                tenant_id: tenant_id.clone(),
            },
            json!({"reason": "test"}),
        ),
    ];
    let mut effects = specs
        .into_iter()
        .enumerate()
        .map(
            |(i, (kind, target, body))| -> TestResult<ResponseEffectSpec> {
                let canonical = canonical_json_bytes(&body)?;
                Ok(ResponseEffectSpec {
                    kind,
                    target,
                    contribution_hash: Digest32::new(*sha256(&canonical).as_bytes()),
                    canonical_contribution: CanonicalBody::new(canonical)?,
                    observed_base_version_hash: if i < states.len() {
                        states[i].version_hash()?
                    } else {
                        digest(7)
                    },
                })
            },
        )
        .collect::<TestResult<Vec<_>>>()?;
    let freeze = effects.remove(4);
    effects.insert(0, freeze);
    let plan = build_response_plan(ResponsePlanInput {
        execution: ResponseExecutionBinding::new(ResponseExecutionMode::DryRun),
        action_id,
        trigger_finding_id: id("finding"),
        trigger_finding_hash: digest(1),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("finding-receipt")?,
        tenant_id: tenant_id.clone(),
        policy_version: id("policy"),
        policy_hash: digest(2),
        affected_ids: affected_ids.as_slice().to_vec(),
        effects,
        ttl_ms: 2000,
        created_at_unix_ms: 1000,
        operator_capability: OperatorCapabilityBinding {
            capability_id: id("capability"),
            capability_digest: digest(3),
            expires_at_unix_ms: 5000,
            executor_subject: id("executor"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: id("submitter"),
        reason_hash: digest(4),
    })?;
    let scope = ResponseSimulationScope {
        effect_id: plan.effects.as_slice()[0].effect_id.clone(),
        result: scope,
    };
    let snapshot = ResponseSimulationSnapshot {
        tenant_id,
        plan_hash: plan.plan_hash,
        captured_at_unix_ms: 1000,
        states: BoundedVec::new(states)?,
        scopes: BoundedVec::new(vec![scope])?,
    };
    Ok((plan, snapshot))
}
