//! Pure response modelling. No effect, receipt, scheduler or alert ports are
//! available here. Authorization remains the kernel's responsibility.

use chio_core_types::canonical_json_bytes;
use chio_security_types::ports::*;
use chio_security_types::response_simulation::*;
use chio_security_types::{
    PlannedResponseEffect, ResponseEffectKind, ResponseExecutionMode, ResponsePlan,
};
use serde::{de::DeserializeOwned, Serialize};

/// Evaluate immediate apply and rollback, and independently evaluate every
/// contribution expiry in chronological order, including overlapping owners.
pub fn evaluate_response_simulation(
    plan: &ResponsePlan,
    snapshot: &ResponseSimulationSnapshot,
) -> PortResult<ResponseSimulationEvaluation> {
    if plan.execution.mode() != ResponseExecutionMode::DryRun {
        return Err(refused(
            "simulation.execution_mode",
            PortErrorKind::InvalidData,
        ));
    }
    crate::state_machine::validate_plan(plan)
        .map_err(|_| refused("simulation.plan", PortErrorKind::InvalidData))?;
    if snapshot.tenant_id != plan.tenant_id
        || snapshot.plan_hash != plan.plan_hash
        || snapshot.captured_at_unix_ms < plan.created_at_unix_ms
        || snapshot.captured_at_unix_ms >= plan.expires_at_unix_ms
    {
        return Err(refused(
            "simulation.snapshot_binding",
            PortErrorKind::Conflict,
        ));
    }
    let initial = snapshot.states.as_slice();
    for state in initial {
        state.version_hash()?;
        if !plan
            .effects
            .as_slice()
            .iter()
            .any(|effect| state.matches(plan, effect) == Ok(true))
        {
            return Err(refused(
                "simulation.unused_snapshot",
                PortErrorKind::InvalidData,
            ));
        }
    }
    let mut expected_scopes = 0;
    for effect in plan.effects.as_slice() {
        if effect.kind == ResponseEffectKind::EscalateAlert {
            continue;
        }
        state_index(initial, plan, effect)?;
        if effect.kind == ResponseEffectKind::FreezeIssuance {
            expected_scopes += 1;
            let spec: IssuanceFreezeSpec = decode(&effect.canonical_contribution)?;
            let matching: Vec<_> = snapshot
                .scopes
                .as_slice()
                .iter()
                .filter(|scope| scope.effect_id == effect.effect_id)
                .collect();
            if matching.len() != 1 || matching[0].result != spec.acquisition.approved_result {
                return Err(refused("simulation.stale_scope", PortErrorKind::Conflict));
            }
        }
    }
    if snapshot.scopes.len() != expected_scopes {
        return Err(refused(
            "simulation.scope_binding",
            PortErrorKind::InvalidData,
        ));
    }
    let mut states = initial.to_vec();
    let mut apply = Vec::new();
    for effect in plan.effects.as_slice() {
        let (outcome, resulting_version_hash) = if effect.kind == ResponseEffectKind::EscalateAlert
        {
            (ResponseSimulationOutcome::WouldDeliverAlert, None)
        } else {
            let index = state_index(&states, plan, effect)?;
            if states[index].version_hash()? != effect.observed_base_version_hash {
                return Err(refused("simulation.stale_state", PortErrorKind::Conflict));
            }
            states[index] = apply_effect(&states[index], plan, effect)?;
            (
                ResponseSimulationOutcome::WouldApply,
                Some(states[index].version_hash()?),
            )
        };
        apply.push(ResponseSimulationStep {
            effect_id: effect.effect_id.clone(),
            at_unix_ms: snapshot.captured_at_unix_ms,
            outcome,
            resulting_version_hash,
        });
    }
    let after_apply = BoundedVec::new(states.clone()).map_err(|_| PortError::invalid_data())?;
    let mut rolled_back = states.clone();
    let rollback =
        rollback_response_simulation(plan, &mut rolled_back, snapshot.captured_at_unix_ms)?;
    let mut expiry = Vec::new();
    // Every expiry is model time, not permission to run a future live effect.
    let mut deadlines: Vec<_> = states
        .iter()
        .flat_map(contributions)
        .filter_map(|(_, _, _, expiry)| expiry)
        .collect();
    deadlines.sort_unstable();
    deadlines.dedup();
    for deadline in deadlines {
        for state in &mut states {
            for (action_id, effect_id, _, expires_at) in contributions(state) {
                if expires_at.is_some_and(|at| at <= deadline) {
                    *state = remove(state, action_id.as_ref(), &effect_id)?;
                    expiry.push(ResponseSimulationStep {
                        effect_id,
                        at_unix_ms: deadline.max(snapshot.captured_at_unix_ms),
                        outcome: ResponseSimulationOutcome::WouldExpire,
                        resulting_version_hash: Some(state.version_hash()?),
                    });
                }
            }
        }
    }
    Ok(ResponseSimulationEvaluation {
        apply,
        rollback,
        expiry,
        after_apply,
        after_rollback: BoundedVec::new(rolled_back).map_err(|_| PortError::invalid_data())?,
        after_expiry: BoundedVec::new(states).map_err(|_| PortError::invalid_data())?,
    })
}

/// Removes only contributions exactly owned by this plan. The caller's state
/// is updated atomically only after every ownership check succeeds.
pub fn rollback_response_simulation(
    plan: &ResponsePlan,
    states: &mut Vec<ResponseSimulationState>,
    at_unix_ms: u64,
) -> PortResult<Vec<ResponseSimulationStep>> {
    if plan.execution.mode() != ResponseExecutionMode::DryRun {
        return Err(PortError::invalid_data());
    }
    let mut candidate = states.clone();
    let mut steps = Vec::new();
    for effect in plan.effects.as_slice().iter().rev() {
        let (outcome, resulting_version_hash) = if effect.kind == ResponseEffectKind::EscalateAlert
        {
            (ResponseSimulationOutcome::AlertNotReversible, None)
        } else {
            let index = state_index(&candidate, plan, effect)?;
            let state = &candidate[index];
            if !contributions(state).iter().any(|(action, id, hash, _)| {
                id == &effect.effect_id
                    && *hash == effect.contribution_hash
                    && action.as_ref().is_none_or(|id| id == &plan.action_id)
            }) {
                return Err(refused(
                    "simulation.rollback_ownership",
                    PortErrorKind::Conflict,
                ));
            }
            // Reusing apply's exact existing-contribution comparison also
            // rejects a changed payload whose hash column was left untouched.
            apply_effect(state, plan, effect)?;
            candidate[index] = remove(state, Some(&plan.action_id), &effect.effect_id)?;
            (
                ResponseSimulationOutcome::WouldRemove,
                Some(candidate[index].version_hash()?),
            )
        };
        steps.push(ResponseSimulationStep {
            effect_id: effect.effect_id.clone(),
            at_unix_ms,
            outcome,
            resulting_version_hash,
        });
    }
    *states = candidate;
    Ok(steps)
}

fn state_index(
    states: &[ResponseSimulationState],
    plan: &ResponsePlan,
    effect: &PlannedResponseEffect,
) -> PortResult<usize> {
    let mut found = None;
    for (index, state) in states.iter().enumerate() {
        if state.matches(plan, effect)? && found.replace(index).is_some() {
            return Err(refused(
                "simulation.duplicate_snapshot",
                PortErrorKind::InvalidData,
            ));
        }
    }
    found.ok_or_else(|| refused("simulation.missing_snapshot", PortErrorKind::InvalidData))
}

fn apply_effect(
    state: &ResponseSimulationState,
    plan: &ResponsePlan,
    effect: &PlannedResponseEffect,
) -> PortResult<ResponseSimulationState> {
    use ResponseSimulationState as S;
    let effect_id = effect.effect_id.clone();
    let contribution_hash = effect.contribution_hash;
    let expires_at_unix_ms = plan.expires_at_unix_ms;
    let action_id = plan.action_id.clone();
    Ok(match state {
        S::Suspension(current) => {
            let spec: SessionSuspensionSpec = decode(&effect.canonical_contribution)?;
            if spec.posture_rank == 0 {
                return Err(PortError::invalid_data());
            }
            S::Suspension(predict_containment_overlay_apply(
                current,
                &OverlayContribution {
                    effect_id,
                    posture_rank: spec.posture_rank,
                    contribution_hash,
                    expires_at_unix_ms: Some(expires_at_unix_ms),
                },
                current.highest_fencing_token.max(1),
            )?)
        }
        S::Throttle(current) => S::Throttle(predict_session_throttle_apply(
            current,
            &SessionThrottleContribution {
                effect_id,
                limits: decode(&effect.canonical_contribution)?,
                contribution_hash,
                expires_at_unix_ms,
            },
            current.highest_fencing_token.max(1),
        )?),
        S::Egress(current) => {
            let spec: EgressRestrictionSpec = decode(&effect.canonical_contribution)?;
            S::Egress(predict_egress_apply(
                current,
                &EgressRestrictionContribution {
                    effect_id,
                    destinations: spec.destinations,
                    contribution_hash,
                    expires_at_unix_ms,
                },
                current.highest_fencing_token.max(1),
            )?)
        }
        S::CapabilitySet(current) => {
            let spec: CapabilitySetSuspensionSpec = decode(&effect.canonical_contribution)?;
            if spec.affected_ids != plan.affected_ids {
                return Err(PortError::integrity_failure());
            }
            S::CapabilitySet(predict_capability_set_suspension_apply(
                current,
                &CapabilitySetSuspensionContribution {
                    action_id,
                    effect_id,
                    affected_ids: spec.affected_ids,
                    contribution_hash,
                    expires_at_unix_ms,
                },
                current.highest_fencing_token.max(1),
            )?)
        }
        S::Issuance(current) => {
            let spec: IssuanceFreezeSpec = decode(&effect.canonical_contribution)?;
            spec.validate_for(&current.key, &plan.action_id, plan.expires_at_unix_ms)?;
            let BlastRadiusResult::Exact {
                metadata,
                sorted_affected_ids,
                affected_set_hash,
                graph_slice_hash,
            } = spec.acquisition.approved_result
            else {
                return Err(PortError::invalid_data());
            };
            if sorted_affected_ids != plan.affected_ids
                || affected_set_hash != plan.affected_set_hash
            {
                return Err(PortError::integrity_failure());
            }
            let token = current.highest_scheduler_fencing_token.max(1);
            // A local model placeholder, never installed or passed to a port.
            let external_fence = LineageFence {
                tenant_id: plan.tenant_id.clone(),
                action_id: action_id.clone(),
                commit_index: metadata.commit_index,
                affected_set_hash,
                fencing_token: 1,
                scheduler_lease_owner_id: LeaseOwnerId::new("response-simulation")
                    .map_err(|_| PortError::invalid_data())?,
                scheduler_fencing_token: token,
                expires_at_unix_ms,
            };
            S::Issuance(predict_issuance_freeze_apply(
                current,
                &IssuanceFreezeContribution {
                    action_id,
                    effect_id,
                    commit_index: metadata.commit_index,
                    affected_set_hash,
                    frozen_affected_ids: sorted_affected_ids,
                    graph_slice_hash,
                    external_fence,
                    contribution_hash,
                    expires_at_unix_ms,
                },
                token,
            )?)
        }
    })
}

type Contribution = (Option<ActionId>, EffectId, Digest32, Option<u64>);
fn contributions(state: &ResponseSimulationState) -> Vec<Contribution> {
    use ResponseSimulationState as S;
    match state {
        S::Suspension(s) => s
            .active_contributions
            .as_slice()
            .iter()
            .map(|c| {
                (
                    None,
                    c.effect_id.clone(),
                    c.contribution_hash,
                    c.expires_at_unix_ms,
                )
            })
            .collect(),
        S::Throttle(s) => s
            .contributions
            .as_slice()
            .iter()
            .map(|c| {
                (
                    None,
                    c.effect_id.clone(),
                    c.contribution_hash,
                    Some(c.expires_at_unix_ms),
                )
            })
            .collect(),
        S::Egress(s) => s
            .contributions
            .as_slice()
            .iter()
            .map(|c| {
                (
                    None,
                    c.effect_id.clone(),
                    c.contribution_hash,
                    Some(c.expires_at_unix_ms),
                )
            })
            .collect(),
        S::CapabilitySet(s) => s
            .contributions
            .as_slice()
            .iter()
            .map(|c| {
                (
                    Some(c.action_id.clone()),
                    c.effect_id.clone(),
                    c.contribution_hash,
                    Some(c.expires_at_unix_ms),
                )
            })
            .collect(),
        S::Issuance(s) => s
            .contributions
            .as_slice()
            .iter()
            .map(|c| {
                (
                    Some(c.action_id.clone()),
                    c.effect_id.clone(),
                    c.contribution_hash,
                    Some(c.expires_at_unix_ms),
                )
            })
            .collect(),
    }
}

fn remove(
    state: &ResponseSimulationState,
    action: Option<&ActionId>,
    effect: &EffectId,
) -> PortResult<ResponseSimulationState> {
    use ResponseSimulationState as S;
    Ok(match state {
        S::Suspension(s) => S::Suspension(predict_containment_overlay_remove(
            s,
            effect,
            s.highest_fencing_token.max(1),
        )?),
        S::Throttle(s) => S::Throttle(predict_session_throttle_remove(
            s,
            effect,
            s.highest_fencing_token.max(1),
        )?),
        S::Egress(s) => S::Egress(predict_egress_removal(
            s,
            effect,
            s.highest_fencing_token.max(1),
        )?),
        S::CapabilitySet(s) => S::CapabilitySet(predict_capability_set_suspension_remove(
            s,
            action.ok_or_else(PortError::invalid_data)?,
            effect,
            s.highest_fencing_token.max(1),
        )?),
        S::Issuance(s) => S::Issuance(predict_issuance_freeze_remove(
            s,
            action.ok_or_else(PortError::invalid_data)?,
            effect,
            s.highest_scheduler_fencing_token.max(1),
        )?),
    })
}

fn decode<T: DeserializeOwned + Serialize>(body: &CanonicalBody) -> PortResult<T> {
    let value = serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
    if canonical_json_bytes(&value).map_err(|_| PortError::invalid_data())? != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(value)
}

fn refused(code: &str, kind: PortErrorKind) -> PortError {
    match ErrorCode::new(code) {
        Ok(code) => PortError::new(kind, code),
        Err(_) => PortError::invalid_data(),
    }
}
