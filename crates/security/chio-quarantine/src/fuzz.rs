//! Stateful fuzz driver over the production response transitions and simulator.
//! Compiled only for explicit fuzz builds and the deterministic regression corpus.
use crate::*;
use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::{ports::*, *};
use std::sync::Arc;
#[path = "../tests/response_support/simulation.rs"]
mod simulation_fixture;
#[path = "../tests/response_support/mod.rs"]
mod support;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Runs a bounded sequence. Invalid transitions must preserve the committed row.
pub fn response_lifecycle(data: &[u8]) {
    if let Err(error) = drive(data) {
        panic!("valid lifecycle fixture failed: {error}");
    }
}

#[derive(serde::Serialize)]
struct LifecycleTrace {
    states: Vec<ResponseState>,
    mutations: ResponseMutationLog,
    generation: u64,
    mode: ResponseExecutionMode,
}

fn drive(data: &[u8]) -> TestResult<LifecycleTrace> {
    let overlap = if data.first().is_some_and(|byte| byte & 1 != 0) {
        2_000
    } else {
        4_000
    };
    let (dry, snapshot) = simulation_fixture::fixture(Some(overlap))?;
    assert!(matches!(
        FreshLiveAdmission::new(dry.clone()),
        Err(DispatchRejection::ExecutionMode {
            observed: ResponseExecutionMode::DryRun
        })
    ));
    let evaluation = simulation::evaluate_response_simulation(&dry, &snapshot)?;
    // Rollback must retain every other owner's contribution in all five ports.
    for (before, after) in snapshot
        .states
        .as_slice()
        .iter()
        .zip(evaluation.after_rollback.as_slice())
    {
        let before = serde_json::to_value(before)?;
        let after = serde_json::to_value(after)?;
        let key = if before["kind"] == "suspension" {
            "active_contributions"
        } else {
            "contributions"
        };
        assert_eq!(before["snapshot"][key], after["snapshot"][key]);
    }
    let plan = build_response_plan(ResponsePlanInput {
        execution: ResponseExecutionBinding::new(ResponseExecutionMode::Live),
        action_id: dry.action_id.clone(),
        trigger_finding_id: dry.trigger_finding_id.clone(),
        trigger_finding_hash: dry.trigger_finding_hash,
        trigger_finding_receipt_id: dry.trigger_finding_receipt_id.clone(),
        tenant_id: dry.tenant_id.clone(),
        policy_version: dry.policy_version.clone(),
        policy_hash: dry.policy_hash,
        affected_ids: dry.affected_ids.as_slice().to_vec(),
        effects: dry
            .effects
            .as_slice()
            .iter()
            .filter(|effect| effect.kind == ResponseEffectKind::SuspendSession)
            .map(|effect| ResponseEffectSpec {
                kind: effect.kind,
                target: effect.target.clone(),
                canonical_contribution: effect.canonical_contribution.clone(),
                contribution_hash: effect.contribution_hash,
                observed_base_version_hash: effect.observed_base_version_hash,
            })
            .collect(),
        ttl_ms: dry.ttl_ms,
        created_at_unix_ms: dry.created_at_unix_ms,
        operator_capability: dry.operator_capability.clone(),
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: dry.submitter.clone(),
        reason_hash: dry.reason_hash,
    })?;
    let store = Arc::new(support::TestResponseStore::default());
    let mut machine = ResponseStateMachine::new(Arc::clone(&store));
    let mut current = machine.create(FreshLiveAdmission::new(plan.clone())?)?;
    let mut now = plan.created_at_unix_ms;
    let states = [
        ResponseState::Applying,
        ResponseState::Active,
        ResponseState::ApplyPartial,
        ResponseState::RollingBack,
        ResponseState::RollbackPartial,
        ResponseState::Lifted,
        ResponseState::Expiring,
        ResponseState::Expired,
        ResponseState::Failed,
        ResponseState::Cancelled,
    ];
    for byte in data.iter().copied().take(64) {
        let before = current.clone();
        let result = match byte % 18 {
            0..=9 => machine.transition(
                &current,
                &ResponseTransitionRequest {
                    expected_generation: current.generation,
                    target_state: states[usize::from(byte % 18)],
                    occurred_at_unix_ms: now,
                    applying_lease_expires_at_unix_ms: (byte % 18 == 0)
                        .then_some(plan.expires_at_unix_ms),
                    error_code: if matches!(byte % 18, 2 | 4 | 8) {
                        Some(ErrorCode::new("fuzz.injected_failure")?)
                    } else {
                        None
                    },
                },
            ),
            10 => {
                now = plan.expires_at_unix_ms;
                machine.handle_due(&current, current.generation, now)
            }
            11 => {
                // Reconstruct the owner from the persisted wire row; do not reuse
                // a snapshot cached before the simulated owner death.
                let persisted = store
                    .load_plan(&ResponsePlanKey {
                        tenant_id: plan.tenant_id.clone(),
                        action_id: plan.action_id.clone(),
                    })?
                    .ok_or("restart lost its committed response")?;
                let encoded = canonical_json_bytes(&persisted)?;
                current = serde_json::from_slice(&encoded)?;
                machine = ResponseStateMachine::new(Arc::clone(&store));
                assert_eq!(
                    decode_response_record(&current)?.plan.plan_hash,
                    plan.plan_hash
                );
                continue;
            }
            12..=16 => {
                let effect = &plan.effects.as_slice()[0];
                machine.record_effect(
                    &current,
                    &EffectMutationRequest {
                        expected_generation: current.generation,
                        effect_id: effect.effect_id.clone(),
                        occurred_at_unix_ms: now,
                        mutation: match byte % 18 {
                            12 => EffectMutation::Requested,
                            13 => EffectMutation::Applied {
                                resulting_version_hash: Digest32::new([9; 32]),
                            },
                            14 => EffectMutation::RollbackRequested,
                            15 => EffectMutation::RollbackRestored {
                                resulting_version_hash: Digest32::new([8; 32]),
                            },
                            _ => EffectMutation::RollbackFailed {
                                error_code: ErrorCode::new("fuzz.rollback_conflict")?,
                            },
                        },
                    },
                )
            }
            _ => {
                let mut corrupt = current.clone();
                corrupt.body_hash = Digest32::new(*sha256(b"substituted").as_bytes());
                assert!(matches!(
                    decode_response_record(&corrupt),
                    Err(StateMachineError::InvalidRecord(
                        RecordDefect::BodyHashMismatch
                    ))
                ));
                continue;
            }
        };
        match result {
            Ok(next) => current = next,
            Err(error) => {
                assert!(!error.code().is_empty());
                assert_eq!(
                    store.load_plan(&ResponsePlanKey {
                        tenant_id: plan.tenant_id.clone(),
                        action_id: plan.action_id.clone()
                    })?,
                    Some(before)
                );
            }
        }
        let restored = decode_response_record(&current)?;
        if restored.state == ResponseState::Lifted {
            assert!(restored.all_applied_reversible_effects_restored());
            for effect in restored.plan.effects.as_slice() {
                assert!(matches!(
                    restored.effect_progress(&effect.effect_id),
                    Some(
                        ResponseEffectProgress::Planned
                            | ResponseEffectProgress::ApplyFailed
                            | ResponseEffectProgress::Restored
                    )
                ));
            }
        }
        assert_eq!(restored.plan.execution.mode(), ResponseExecutionMode::Live);
    }
    // The timeout owner may commit Expiring and RollingBack in one call.
    // Read its durable mutation history so intermediate commits are included.
    let snapshot = decode_response_record(&current)?;
    let mut trace = vec![ResponseState::Planned];
    for mutation in snapshot.mutations.as_slice() {
        match mutation {
            ResponseMutationRecord::Transition(record) => trace.push(record.to_state),
            ResponseMutationRecord::Failed(record) => trace.push(record.to_state),
            ResponseMutationRecord::Final(record) => trace.push(record.final_state),
            _ => {}
        }
    }
    Ok(LifecycleTrace {
        states: trace,
        mutations: snapshot.mutations,
        generation: snapshot.generation,
        mode: snapshot.plan.execution.mode(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn lifecycle_seed_corpus_reaches_apply_rollback_expiry_and_restart() {
        let happy = super::drive(&[0, 12, 13, 1, 11, 3, 14, 15, 5])
            .unwrap_or_else(|error| panic!("fixture: {error}"));
        assert!(happy.states.contains(&super::ResponseState::Active));
        assert!(happy.states.contains(&super::ResponseState::Lifted));
        let partial = super::drive(&[0, 12, 13, 1, 11, 3, 14, 16, 4, 3, 14, 15, 5])
            .unwrap_or_else(|error| panic!("fixture: {error}"));
        assert!(partial
            .states
            .contains(&super::ResponseState::RollbackPartial));
        assert!(partial.states.contains(&super::ResponseState::Lifted));
        let expiry = super::drive(&[0, 12, 13, 1, 11, 10, 3, 14, 15, 5])
            .unwrap_or_else(|error| panic!("fixture: {error}"));
        assert!(expiry.states.contains(&super::ResponseState::Expiring));
        assert!(expiry.states.contains(&super::ResponseState::Lifted));
        let unstarted = super::drive(&[11, 10]).unwrap_or_else(|error| panic!("fixture: {error}"));
        assert!(unstarted.states.contains(&super::ResponseState::Expired));
        let unresolved =
            super::drive(&[0, 12, 11, 10, 3, 5]).unwrap_or_else(|error| panic!("fixture: {error}"));
        assert_eq!(
            unresolved.states.last(),
            Some(&super::ResponseState::Applying)
        );
        if let Some(directory) = std::env::var_os("CHIO_RESPONSE_TRACE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory)
                .unwrap_or_else(|error| panic!("trace directory: {error}"));
            let traces = serde_json::json!({
                "schema": "chio.response-runtime-trace.v1",
                "owner": "ResponseStateMachine",
                "happy": happy, "partial": partial, "expiry": expiry, "unstarted": unstarted,
                "unresolved": unresolved,
            });
            std::fs::write(
                directory.join("lifecycle.json"),
                serde_json::to_vec_pretty(&traces)
                    .unwrap_or_else(|error| panic!("trace encode: {error}")),
            )
            .unwrap_or_else(|error| panic!("trace write: {error}"));
        }
    }

    #[test]
    fn lifecycle_sequences_preserve_committed_rows_and_rollback_invariants() {
        // Repeatable stateful property cases supplement the coverage-guided target.
        // Every case starts in valid Applying work and then explores fault/retry steps.
        let mut generator = 0x2026_0927_u64;
        for _ in 0..64 {
            let mut sequence = vec![0, 12, 13, 1];
            for _ in 0..32 {
                generator = generator.wrapping_mul(6364136223846793005).wrapping_add(1);
                sequence.push(generator.to_le_bytes()[7]);
            }
            super::response_lifecycle(&sequence);
        }
    }
}
