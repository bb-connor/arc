use chio_quarantine::simulation::{evaluate_response_simulation, rollback_response_simulation};
use chio_security_types::{ports::*, response_simulation::*, *};
use serde_json::json;

#[path = "response_support/simulation.rs"]
mod support;
use support::{fixture, TestResult};
fn digest(value: u8) -> Digest32 {
    Digest32::new([value; 32])
}

#[test]
fn all_six_effects_model_apply_and_rollback_without_mutating_snapshot() -> TestResult {
    let (plan, snapshot) = fixture(None)?;
    let before = snapshot.clone();
    let result = evaluate_response_simulation(&plan, &snapshot)?;
    assert_eq!(snapshot, before);
    assert_eq!(result.apply.len(), 6);
    assert_eq!(
        result.apply[5].outcome,
        ResponseSimulationOutcome::WouldDeliverAlert
    );
    assert_eq!(
        result.rollback[0].outcome,
        ResponseSimulationOutcome::AlertNotReversible
    );
    assert_eq!(result.expiry.len(), 5);
    for state in result
        .after_rollback
        .as_slice()
        .iter()
        .chain(result.after_expiry.as_slice())
    {
        let json = serde_json::to_value(state)?;
        let entries = json["snapshot"]
            .get("contributions")
            .or_else(|| json["snapshot"].get("active_contributions"));
        assert_eq!(entries, Some(&json!([])));
    }
    Ok(())
}

#[test]
fn overlapping_owners_survive_rollback_and_expire_in_both_orders() -> TestResult {
    for expiry in [2000, 4000] {
        let (plan, snapshot) = fixture(Some(expiry))?;
        let result = evaluate_response_simulation(&plan, &snapshot)?;
        assert_eq!(result.expiry.len(), 10);
        assert!(result
            .expiry
            .windows(2)
            .all(|pair| pair[0].at_unix_ms <= pair[1].at_unix_ms));
        assert_eq!(result.expiry[0].at_unix_ms, expiry.min(3000));
        assert_eq!(result.expiry[9].at_unix_ms, expiry.max(3000));
        for (original, rolled_back) in snapshot
            .states
            .as_slice()
            .iter()
            .zip(result.after_rollback.as_slice())
        {
            let original = serde_json::to_value(original)?;
            let rolled_back = serde_json::to_value(rolled_back)?;
            let key = if original["kind"] == "suspension" {
                "active_contributions"
            } else {
                "contributions"
            };
            assert_eq!(original["snapshot"][key], rolled_back["snapshot"][key]);
        }
    }
    Ok(())
}

#[test]
fn rollback_rejects_replaced_contribution_without_partial_removal() -> TestResult {
    let (plan, snapshot) = fixture(None)?;
    let result = evaluate_response_simulation(&plan, &snapshot)?;
    let mut states = result.after_apply.into_vec();
    if let ResponseSimulationState::Throttle(state) = &mut states[1] {
        let mut entries = state.contributions.clone().into_vec();
        entries[0].limits.max_invocations += 1;
        state.contributions = BoundedVec::new(entries)?;
    }
    let before = states.clone();
    let error = rollback_response_simulation(&plan, &mut states, 1500)
        .err()
        .ok_or("rollback accepted changed contribution")?;
    assert_eq!(error.kind(), PortErrorKind::Conflict);
    assert_eq!(states, before);
    Ok(())
}

#[test]
fn rejects_live_mode_stale_scope_and_stale_effect_versions() -> TestResult {
    let (mut plan, mut snapshot) = fixture(None)?;
    plan.execution = ResponseExecutionBinding::new(ResponseExecutionMode::Live);
    let error = evaluate_response_simulation(&plan, &snapshot)
        .err()
        .ok_or("live mode accepted")?;
    assert_eq!(error.code().as_str(), "simulation.execution_mode");
    plan.execution = ResponseExecutionBinding::new(ResponseExecutionMode::DryRun);
    let mut scopes = snapshot.scopes.clone().into_vec();
    if let BlastRadiusResult::Exact {
        graph_slice_hash, ..
    } = &mut scopes[0].result
    {
        *graph_slice_hash = digest(99);
    }
    snapshot.scopes = BoundedVec::new(scopes)?;
    let error = evaluate_response_simulation(&plan, &snapshot)
        .err()
        .ok_or("stale scope accepted")?;
    assert_eq!(error.code().as_str(), "simulation.stale_scope");
    let (plan, mut snapshot) = fixture(None)?;
    let mut states = snapshot.states.into_vec();
    if let ResponseSimulationState::Throttle(state) = &mut states[1] {
        state.generation += 1;
    }
    snapshot.states = BoundedVec::new(states)?;
    let error = evaluate_response_simulation(&plan, &snapshot)
        .err()
        .ok_or("stale state accepted")?;
    assert_eq!(error.code().as_str(), "simulation.stale_state");
    Ok(())
}
