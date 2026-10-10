use super::*;
use chio_quarantine::{ExecutorError, StateMachineError};
use chio_security_types::{DispatchRejection, ResponseExecutionBinding, ResponseExecutionMode};

#[test]
fn dry_run_scheduler_record_is_rejected_before_journals_or_effects() {
    let harness = Harness::new();
    let live = create_plan(Arc::clone(&harness.store));
    let mut snapshot = decode_response_record(&live)
        .unwrap_or_else(|error| panic!("live response snapshot: {error}"));
    snapshot.plan.execution = ResponseExecutionBinding::new(ResponseExecutionMode::DryRun);
    let authorization = serde_json::to_value(snapshot.plan.authorization_body())
        .unwrap_or_else(|error| panic!("dry-run authorization body: {error}"));
    snapshot.plan.plan_hash = Digest32::new(
        *chio_core_types::capability::governance::GovernedResponsePlanIntentBody::compute_plan_body_digest(
            &authorization,
        )
        .unwrap_or_else(|error| panic!("dry-run plan hash: {error}"))
        .as_bytes(),
    );
    let snapshot =
        chio_quarantine::state_machine::projection::initial_response_snapshot(snapshot.plan)
            .unwrap_or_else(|error| panic!("initial dry-run snapshot: {error}"));
    let canonical = chio_core_types::canonical_json_bytes(&snapshot)
        .unwrap_or_else(|error| panic!("dry-run response snapshot: {error}"));
    let dry_run = ResponsePlanRecord {
        canonical_body: CanonicalBody::new(canonical.clone())
            .unwrap_or_else(|error| panic!("dry-run canonical body: {error}")),
        body_hash: Digest32::new(*chio_core_types::sha256(&canonical).as_bytes()),
        ..live.clone()
    };
    // Exercise untrusted historical readback without minting fresh authority.
    decode_response_record(&dry_run)
        .unwrap_or_else(|error| panic!("well-formed dry-run readback: {error}"));
    let result = harness
        .executor()
        .execute(&dry_run, &work(&dry_run, 1, 900), 100);
    assert!(
        matches!(
            result,
            Err(ExecutorError::StateMachine(
                StateMachineError::InvalidDispatch(DispatchRejection::ExecutionMode {
                    observed: ResponseExecutionMode::DryRun
                })
            ))
        ),
        "unexpected dry-run result: {result:?}"
    );
    assert_eq!(harness.load(&live), live);
    assert_eq!(harness.effects.mutation_counts(), (0, 0));
    assert!(harness.receipts.requests().is_empty());
    assert!(harness
        .store
        .effect_transitions
        .lock()
        .unwrap_or_else(|error| panic!("effect journal: {error}"))
        .is_empty());
    assert!(harness
        .alerts
        .alerts
        .lock()
        .unwrap_or_else(|error| panic!("alert journal: {error}"))
        .is_empty());
}
