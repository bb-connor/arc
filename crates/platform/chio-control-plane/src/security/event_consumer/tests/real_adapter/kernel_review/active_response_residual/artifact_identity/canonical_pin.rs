use super::*;

#[test]
fn automatic_same_artifact_retry_keeps_the_first_preparation_identity() {
    let (_initial_time, fixture) = stable_fixture(false);
    let request = fixture.native_request();
    let first = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let binding = first
        .durable_dispatch_binding(request.response_plan())
        .test_unwrap();
    let _later =
        chio_test_support::clock::scope_unix_secs(binding.authorized_at_unix_ms / 1_000 + 1);

    let retry = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();

    assert_eq!(
        retry
            .durable_dispatch_binding(request.response_plan())
            .test_unwrap(),
        binding,
        "same verified artifact received another preparation identity"
    );
    assert_eq!(retry, first);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}

#[test]
fn automatic_different_authentic_artifact_cannot_claim_the_same_action() {
    let (_initial_time, fixture) = stable_fixture(false);
    let request = fixture.native_request();
    let first = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(request)
        .test_unwrap();
    let binding = first
        .durable_dispatch_binding(request.response_plan())
        .test_unwrap();
    let different = shorter_signed_request(&fixture, &binding);
    prove_counterpart_was_admissible_at_recorded_time(&fixture, &binding, &different);
    let before = retained_state(&fixture, &first);

    let refused = fixture
        .runtime
        .kernel
        .prepare_active_response_admission(&different);

    assert!(
        matches!(refused, Err(KernelError::GovernedTransactionDenied(_))),
        "another valid artifact claimed the original action: {refused:?}"
    );
    assert_eq!(retained_state(&fixture, &first), before);
    assert_original_reconstructs(&fixture, &first, &binding);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}
