#[test]
fn authoritative_apply_failure_without_applied_effect_can_terminally_fail() {
    let (machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&machine, &planned, 110);
    let failed_effect_id = effect_id(&applying, 0);
    let requested = machine
        .record_effect(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: failed_effect_id.clone(),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|failure| panic!("effect request persistence failed: {failure}"));
    let failure_code = error("response.effect_rejected");
    let failed_transition_id = record("effect-rejected-transition");
    let rejected = machine
        .record_effect_with_receipt(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: failed_effect_id.clone(),
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Failed {
                    error_code: failure_code.clone(),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token: 1,
                effect_transition_id: Some(failed_transition_id.clone()),
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|failure| panic!("effect failure persistence failed: {failure}"));
    assert!(matches!(
        machine.transition(
            &rejected,
            &transition(rejected.generation, ResponseState::Failed, 122),
        ),
        Err(StateMachineError::InvalidFailureRecord)
    ));
    let terminal_failure = ResponseTransitionRequest {
        expected_generation: rejected.generation,
        target_state: ResponseState::Failed,
        occurred_at_unix_ms: 122,
        applying_lease_expires_at_unix_ms: None,
        error_code: Some(failure_code.clone()),
    };
    let failed = machine
        .transition(&rejected, &terminal_failure)
        .unwrap_or_else(|failure| panic!("terminal failure transition failed: {failure}"));
    let snapshot = decode_response_record(&failed)
        .unwrap_or_else(|failure| panic!("terminal failure decode failed: {failure}"));

    assert_eq!(snapshot.state, ResponseState::Failed);
    assert_eq!(
        snapshot.effect_progress(&failed_effect_id),
        Some(ResponseEffectProgress::ApplyFailed)
    );
    let evidence = snapshot
        .terminal_failure_evidence()
        .unwrap_or_else(|| panic!("terminal failure evidence missing"));
    assert_eq!(evidence.error_code(), &failure_code);
    let failed_effect = evidence
        .failed_effect()
        .unwrap_or_else(|| panic!("failed effect evidence missing"));
    assert_eq!(failed_effect.effect_id(), &failed_effect_id);
    assert_eq!(failed_effect.transition_id(), &failed_transition_id);
    assert_eq!(failed_effect.generation(), 1);

    let mut ambiguous = snapshot.clone();
    let mut mutations = ambiguous.mutations.clone().into_vec();
    let terminal = mutations
        .pop()
        .unwrap_or_else(|| panic!("terminal failure mutation missing"));
    let duplicate = mutations
        .iter()
        .find(|mutation| {
            matches!(
                mutation,
                chio_security_types::ResponseMutationRecord::EffectFailed(_)
            )
        })
        .cloned()
        .unwrap_or_else(|| panic!("effect failure mutation missing"));
    mutations.push(duplicate);
    mutations.push(terminal);
    ambiguous.mutations = BoundedVec::new(mutations)
        .unwrap_or_else(|error| panic!("ambiguous failure mutations: {error}"));
    assert!(!ambiguous.terminal_failure_effects_are_exact(&failure_code));
    assert!(ambiguous.terminal_failure_evidence().is_none());
}
#[test]
fn unresolved_effect_request_cannot_be_terminally_failed() {
    let (machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&machine, &planned, 110);
    let requested = machine
        .record_effect(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: effect_id(&applying, 0),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
        )
        .unwrap_or_else(|failure| panic!("effect request persistence failed: {failure}"));

    assert!(matches!(
        machine.transition(
            &requested,
            &transition(requested.generation, ResponseState::Failed, 121),
        ),
        Err(StateMachineError::InvalidFailureRecord)
    ));
}

#[test]
fn a_second_authoritative_apply_failure_is_rejected_before_terminal_failure() {
    let (machine, planned) = machine_with_plan(2);
    let applying = enter_applying(&machine, &planned, 110);
    let first_requested = request_effect_at(&machine, &applying, 0, 120);
    let first_failed =
        fail_requested_effect_at(&machine, &first_requested, 0, 121, "response.effect_first");
    let second_request = machine.record_effect(
        &first_failed,
        &EffectMutationRequest {
            expected_generation: first_failed.generation,
            effect_id: effect_id(&first_failed, 1),
            occurred_at_unix_ms: 122,
            mutation: EffectMutation::Requested,
        },
    );
    assert!(matches!(
        second_request,
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
    let terminal_failure = ResponseTransitionRequest {
        expected_generation: first_failed.generation,
        target_state: ResponseState::Failed,
        occurred_at_unix_ms: 123,
        applying_lease_expires_at_unix_ms: None,
        error_code: Some(error("response.effect_first")),
    };
    let failed = machine
        .transition(&first_failed, &terminal_failure)
        .unwrap_or_else(|failure| panic!("terminal failure rejected: {failure}"));
    let failed = decode_response_record(&failed)
        .unwrap_or_else(|failure| panic!("terminal failure decode failed: {failure}"));
    assert_eq!(failed.state, ResponseState::Failed);
}

#[test]
fn apply_partial_requires_resolved_effects_and_exact_failure_error() {
    let failure_code = "response.effect_second";

    let (machine, planned) = machine_with_plan(2);
    let applying = enter_applying(&machine, &planned, 110);
    let first_requested = request_effect_at(&machine, &applying, 0, 120);
    let first_applied = apply_requested_effect_at(&machine, &first_requested, 0, 121);
    let unresolved = request_effect_at(&machine, &first_applied, 1, 122);
    let unresolved_failure = ResponseTransitionRequest {
        expected_generation: unresolved.generation,
        target_state: ResponseState::Failed,
        occurred_at_unix_ms: 123,
        applying_lease_expires_at_unix_ms: None,
        error_code: Some(error(failure_code)),
    };
    assert!(matches!(
        machine.transition(&unresolved, &unresolved_failure),
        Err(StateMachineError::InvalidFailureRecord)
    ));

    let rejected = fail_requested_effect_at(&machine, &unresolved, 1, 123, failure_code);
    let mismatched_failure = ResponseTransitionRequest {
        expected_generation: rejected.generation,
        target_state: ResponseState::Failed,
        occurred_at_unix_ms: 124,
        applying_lease_expires_at_unix_ms: None,
        error_code: Some(error("response.different_failure")),
    };
    assert!(matches!(
        machine.transition(&rejected, &mismatched_failure),
        Err(StateMachineError::InvalidFailureRecord)
    ));

    let exact_failure = ResponseTransitionRequest {
        expected_generation: rejected.generation,
        target_state: ResponseState::Failed,
        occurred_at_unix_ms: 124,
        applying_lease_expires_at_unix_ms: None,
        error_code: Some(error(failure_code)),
    };
    let partial = machine
        .transition(&rejected, &exact_failure)
        .unwrap_or_else(|failure| panic!("exact partial failure rejected: {failure}"));
    let partial = decode_response_record(&partial)
        .unwrap_or_else(|failure| panic!("partial response decode failed: {failure}"));
    assert_eq!(partial.state, ResponseState::ApplyPartial);
    assert!(partial.terminal_apply_partial_effects_are_exact(&error(failure_code)));
}

#[test]
fn apply_partial_rejects_a_second_authoritative_failure_before_it_can_wedge() {
    let (machine, planned) = machine_with_plan(3);
    let applying = enter_applying(&machine, &planned, 110);
    let first_requested = request_effect_at(&machine, &applying, 0, 120);
    let first_applied = apply_requested_effect_at(&machine, &first_requested, 0, 121);
    let second_requested = request_effect_at(&machine, &first_applied, 1, 122);
    let second_failed = fail_requested_effect_at(
        &machine,
        &second_requested,
        1,
        123,
        "response.effect_second",
    );
    let third_request = machine.record_effect(
        &second_failed,
        &EffectMutationRequest {
            expected_generation: second_failed.generation,
            effect_id: effect_id(&second_failed, 2),
            occurred_at_unix_ms: 124,
            mutation: EffectMutation::Requested,
        },
    );
    assert!(matches!(
        third_request,
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
    let terminal_failure = ResponseTransitionRequest {
        expected_generation: second_failed.generation,
        target_state: ResponseState::Failed,
        occurred_at_unix_ms: 125,
        applying_lease_expires_at_unix_ms: None,
        error_code: Some(error("response.effect_second")),
    };
    let partial = machine
        .transition(&second_failed, &terminal_failure)
        .unwrap_or_else(|failure| panic!("recoverable partial transition failed: {failure}"));
    let partial = decode_response_record(&partial)
        .unwrap_or_else(|failure| panic!("recoverable partial decode failed: {failure}"));
    assert_eq!(partial.state, ResponseState::ApplyPartial);
}
