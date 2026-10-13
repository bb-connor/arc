use super::*;

#[test]
fn invalid_effect_receipt_fences_are_rejected_before_persistence() {
    let (machine, planned) = machine_with_plan(1);
    let applying = machine
        .transition(&planned, &transition(0, ResponseState::Applying, 110))
        .unwrap_or_else(|failure| panic!("begin apply failed: {failure}"));
    for (effect_generation, scheduler_fencing_token) in [(0, 1), (1, 9), (2, 1)] {
        let result = machine.record_effect_with_receipt(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: effect_id(&applying, 0),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
            &EffectReceiptContext {
                effect_generation,
                scheduler_lease_owner_id: None,
                scheduler_fencing_token,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        );
        if effect_generation == 0 {
            assert!(matches!(
                result,
                Err(StateMachineError::InvalidEffectLifecycle)
            ));
        } else {
            assert!(matches!(
                result,
                Err(StateMachineError::InvalidRecord(
                    chio_quarantine::RecordDefect::Lifecycle(
                        chio_core_types::Error::CanonicalJson(message)
                    )
                )) if message == "scheduler owner and fencing token binding is invalid"
            ));
        }
    }
}

#[test]
fn receipt_backed_effect_generation_and_fencing_token_cannot_regress() {
    let (generation_machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&generation_machine, &planned, 110);
    let generation_effect_id = effect_id(&applying, 0);
    let requested = generation_machine
        .record_effect_with_receipt(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: generation_effect_id.clone(),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
            &EffectReceiptContext {
                effect_generation: 3,
                scheduler_lease_owner_id: Some(
                    LeaseOwnerId::new("worker-1")
                        .unwrap_or_else(|failure| panic!("invalid lease owner: {failure}")),
                ),
                scheduler_fencing_token: 1,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|failure| panic!("receipt-backed effect request rejected: {failure}"));
    assert!(matches!(
        generation_machine.record_effect_with_receipt(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: generation_effect_id,
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: Some(
                    LeaseOwnerId::new("worker-1")
                        .unwrap_or_else(|failure| panic!("invalid lease owner: {failure}")),
                ),
                scheduler_fencing_token: 1,
                effect_transition_id: Some(record("effect-generation-regression")),
                prior_receipt_id: None,
            },
        ),
        Err(StateMachineError::InvalidEffectLifecycle)
    ));

    let (fencing_machine, planned) = machine_with_plan(1);
    let applying = enter_applying(&fencing_machine, &planned, 110);
    let effect_id = effect_id(&applying, 0);
    let requested = fencing_machine
        .record_effect_with_receipt(
            &applying,
            &EffectMutationRequest {
                expected_generation: applying.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 120,
                mutation: EffectMutation::Requested,
            },
            &EffectReceiptContext {
                effect_generation: 1,
                scheduler_lease_owner_id: Some(
                    LeaseOwnerId::new("worker-1")
                        .unwrap_or_else(|failure| panic!("invalid lease owner: {failure}")),
                ),
                scheduler_fencing_token: 9,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        )
        .unwrap_or_else(|failure| panic!("fenced effect request rejected: {failure}"));
    assert!(matches!(
        fencing_machine.record_effect_with_receipt(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id: effect_id.clone(),
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: Some(
                    LeaseOwnerId::new("worker-1")
                        .unwrap_or_else(|failure| panic!("invalid lease owner: {failure}")),
                ),
                scheduler_fencing_token: 9,
                effect_transition_id: None,
                prior_receipt_id: None,
            },
        ),
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
    assert!(matches!(
        fencing_machine.record_effect_with_receipt(
            &requested,
            &EffectMutationRequest {
                expected_generation: requested.generation,
                effect_id,
                occurred_at_unix_ms: 121,
                mutation: EffectMutation::Applied {
                    resulting_version_hash: digest(70),
                },
            },
            &EffectReceiptContext {
                effect_generation: 2,
                scheduler_lease_owner_id: Some(
                    LeaseOwnerId::new("worker-1")
                        .unwrap_or_else(|failure| panic!("invalid lease owner: {failure}")),
                ),
                scheduler_fencing_token: 8,
                effect_transition_id: Some(record("effect-fencing-regression")),
                prior_receipt_id: None,
            },
        ),
        Err(StateMachineError::InvalidEffectLifecycle)
    ));
}
