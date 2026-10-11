use super::*;

#[test]
fn claimed_tool_return_and_post_return_begin_are_one_durable_write_each() {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_000);
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = committed(&fixture, "claimed-return", begun_at);
    let at = begun_at + 20;
    let (blob, outcome) = returned_value(
        &operation,
        fixture.fence.clone(),
        at,
        serde_json::json!({"completed": true}),
        None,
    )
    .expect("returned outcome");
    // The same claimant the earlier transitions claimed under; another
    // claimant would be fenced by its still-active claim.
    let claimant = id("claimant_id", "tool-outcome-worker");
    let admission: &dyn QualifiedAdmissionOperationStore = &fixture.operations;
    let before = fixture.authority.anchor_generation().expect("anchor");
    let request = RecoveryClaimRequest {
        operation_id: operation.binding().operation_id(),
        expected_version: operation.version(),
        claimant_id: &claimant,
        expires_at_unix_ms: at + 60_000,
        fence: &fixture.fence,
    };
    let (stored, finalizing) = fixture
        .outcomes
        .claim_and_record_tool_returned(
            admission,
            request,
            &mut qualified_lease(request, at + 1),
            &operation,
            &blob,
            &outcome,
            &fixture.fence,
            at + 1,
        )
        .expect("claimed tool return")
        .into_parts();
    assert_eq!(finalizing.state(), AdmissionOperationState::Finalizing);
    assert_eq!(
        fixture.authority.anchor_generation().expect("anchor"),
        before + 1
    );

    let prepared = prepared_evaluation(&finalizing, &stored, at + 2).expect("prepared evaluation");
    let request = RecoveryClaimRequest {
        operation_id: finalizing.binding().operation_id(),
        expected_version: finalizing.version(),
        claimant_id: &claimant,
        expires_at_unix_ms: at + 60_000,
        fence: &fixture.fence,
    };
    let (evaluation, lease) = fixture
        .outcomes
        .claim_and_begin_post_return_evaluation(
            admission,
            request,
            &mut qualified_lease(request, at + 3),
            &prepared,
            &fixture.fence,
            at + 3,
        )
        .expect("claimed post-return begin");
    assert_eq!(evaluation, prepared);
    assert_eq!(
        fixture.authority.anchor_generation().expect("anchor"),
        before + 2
    );
    let pure = record_pure_step(&prepared).expect("pure result");
    assert_eq!(
        fixture
            .outcomes
            .stage_post_return_evaluation(
                finalizing.binding().operation_id(),
                prepared.version(),
                &lease,
                &pure,
                &fixture.fence,
                at + 4,
            )
            .expect("stage under the returned lease"),
        pure
    );

    let stepped = committed(&fixture, "stepped-return", begun_at + 40);
    let before = fixture.authority.anchor_generation().expect("anchor");
    record_return(&fixture, &stepped, begun_at + 60);
    assert_eq!(
        fixture.authority.anchor_generation().expect("anchor"),
        before + 2
    );
}

#[test]
fn expired_claims_refuse_callbacks_and_preserve_durable_tool_outcomes() {
    for post_return in [false, true] {
        let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_000);
        let fixture = fixture();
        let at = now_ms();
        let operation = committed(&fixture, "expired-qualified-return", at);
        let (blob, outcome) = returned_value(
            &operation,
            fixture.fence.clone(),
            at + 20,
            serde_json::json!({"completed": true}),
            None,
        )
        .expect("returned outcome");
        let claimant = id("claimant_id", "tool-outcome-worker");
        let admission: &dyn QualifiedAdmissionOperationStore = &fixture.operations;
        let request = RecoveryClaimRequest {
            operation_id: operation.binding().operation_id(),
            expected_version: operation.version(),
            claimant_id: &claimant,
            expires_at_unix_ms: at + 60_000,
            fence: &fixture.fence,
        };
        let prepared = if post_return {
            let (stored, finalizing) = fixture
                .outcomes
                .claim_and_record_tool_returned(
                    admission,
                    request,
                    &mut qualified_lease(request, at + 21),
                    &operation,
                    &blob,
                    &outcome,
                    &fixture.fence,
                    at + 21,
                )
                .expect("prepare post-return state")
                .into_parts();
            Some((
                prepared_evaluation(&finalizing, &stored, at + 22).expect("prepared evaluation"),
                finalizing,
            ))
        } else {
            None
        };
        let connection = rusqlite::Connection::open(&fixture.database).expect("connection");
        let snapshot = crate::tests::authority_snapshot(&connection).expect("snapshot");
        let anchor = fixture.authority.anchor_generation().expect("anchor");
        // This owner only advances. Expiry cannot be undone by restoring fixture time.
        let _expired =
            chio_test_support::clock::scope_unix_secs(request.expires_at_unix_ms / 1000 + 1);
        match prepared {
            Some((prepared, finalizing)) => {
                let request = RecoveryClaimRequest {
                    operation_id: finalizing.binding().operation_id(),
                    expected_version: finalizing.version(),
                    ..request
                };
                assert!(fixture
                    .outcomes
                    .claim_and_begin_post_return_evaluation(
                        admission,
                        request,
                        &mut |_, _| panic!("expired post-return called lease callback"),
                        &prepared,
                        &fixture.fence,
                        at + 23,
                    )
                    .is_err());
            }
            None => {
                assert!(fixture
                    .outcomes
                    .claim_and_record_tool_returned(
                        admission,
                        request,
                        &mut |_, _| panic!("expired return called lease callback"),
                        &operation,
                        &blob,
                        &outcome,
                        &fixture.fence,
                        at + 21,
                    )
                    .is_err());
            }
        }
        assert_eq!(
            crate::tests::authority_snapshot(&connection).expect("snapshot"),
            snapshot
        );
        assert_eq!(
            fixture.authority.anchor_generation().expect("anchor"),
            anchor
        );
    }
}
