//! Fused claims preserve the same M4 authority boundary as separate commands.
use super::*;

#[test]
fn fused_claim_cannot_fabricate_security_participant_custody() -> AnchoredTestResult {
    for attachment in [
        AdmissionAttachment::RuntimeParticipantLedgerDigest(digest("runtime", 'a')),
        AdmissionAttachment::GovernedApprovalLedgerDigest(digest("approval", 'b')),
        AdmissionAttachment::DpopReplayLedgerDigest(digest("dpop", 'c')),
        AdmissionAttachment::CallerDispatchContextDigest(digest("caller", 'd')),
    ] {
        let fixture = fixture();
        let operation = prepared_operation(
            &fixture.fence,
            AdmissionOperationKind::ToolDispatch,
            "fused-security-refusal",
            "fused-security-capability",
        );
        let now = now_ms();
        fixture.store.begin(&operation, &fixture.fence, now)?;
        let claimant = identifier("claimant_id", "fused-security-worker");
        let connection = Connection::open(&fixture.database)?;
        let commits = admission_commit_rows(&connection)?;
        let generation = fixture.authority.anchor_generation()?;
        let result = fixture.store.claim_and_apply(
            claim_request(&fixture, &operation, &claimant, now + 1),
            now + 1,
            ClaimedTransition {
                attachments: vec![attachment],
                next_state: operation.state(),
            },
        );
        assert!(matches!(
            result,
            Err(AdmissionOperationStoreError::Invariant(_))
        ));
        assert_eq!(stored_claimant(&fixture, &operation), None);
        assert_eq!(admission_commit_rows(&connection)?, commits);
        assert_eq!(fixture.authority.anchor_generation()?, generation);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation.clone())
        );
        let accepted = fixture.store.claim_and_apply(
            claim_request(&fixture, &operation, &claimant, now + 2),
            now + 2,
            broker_transition(&operation, "fused-security-valid-attempt"),
        )?;
        assert_eq!(
            accepted.into_operation().state(),
            AdmissionOperationState::BrokerAttemptRegistered
        );
    }
    Ok(())
}

#[test]
fn fused_claim_rejects_expiry_at_the_authority_clock_before_callback() -> AnchoredTestResult {
    let fixture = fixture();
    let now = now_ms() / 1_000 * 1_000;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(now / 1_000, []);
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "fused-expired-claim",
        "fused-expired-capability",
    );
    fixture.store.begin(&operation, &fixture.fence, now)?;
    let claimant = identifier("claimant_id", "fused-expired-worker");
    let connection = Connection::open(&fixture.database)?;
    let commits = admission_commit_rows(&connection)?;
    let generation = fixture.authority.anchor_generation()?;
    let _expired = chio_kernel::scope_fixed_runtime_for_current_thread(now / 1_000 + 1, []);
    let mut called = false;
    let result = fixture.store.claim_and_compare_and_swap(
        RecoveryClaimRequest {
            expires_at_unix_ms: now + 1_000,
            ..claim_request(&fixture, &operation, &claimant, now)
        },
        now,
        &mut |_, _| {
            called = true;
            Err(AdmissionOperationStoreError::Invariant(
                "callback must not run".into(),
            ))
        },
    );
    assert!(matches!(
        result,
        Err(AdmissionOperationStoreError::Operation(
            AdmissionOperationError::LeaseExpired
        ))
    ));
    assert!(!called);
    assert_eq!(stored_claimant(&fixture, &operation), None);
    assert_eq!(admission_commit_rows(&connection)?, commits);
    assert_eq!(fixture.authority.anchor_generation()?, generation);
    Ok(())
}
