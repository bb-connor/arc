//! Physical hold ownership is invariant across first capture and exact replay.
use super::*;

#[test]
fn combined_capture_rejects_another_operations_hold_before_and_after_owner_capture(
) -> AnchoredTestResult {
    let fixture = fixture();
    let owner = pending(&fixture, "capture-owner")?;
    let substitute = pending(&fixture, "capture-substitute")?;
    let capture = authorize(&fixture, owner.binding().operation_id().as_str())?;
    let budget = fixture.authority.budget_store();
    let lease = claim(&fixture, &owner, "capture-owner", now_ms());
    let mut committed = None;
    for owner_captured in [false, true] {
        let substitute_lease = claim(&fixture, &substitute, "capture-substitute", now_ms());
        let before = counts(&fixture)?;
        let result = fixture.store.capture_invocation_and_commit_dispatch(
            &substitute,
            &substitute_lease,
            capture.clone(),
            &fixture.fence,
            now_ms(),
        );
        let error = result
            .err()
            .ok_or("another operation captured the owner's hold")?;
        assert!(error
            .to_string()
            .contains("capture hold belongs to another admission operation"));
        assert_eq!(counts(&fixture)?, before);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(substitute.binding().operation_id())?
                .as_ref(),
            Some(&substitute)
        );
        let quota = budget
            .get_invocation_quota_usage(&chio_kernel::budget_store::BudgetQuotaKey::grant(
                "shared-capability",
                0,
            ))?
            .ok_or("physical quota")?;
        assert_eq!(
            (quota.reserved_invocations, quota.captured_invocations),
            if owner_captured { (0, 1) } else { (1, 0) }
        );
        let (decision, operation) = fixture.store.capture_invocation_and_commit_dispatch(
            &owner,
            &lease,
            capture.clone(),
            &fixture.fence,
            now_ms(),
        )?;
        if owner_captured {
            assert!(matches!(
                decision,
                BudgetInvocationCaptureDecision::AlreadyCaptured(_)
            ));
            assert_eq!(committed.as_ref(), Some(&operation));
            assert_eq!(counts(&fixture)?, before);
        } else {
            assert!(matches!(
                decision,
                BudgetInvocationCaptureDecision::Captured(_)
            ));
            assert_eq!(
                operation.state(),
                AdmissionOperationState::DispatchCommitted
            );
            committed = Some(operation);
        }
    }
    Ok(())
}

#[test]
fn budget_only_references_preserve_split_capture_and_exact_replay() -> AnchoredTestResult {
    for reference in ["opaque-budget-reference".to_owned(), "a".repeat(64)] {
        let fixture = fixture();
        let capture = authorize(&fixture, &reference)?;
        let budget = fixture.authority.budget_store();
        assert!(matches!(
            budget.capture_invocation_reservations(capture.clone())?,
            BudgetInvocationCaptureDecision::Captured(_)
        ));
        let before = counts(&fixture)?;
        assert!(matches!(
            budget.capture_invocation_reservations(capture)?,
            BudgetInvocationCaptureDecision::AlreadyCaptured(_)
        ));
        assert_eq!(counts(&fixture)?, before);
    }
    Ok(())
}

#[test]
fn missing_committed_admission_cannot_be_reclassified_as_a_budget_only_reference(
) -> AnchoredTestResult {
    let fixture = fixture();
    let owner = pending(&fixture, "capture-missing-owner")?;
    let capture = authorize(&fixture, owner.binding().operation_id().as_str())?;
    // Inject the missing row inside a rollback-only transaction so the check
    // itself, not the outer anchor verifier, must distinguish lost ownership.
    {
        let mut connection = fixture.store.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "PRAGMA defer_foreign_keys = ON; DROP TRIGGER admission_operations_no_delete;",
        )?;
        transaction.execute(
            "DELETE FROM admission_operations WHERE operation_id = ?1",
            [owner.binding().operation_id().as_str()],
        )?;
        let error = crate::admission_operation_store::verify_dispatch_capture_owner_tx(
            &transaction,
            &capture.hold_id,
            None,
        )
        .err()
        .ok_or("missing admission was treated as a budget-only reference")?;
        assert!(error
            .to_string()
            .contains("capture hold lost its committed admission operation"));
        transaction.rollback()?;
    }
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(owner.binding().operation_id())?
            .as_ref(),
        Some(&owner)
    );
    let lease = claim(&fixture, &owner, "capture-missing-owner", now_ms());
    let (_, committed) = fixture.store.capture_invocation_and_commit_dispatch(
        &owner,
        &lease,
        capture,
        &fixture.fence,
        now_ms(),
    )?;
    assert_eq!(
        committed.state(),
        AdmissionOperationState::DispatchCommitted
    );
    Ok(())
}

fn authorize(fixture: &Fixture, owner: &str) -> AnchoredTestResult<BudgetCaptureInvocationRequest> {
    let authority = BudgetEventAuthority {
        authority_id: fixture.fence.store_uuid.clone(),
        lease_id: fixture.fence.lease_id.clone(),
        lease_epoch: fixture.fence.owner_epoch,
    };
    let budget = fixture.authority.budget_store();
    assert!(matches!(
        budget.authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "shared-capability".into(),
            grant_index: 0,
            max_invocations: Some(1),
            invocation_quotas: vec![],
            cumulative_approval: None,
            admission_binding: Some(BudgetAdmissionBinding {
                operation_id: owner.into(),
                revocation_set: CanonicalRevocationSet::canonicalize(vec![
                    "shared-capability".into()
                ])?,
                authorization_artifact_digests: vec!["a".repeat(64)],
                last_observed_revocation: None,
                supplemental_verifier_id: None,
                supplemental_verifier_config_digest: None,
                supplemental_authorization_artifact_digest: None,
                supplemental_authorization_expires_at: None,
            }),
            requested_exposure_units: 0,
            max_cost_per_invocation: None,
            max_total_cost_units: None,
            hold_id: Some("shared-hold".into()),
            event_id: Some("authorize-shared-hold".into()),
            authority: Some(authority.clone()),
        })?,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    Ok(BudgetCaptureInvocationRequest {
        capability_id: "shared-capability".into(),
        grant_index: 0,
        hold_id: "shared-hold".into(),
        event_id: "capture-shared-hold".into(),
        trusted_time: None,
        authority: Some(authority),
    })
}

fn pending(fixture: &Fixture, request_id: &str) -> AnchoredTestResult<AdmissionOperationV1> {
    let mut operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        request_id,
        "shared-capability",
    );
    fixture.store.begin(&operation, &fixture.fence, now_ms())?;
    for (state, attachments) in [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                &operation, request_id,
            ))],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "hold",
                "shared-hold",
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, vec![]),
        (AdmissionOperationState::CapturePending, vec![]),
    ] {
        let lease = claim(fixture, &operation, request_id, now_ms());
        operation = fixture
            .store
            .compare_and_swap(
                &command(&operation, lease, attachments, state, None),
                now_ms(),
            )?
            .into_operation();
    }
    Ok(operation)
}

fn counts(fixture: &Fixture) -> AnchoredTestResult<(i64, i64, i64)> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT (SELECT COUNT(*) FROM authority_global_commits),
          (SELECT COUNT(*) FROM budget_mutation_events),
          (SELECT COUNT(*) FROM admission_operation_commits)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}
