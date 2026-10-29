use super::*;
use crate::admission_operation_store::{runtime_participant, RuntimeSourceRequalificationInput};

#[test]
fn superseded_source_keeps_history_but_refuses_new_claim_and_dispatch() -> TestResult {
    let fixture = fixture();
    let source = installed(&fixture)?;
    let (initial, lease) = setup(&fixture, "requalified-claim-history")?;
    let first = intent(&initial, &source, "first", &[])?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&initial, &lease, &first, now_ms())?;
    let snapshot = {
        let connection = fixture.store.connection()?;
        runtime_participant::dispatch_snapshot(&connection, &operation, 0)?
            .ok_or("missing valid dispatch snapshot")?
    };
    let replacement = Source::new(&fixture, Behavior::Normal);
    fixture.store.requalify_runtime_source(
        RuntimeSourceRequalificationInput {
            prior: &source,
            source_id: &identifier("source", "claim-replacement-source"),
            runtime_authority_id: &identifier("runtime", "claim-replacement-runtime"),
            source: &replacement,
        },
        &fixture.fence,
        now_ms(),
    )?;
    {
        let connection = fixture.store.connection()?;
        runtime_participant::verify_dispatch_snapshot(&connection, &operation, &Some(snapshot))?;
        assert_eq!(
            runtime_participant::dispatch_snapshot(&connection, &operation, 0),
            Err(AdmissionOperationStoreError::Invariant(
                "runtime source qualification has been superseded".into(),
            )),
        );
    }
    let history = fixture
        .store
        .load_runtime_participant_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("missing retained history")?;
    assert_eq!(history.1.len(), 1);
    assert_eq!(history.1[0].reference, reference);
    let lease = renew(&fixture, &operation, &lease)?;
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())?;
    let next = intent(&operation, &source, "after-supersession", &[])?;
    let before = global_count(&fixture.store);
    assert_eq!(
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &next, now_ms()),
        Err(AdmissionOperationStoreError::Invariant(
            "runtime source qualification has been superseded".into(),
        )),
    );
    assert_eq!(global_count(&fixture.store), before);
    let history = fixture
        .store
        .load_runtime_participant_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("missing released history")?;
    assert_eq!(history.1.len(), 1);
    assert_eq!(history.1[0].reference, reference);
    Ok(())
}

fn capture_ready(
    fixture: &Fixture,
    source: &RuntimeSourceRecordV1,
    name: &str,
) -> TestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    BudgetCaptureInvocationRequest,
)> {
    let (operation, lease) = setup(fixture, name)?;
    let claim = intent(&operation, source, name, &[])?;
    let (operation, _) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &claim, now_ms())?;
    let lease = renew(fixture, &operation, &lease)?;
    let hold_id = format!("{name}-hold");
    let authority = BudgetEventAuthority {
        authority_id: fixture.fence.store_uuid.clone(),
        lease_id: fixture.fence.lease_id.clone(),
        lease_epoch: fixture.fence.owner_epoch,
    };
    let request = BudgetAuthorizeHoldRequest {
        capability_id: operation.binding().capability_id().as_str().into(),
        grant_index: 0,
        max_invocations: Some(2),
        invocation_quotas: vec![],
        cumulative_approval: None,
        admission_binding: Some(BudgetAdmissionBinding {
            operation_id: operation.binding().operation_id().as_str().into(),
            revocation_set: CanonicalRevocationSet::canonicalize(vec![operation
                .binding()
                .capability_id()
                .as_str()
                .into()])?,
            authorization_artifact_digests: vec![operation
                .to_persisted()
                .binding
                .authorization_capability_hash
                .as_str()
                .into()],
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 0,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: Some(hold_id.clone()),
        event_id: Some(format!("{name}-authorize")),
        authority: Some(authority.clone()),
    };
    let capture = BudgetCaptureInvocationRequest {
        capability_id: request.capability_id.clone(),
        grant_index: 0,
        hold_id,
        event_id: format!("{name}-capture"),
        trusted_time: None,
        authority: Some(authority),
    };
    let (decision, mut operation) = fixture.store.authorize_budget_and_commit_admission(
        &operation,
        &lease,
        request,
        None,
        None,
        &fixture.fence,
        now_ms(),
    )?;
    if !matches!(decision, BudgetAuthorizeHoldDecision::Authorized(_)) {
        return Err(format!("budget authorization refused: {decision:?}").into());
    }
    for state in [
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
    ] {
        let current = renew(fixture, &operation, &lease)?;
        operation = fixture
            .store
            .compare_and_swap(&command(&operation, current, vec![], state, None), now_ms())?
            .into_operation();
    }
    let lease = renew(fixture, &operation, &lease)?;
    Ok((operation, lease, capture))
}

fn hold_state(fixture: &Fixture, hold_id: &str) -> TestResult<String> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT invocation_state FROM budget_authorization_holds WHERE hold_id = ?1",
        [hold_id],
        |row| row.get(0),
    )?)
}

#[test]
fn superseded_source_acknowledges_committed_capture_but_refuses_new_capture() -> TestResult {
    let fixture = fixture();
    let source = installed(&fixture)?;
    let (committed, committed_lease, committed_capture) =
        capture_ready(&fixture, &source, "requalified-capture-committed")?;
    let (fresh, fresh_lease, fresh_capture) =
        capture_ready(&fixture, &source, "requalified-capture-fresh")?;
    let (_, captured) = fixture.store.capture_invocation_and_commit_dispatch(
        &committed,
        &committed_lease,
        committed_capture.clone(),
        &fixture.fence,
        now_ms(),
    )?;
    fixture.store.requalify_runtime_source(
        RuntimeSourceRequalificationInput {
            prior: &source,
            source_id: &identifier("source", "capture-replacement-source"),
            runtime_authority_id: &identifier("runtime", "capture-replacement-runtime"),
            source: &Source::new(&fixture, Behavior::Normal),
        },
        &fixture.fence,
        now_ms(),
    )?;
    let before = global_count(&fixture.store);
    let (decision, restored) = fixture.store.capture_invocation_and_commit_dispatch(
        &committed,
        &committed_lease,
        committed_capture.clone(),
        &fixture.fence,
        now_ms(),
    )?;
    assert!(matches!(
        decision,
        BudgetInvocationCaptureDecision::AlreadyCaptured(_)
    ));
    assert_eq!(restored, captured);
    assert_eq!(global_count(&fixture.store), before);
    assert_eq!(
        hold_state(&fixture, &committed_capture.hold_id)?,
        "captured"
    );
    let refused = fixture.store.capture_invocation_and_commit_dispatch(
        &fresh,
        &fresh_lease,
        fresh_capture.clone(),
        &fixture.fence,
        now_ms(),
    );
    assert!(
        matches!(&refused, Err(error) if format!("{error:?}").contains("runtime source qualification has been superseded")),
        "{refused:?}"
    );
    assert_eq!(global_count(&fixture.store), before);
    assert_eq!(hold_state(&fixture, &fresh_capture.hold_id)?, "authorized");
    Ok(())
}
