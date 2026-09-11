use super::*;
#[path = "claims/budget.rs"]
mod budget;
#[path = "claims/faults.rs"]
mod faults;
#[path = "claims/kernel_recovery.rs"]
mod kernel_recovery;
#[path = "claims/kernel_routes.rs"]
mod kernel_routes;
#[path = "claims/lifecycle.rs"]
mod lifecycle;
#[path = "claims/migration.rs"]
mod migration;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent,
};
use chio_kernel::admission_operation::governed_approval_claim::{
    GovernedApprovalAuthorityBindingV1, GovernedApprovalClaimDisposition,
    GovernedApprovalClaimIntentInput, GovernedApprovalClaimIntentV1, GovernedApprovalClaimPhase,
    GovernedApprovalCredentialV1,
};

fn activate(
    fixture: &Fixture,
    source: &Source,
) -> AnchoredTestResult<GovernedApprovalAuthorityBindingV1> {
    let pinned = pin(fixture, source)?;
    let imported = import(fixture, source, &pinned)?;
    let binding = GovernedApprovalAuthorityBindingV1::new(
        identifier("authority", AUTHORITY_ID),
        imported.expectation_id().clone(),
    );
    let active = fixture.store.activate_governed_approval_replay_source(
        &binding,
        source,
        &fixture.fence,
        now_ms(),
    )?;
    assert!(active.is_active());
    Ok(binding)
}

fn setup(
    fixture: &Fixture,
    name: &str,
) -> AnchoredTestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    GovernedApprovalCredentialV1,
)> {
    setup_for_phase(fixture, name, GovernedApprovalClaimPhase::Dispatch)
}

fn setup_for_phase(
    fixture: &Fixture,
    name: &str,
    phase: GovernedApprovalClaimPhase,
) -> AnchoredTestResult<(
    AdmissionOperationV1,
    AdmissionRecoveryLease,
    GovernedApprovalCredentialV1,
)> {
    let intent = GovernedTransactionIntent {
        id: name.into(),
        server_id: "server".into(),
        tool_name: "tool".into(),
        purpose: "approval custody test".into(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    let (operation, retained) = super::super::retained_request::original_with_intent(
        &fixture.fence,
        name,
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            execution_nonce: phase == GovernedApprovalClaimPhase::NoncePreflight,
            ..AdmissionParticipantRequirements::NONE
        },
        Some(intent),
    )?;
    let selected = load(fixture)?;
    let profile = super::super::retained_request::authority_profile::selection(
        None,
        selected.map(|selected| {
            GovernedApprovalAuthorityBindingV1::new(
                identifier("authority", AUTHORITY_ID),
                selected.expectation_id().clone(),
            )
        }),
        None,
    )?;
    let (operation, retained) =
        super::super::retained_request::authority_profile::prepare_with_profile(
            operation, retained, profile,
        )?;
    let request = retained.request_for_revalidation();
    let key = Keypair::generate();
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("approval-{name}"),
            approver: key.public_key(),
            subject: request.capability.subject.clone(),
            governed_intent_hash: request
                .governed_intent
                .as_ref()
                .ok_or("intent missing")?
                .binding_hash()?,
            request_id: name.into(),
            threshold_proposal_hash: None,
            issued_at: now_ms() / 1000 - 1,
            expires_at: now_ms() / 1000 + 300,
            decision: GovernedApprovalDecision::Approved,
        },
        &key,
    )?;
    let credential = GovernedApprovalCredentialV1::from_token(&token)?;
    fixture.store.begin_with_retained_tool_request(
        &operation,
        &retained,
        &fixture.fence,
        now_ms(),
    )?;
    let lease = claim(fixture, &operation, name, now_ms());
    if phase == GovernedApprovalClaimPhase::NoncePreflight {
        return Ok((operation, lease, credential));
    }
    let operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease.clone(),
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation, name,
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now_ms(),
        )?
        .into_operation();
    let lease = renew(fixture, &operation, &lease, now_ms())?;
    Ok((operation, lease, credential))
}

fn renew(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    now: u64,
) -> AnchoredTestResult<AdmissionRecoveryLease> {
    Ok(fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        lease.untrusted_claim().claimant_id(),
        now,
        now + 120_000,
        &fixture.fence,
    )?)
}

fn candidate(
    operation: &AdmissionOperationV1,
    authority: &GovernedApprovalAuthorityBindingV1,
    episode: &str,
    credential: GovernedApprovalCredentialV1,
) -> AnchoredTestResult<GovernedApprovalClaimIntentV1> {
    Ok(GovernedApprovalClaimIntentV1::new(
        GovernedApprovalClaimIntentInput {
            episode_id: identifier("episode", episode),
            approval_authority_id: authority.approval_authority_id().clone(),
            expectation_id: authority.expectation_id().clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            grant_index: 0,
            phase: GovernedApprovalClaimPhase::Dispatch,
            credential,
        },
    )?)
}

#[test]
fn approval_claim_retry_release_and_successor_preserve_exact_ownership() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let binding = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(&fixture, "approval-lifecycle")?;
    let first = candidate(&operation, &binding, "first", credential.clone())?;
    let (operation, reference) =
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &first, now_ms())?;
    let lease = renew(&fixture, &operation, &lease, now_ms())?;
    let count = global_count(&fixture);
    assert_eq!(
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &first, now_ms())?,
        (operation.clone(), reference.clone())
    );
    assert_eq!(global_count(&fixture), count);
    fixture
        .store
        .release_governed_approval(&operation, &lease, &reference, now_ms())?;
    assert!(fixture
        .store
        .claim_governed_approval(&operation, &lease, &first, now_ms())
        .is_err());
    let next = candidate(&operation, &binding, "next", credential)?;
    let (operation, next_reference) =
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &next, now_ms())?;
    assert_ne!(reference, next_reference);
    let count = global_count(&fixture);
    fixture
        .store
        .release_governed_approval(&operation, &lease, &reference, now_ms())?;
    assert_eq!(global_count(&fixture), count);
    let (_, history) = fixture
        .store
        .load_governed_approval_claim_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("history missing")?;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].disposition,
        GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(
        history[1].disposition,
        GovernedApprovalClaimDisposition::ReservedBeforeDispatch
    );
    verify_admission_operation_invariants(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn inactive_wrong_generation_or_original_provenance_cannot_claim() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
    let binding = GovernedApprovalAuthorityBindingV1::new(
        identifier("authority", AUTHORITY_ID),
        imported.expectation_id().clone(),
    );
    let (operation, lease, credential) = setup(&fixture, "approval-provenance")?;
    let intent = candidate(&operation, &binding, "inactive", credential.clone())?;
    let count = global_count(&fixture);
    assert!(fixture
        .store
        .claim_governed_approval(&operation, &lease, &intent, now_ms())
        .is_err());
    assert_eq!(global_count(&fixture), count);
    fixture.store.activate_governed_approval_replay_source(
        &binding,
        &source,
        &fixture.fence,
        now_ms(),
    )?;
    for changed in 0..5 {
        let mut value = credential.clone();
        let mut authority = binding.clone();
        match changed {
            0 => value.request_id = identifier("request", "different"),
            1 => value.subject_id = identifier("subject", "different"),
            2 => value.intent_hash = digest("intent", 'f'),
            3 => {
                authority = GovernedApprovalAuthorityBindingV1::new(
                    identifier("authority", AUTHORITY_ID),
                    identifier("expectation", "different"),
                )
            }
            _ => value.expires_at_unix_secs = value.issued_at_unix_secs + 1,
        }
        let candidate = candidate(&operation, &authority, "invalid", value)?;
        let count = global_count(&fixture);
        assert!(fixture
            .store
            .claim_governed_approval(&operation, &lease, &candidate, now_ms())
            .is_err());
        assert_eq!(global_count(&fixture), count);
    }
    Ok(())
}

#[test]
fn expired_predispatch_claim_can_be_read_and_released_but_not_used() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let binding = activate(&fixture, &source)?;
    let (operation, lease, mut credential) = setup(&fixture, "approval-expiry")?;
    let expires = now_ms() / 1000 + 60;
    credential.expires_at_unix_secs = expires;
    let intent = candidate(&operation, &binding, "expiring", credential)?;
    let (operation, _) =
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
    let now = expires * 1000;
    let lease = renew(&fixture, &operation, &lease, now)?;
    let (restored, history) = fixture
        .store
        .load_governed_approval_claim_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now,
        )?
        .ok_or("missing history")?;
    assert_eq!(restored, operation);
    {
        let mut connection = fixture.store.connection()?;
        let tx = connection.transaction()?;
        crate::admission_operation_store::verify_approval_budget_selection_tx(
            &tx,
            &operation,
            0,
            GovernedApprovalClaimPhase::Dispatch,
        )?;
        assert!(
            crate::admission_operation_store::verify_fresh_approval_tx(&tx, &operation, now)
                .is_err()
        );
    }
    fixture
        .store
        .release_governed_approval(&operation, &lease, &history[0].reference, now)?;
    Ok(())
}
