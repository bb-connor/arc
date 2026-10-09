//! New native admissions are refused with a typed, retryable operator error
//! before the store-wide current-row budget, and admit again once finished
//! sessions leave. Each identity class keeps a measured number of rows.
use super::session_churn::{checkpoint, clock, finish, key, request, rows, session_rows, taint};
use super::*;
use chio_security_types::InformationLabel;

fn exhausted(error: &(dyn Error + 'static)) -> Option<String> {
    match error.downcast_ref::<AdmissionOperationStoreError>() {
        Some(AdmissionOperationStoreError::Unavailable(detail))
            if detail.starts_with("native security current-row capacity is exhausted: ") =>
        {
            Some(detail.clone())
        }
        _ => None,
    }
}

/// Admit and join one operation in a new session, leaving it unfinished.
fn admit(fixture: &Fixture, principal: &str, name: &str) -> AnchoredTestResult<Pending> {
    let label = taint("capacity")?;
    let identity = key(principal, "capacity-lineage", name)?;
    let (context, join) = request(name, &identity, &label, &label)?;
    pending_with(fixture, name, None, context, join)
}

#[test]
fn new_admissions_past_the_budget_refuse_typed_and_recover_after_session_churn(
) -> AnchoredTestResult {
    const HEAD_ROOM: u64 = 60;
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let budget = rows(&fixture)? + HEAD_ROOM;
    native::with_test_current_rows(budget, || -> AnchoredTestResult {
        let mut admitted = Vec::new();
        let refusal = loop {
            // A new principal each time, so no single principal's share binds.
            let index = admitted.len();
            match admit(
                &fixture,
                &format!("churn-principal-{index}"),
                &format!("fill-{index}"),
            ) {
                Ok(pending) => admitted.push(pending),
                Err(error) => break error,
            }
            assert!(rows(&fixture)? <= budget);
            if admitted.len() > usize::try_from(HEAD_ROOM)? {
                return Err("new admissions were never refused".into());
            }
        };
        let detail = exhausted(refusal.as_ref()).ok_or_else(|| refusal.to_string())?;
        assert!(detail.contains("budget"), "{detail}");
        assert!(!admitted.is_empty());
        // Churn stops: the admitted operations finish and their sessions leave.
        for pending in &admitted {
            compensation::compensate(&fixture, pending)?;
        }
        checkpoint(&fixture)?;
        let first = key("churn-principal-0", "capacity-lineage", "fill-0")?;
        assert_eq!(session_rows(&fixture, &first)?, (0, 0, 0));
        // New admissions succeed again without a restart.
        let label = taint("capacity")?;
        let again = key("churn-principal", "capacity-lineage", "after-churn")?;
        finish(&fixture, "after-churn", &again, &label, &label)?;
        assert!(rows(&fixture)? <= budget);
        Ok(())
    })?;
    let fixture = reopen(fixture)?;
    let connection = fixture.store.connection()?;
    native::verify_all(&connection)?;
    native::verify_coverage(&connection)?;
    Ok(())
}

#[test]
fn identity_classes_keep_measured_current_rows() -> AnchoredTestResult {
    const ROOTS: u64 = 8;
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let label = taint("measured")?;
    let only = taint("measured-session-only")?;
    let bottom = InformationLabel::bottom();
    let settle = |fixture: &Fixture| -> AnchoredTestResult<u64> {
        checkpoint(fixture)?;
        checkpoint(fixture)?;
        rows(fixture)
    };
    let first = key("measured-principal", "root-0", "session-0")?;
    finish(&fixture, "measured-0", &first, &label, &label)?;
    let before = settle(&fixture)?;
    // A finished session whose label its principal dominates keeps nothing.
    for index in 1..=ROOTS {
        let session = key("measured-principal", "root-0", &format!("session-{index}"))?;
        finish(
            &fixture,
            &format!("session-{index}"),
            &session,
            &label,
            &label,
        )?;
    }
    assert_eq!(settle(&fixture)?, before);
    // A session carrying taint its principal lacks keeps label, membership, context.
    let before = settle(&fixture)?;
    for index in 1..=ROOTS {
        let session = key("measured-principal", "root-0", &format!("only-{index}"))?;
        finish(&fixture, &format!("only-{index}"), &session, &bottom, &only)?;
    }
    assert_eq!(settle(&fixture)? - before, 3 * ROOTS);
    // A new lineage root of an existing principal keeps its lineage label and
    // its copied isolation epoch.
    let before = settle(&fixture)?;
    for index in 1..=ROOTS {
        let root = key(
            "measured-principal",
            &format!("root-{index}"),
            &format!("rooted-{index}"),
        )?;
        finish(&fixture, &format!("rooted-{index}"), &root, &label, &label)?;
    }
    assert_eq!(settle(&fixture)? - before, 2 * ROOTS);
    // A new principal on a new lineage root keeps its principal label, its
    // genesis epoch and the lineage label.
    let before = settle(&fixture)?;
    for index in 1..=ROOTS {
        let principal = key(
            &format!("measured-principal-{index}"),
            &format!("principal-root-{index}"),
            &format!("principal-session-{index}"),
        )?;
        finish(
            &fixture,
            &format!("principal-{index}"),
            &principal,
            &label,
            &label,
        )?;
    }
    assert_eq!(settle(&fixture)? - before, 3 * ROOTS);
    Ok(())
}

#[test]
fn every_parked_admitted_operation_finishes_after_admissions_are_refused() -> AnchoredTestResult {
    const HEAD_ROOM: u64 = 60;
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let budget = rows(&fixture)? + HEAD_ROOM;
    native::with_test_current_rows(budget, || -> AnchoredTestResult {
        // Joined operations parked before egress, across the budget.
        let mut parked = Vec::new();
        let refusal = loop {
            match admit(
                &fixture,
                &format!("parked-principal-{}", parked.len()),
                &format!("parked-{}", parked.len()),
            ) {
                Ok(pending) => parked.push(pending),
                Err(error) => break error,
            }
            if parked.len() > usize::try_from(HEAD_ROOM)? {
                return Err("new admissions were never refused".into());
            }
        };
        let detail = exhausted(refusal.as_ref()).ok_or_else(|| refusal.to_string())?;
        assert!(detail.contains("budget"), "{detail}");
        assert!(!parked.is_empty());
        // Every one of them still acquires and commits its egress and finishes.
        for pending in &parked {
            let fence = pending.acquire(&fixture)?;
            pending.commit(&fixture, &commitment(&fence)?)?;
            assert!(rows(&fixture)? <= budget);
            compensation::compensate(&fixture, pending)?;
        }
        Ok(())
    })
}

/// A two-of-two threshold approval for `request_id`, valid from `created_at`.
fn threshold_approval(
    request_id: &str,
    created_at: u64,
) -> AnchoredTestResult<chio_kernel::ThresholdApprovalReplayReservationV1> {
    use chio_core::capability::governance::{
        ApprovalSetBody, GovernedApprovalDecision, GovernedApprovalToken,
        GovernedApprovalTokenBody, ThresholdApprovalProposal, ThresholdApprovalProposalBody,
        THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
    };
    let authority = Keypair::generate();
    let subject = Keypair::generate();
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
            proposal_id: format!("{request_id}-proposal"),
            request_id: request_id.to_owned(),
            governed_intent_hash: sha256_hex(b"parked-approval-intent"),
            subject: subject.public_key(),
            authorizing_capability_digest: sha256_hex(b"parked-approval-capability"),
            policy_hash: sha256_hex(b"parked-approval-policy"),
            threshold: 2,
            eligible_set_digest: sha256_hex(b"parked-approval-eligible-set"),
            proposal_created_at: created_at,
            proposal_deadline: created_at + 300,
            policy_authority: authority.public_key(),
        },
        &authority,
    )?;
    let proposal_hash = proposal.artifact_digest()?;
    let tokens = (0..2)
        .map(|index| {
            let approver = Keypair::generate();
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("{request_id}-token-{index}"),
                    approver: approver.public_key(),
                    subject: subject.public_key(),
                    governed_intent_hash: sha256_hex(b"parked-approval-intent"),
                    request_id: request_id.to_owned(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    issued_at: created_at,
                    expires_at: created_at + 300,
                    decision: GovernedApprovalDecision::Approved,
                },
                &approver,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let digests = tokens
        .iter()
        .map(|token| token.artifact_digest())
        .collect::<Result<Vec<_>, _>>()?;
    let verified = ApprovalSetBody::new(digests, &proposal)?;
    Ok(chio_kernel::ThresholdApprovalReplayReservationV1::new(
        proposal, tokens, verified,
    )?)
}

fn advance(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    lease: AdmissionRecoveryLease,
    attachments: Vec<AdmissionAttachment>,
    state: AdmissionOperationState,
) -> AnchoredTestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    let operation = fixture
        .store
        .compare_and_swap(
            &command(operation, lease, attachments, state, None),
            now_ms(),
        )?
        .into_operation();
    let lease = renew(
        fixture,
        &operation,
        &claim(fixture, &operation, "parked-approval", now_ms()),
    )?;
    Ok((operation, lease))
}

#[test]
fn a_parked_approval_across_the_budget_completes_from_its_reservation() -> AnchoredTestResult {
    const HEAD_ROOM: u64 = 60;
    let _clock = clock();
    let fixture = fixture();
    hydrate(&fixture, &imported(&fixture, "source")?)?;
    let initialized = fixture
        .store
        .load_security_participant_state(
            &identifier("authority", "source"),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("native initialization absent")?;
    let label = taint("parked-approval")?;
    // Its own lineage: the crowd's label joins must not touch its context.
    let identity = key("approval-principal", "approval-lineage", "approval-session")?;
    let (context, join) = request("parked-approval", &identity, &label, &label)?;
    let (operation, lease) = mutations::setup_with_approval(&fixture, "parked-approval", &context)?;
    let lease = renew(&fixture, &operation, &lease)?;
    let joined = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &join,
        now_ms(),
    )?;
    // Park in the approval state with its proposal and budget hold.
    let approval = threshold_approval(operation.binding().request_id().as_str(), now_ms() / 1_000)?;
    let proposal_hash = AdmissionDigest::try_new(
        "threshold_proposal_hash",
        approval.proposal().artifact_digest()?,
    )?;
    let (parked, lease) = advance(
        &fixture,
        &operation,
        lease,
        vec![
            AdmissionAttachment::ThresholdProposalHash(proposal_hash.clone()),
            AdmissionAttachment::ThresholdProposal(Box::new(approval.proposal().clone())),
            AdmissionAttachment::BudgetHoldId(identifier("hold", "parked-approval-hold")),
        ],
        AdmissionOperationState::ApprovalRequired,
    )?;
    assert_eq!(parked.state(), AdmissionOperationState::ApprovalRequired);
    // An existing identity whose further operations each add one row.
    let bottom = InformationLabel::bottom();
    let topup = key("topup-principal", "topup-lineage", "topup-session")?;
    finish(&fixture, "topup", &topup, &bottom, &bottom)?;
    let budget = rows(&fixture)? + HEAD_ROOM;
    native::with_test_current_rows(budget, || -> AnchoredTestResult {
        // Other admissions cross the budget while the approval is parked.
        let mut admitted = 0_u64;
        let refusal = loop {
            match admit(
                &fixture,
                &format!("crowd-principal-{admitted}"),
                &format!("crowd-{admitted}"),
            ) {
                Ok(_) => admitted += 1,
                Err(error) => break error,
            }
            if admitted > HEAD_ROOM {
                return Err("new admissions were never refused".into());
            }
        };
        let detail = exhausted(refusal.as_ref()).ok_or_else(|| refusal.to_string())?;
        assert!(detail.contains("budget"), "{detail}");
        // Then one-row operations on the existing identity take every row left.
        let mut topped = 0_u64;
        loop {
            let name = format!("topup-{topped}");
            let (_, generation) = super::session_churn::observe(&fixture, &topup)?;
            let (context, join) = request(&name, &topup, &bottom, &bottom)?;
            match pending_with(&fixture, &name, generation, context, join) {
                Ok(_) => topped += 1,
                Err(error) => {
                    exhausted(error.as_ref()).ok_or_else(|| error.to_string())?;
                    break;
                }
            }
            if topped > HEAD_ROOM {
                return Err("existing-identity operations were never refused".into());
            }
        }
        // The approval arrives and the operation completes its egress.
        let (authorized, lease) = advance(
            &fixture,
            &parked,
            lease,
            vec![],
            AdmissionOperationState::BudgetAuthorized,
        )?;
        let set_hash = AdmissionDigest::try_new(
            "approval_set_hash",
            approval.verified_set().approval_set_hash()?,
        )?;
        let reserved = fixture
            .store
            .reserve_threshold_approval_and_commit_admission(
                &command(
                    &authorized,
                    lease,
                    vec![
                        AdmissionAttachment::ThresholdProposalHash(proposal_hash),
                        AdmissionAttachment::ApprovalSetHash(set_hash),
                    ],
                    AdmissionOperationState::ApprovalReserved,
                    None,
                ),
                &approval,
                now_ms(),
            )?
            .into_operation();
        let lease = renew(
            &fixture,
            &reserved,
            &claim(&fixture, &reserved, "parked-approval", now_ms()),
        )?;
        let (ready, lease) = advance(
            &fixture,
            &reserved,
            lease,
            vec![],
            AdmissionOperationState::ReadyToDispatch,
        )?;
        let (capture, lease) = advance(
            &fixture,
            &ready,
            lease,
            vec![],
            AdmissionOperationState::CapturePending,
        )?;
        let (_, retained) = fixture
            .store
            .load_retained_tool_request(capture.binding().operation_id(), &fixture.fence, now_ms())?
            .ok_or("retained request absent")?;
        let hash: [u8; 32] = hex::decode(capture.binding().action_parameter_hash().as_str())?
            .try_into()
            .map_err(|_| "action digest width")?;
        let pending = Pending {
            operation: capture,
            lease,
            initialized,
            context: SecurityInvocationContext::v1(
                context
                    .as_v1()
                    .clone()
                    .with_flow_state_generation(joined.context_generation),
            ),
            request: retained.request_for_revalidation().clone(),
            plan: EgressFenceRequest {
                key: join.key.clone(),
                request_id: RequestId::new("parked-approval")?,
                request_hash: Digest32::new(hash),
                expected_context_generation: joined.context_generation,
                expires_at_unix_ms: now_ms() + 90_000,
            },
        };
        let fence = pending.acquire(&fixture)?;
        pending.commit(&fixture, &commitment(&fence)?)?;
        assert!(rows(&fixture)? <= budget);
        Ok(())
    })
}
