use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, VerifiedApprovalSetBody,
    THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_kernel::ThresholdApprovalReplayReservationV1;

// Store fixtures bind real signed packets to the retained capability and policy.
// They do not exercise the kernel's policy resolver or operator directory.
pub(in crate::admission_operation_store::tests::execution_nonce) fn reserve_approvals(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    original: &RetainedToolAdmissionRequestV1,
    key: &Keypair,
    token_seconds: u64,
) -> TestResult<AdmissionOperationV1> {
    let subject = original
        .request_for_revalidation()
        .capability
        .subject
        .clone();
    let approvers = [Keypair::generate(), Keypair::generate()];
    let created_at = now_ms() / 1_000;
    let intent = sha256_hex(b"nonce-approval-test-intent");
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.into(),
            proposal_id: "nonce-approval-proposal".into(),
            request_id: operation.binding().request_id().as_str().into(),
            governed_intent_hash: intent.clone(),
            subject: subject.clone(),
            authorizing_capability_digest: operation
                .to_persisted()
                .binding
                .authorization_capability_hash
                .as_str()
                .into(),
            policy_hash: operation.binding().policy_hash().as_str().into(),
            threshold: 2,
            eligible_set_digest: sha256_hex(b"nonce-approval-eligible-set"),
            proposal_created_at: created_at,
            proposal_deadline: created_at + 300,
            policy_authority: key.public_key(),
        },
        key,
    )?;
    let proposal_hash = proposal.artifact_digest()?;
    let tokens = approvers
        .iter()
        .enumerate()
        .map(|(index, signer)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("nonce-approval-token-{index}"),
                    approver: signer.public_key(),
                    subject: subject.clone(),
                    governed_intent_hash: intent.clone(),
                    request_id: operation.binding().request_id().as_str().into(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    issued_at: created_at,
                    expires_at: created_at + token_seconds,
                    decision: GovernedApprovalDecision::Approved,
                },
                signer,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let digests = tokens
        .iter()
        .map(GovernedApprovalToken::artifact_digest)
        .collect::<Result<Vec<_>, _>>()?;
    let set = VerifiedApprovalSetBody::new(digests, &proposal)?;
    let set_hash = set.approval_set_hash()?;
    let reservation = ThresholdApprovalReplayReservationV1::new(proposal, tokens, set)?;
    let command = nonce_command(
        &fixture.store,
        &fixture.fence,
        operation,
        key,
        vec![
            AdmissionAttachment::ThresholdProposalHash(AdmissionDigest::try_new(
                "proposal_hash",
                proposal_hash,
            )?),
            AdmissionAttachment::ApprovalSetHash(AdmissionDigest::try_new(
                "approval_set",
                set_hash,
            )?),
        ],
        AdmissionOperationState::ApprovalReserved,
    )?;
    Ok(fixture
        .store
        .reserve_threshold_approval_and_commit_admission(&command, &reservation, now_ms())?
        .into_operation())
}

fn ready_approved(token_seconds: u64) -> TestResult<NonceFixture> {
    let mut fixture = nonce_fixture_with_approval_window(true, Some(token_seconds))?;
    fixture.operation = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?
        .into_operation();
    Ok(fixture)
}

fn approval_state(fixture: &NonceFixture) -> TestResult<String> {
    Ok(fixture.fixture.store.connection()?.query_row(
        "SELECT state FROM threshold_approval_proposals WHERE operation_id = ?1",
        [fixture.operation.binding().operation_id().as_str()],
        |row| row.get(0),
    )?)
}

#[test]
fn durable_nonce_lifecycle_composed_approval_commits_or_cancels_with_its_effect() -> TestResult {
    for cancel in [false, true] {
        let mut fixture = ready_approved(300)?;
        prepare(&mut fixture)?;
        assert_eq!(approval_state(&fixture)?, "reserved");
        if cancel {
            release(&fixture)?;
            fixture
                .fixture
                .store
                .commit_terminal_projection(&projection(&fixture)?)?;
        } else {
            capture(&mut fixture)?;
        }
        assert_eq!(
            approval_state(&fixture)?,
            if cancel { "cancelled" } else { "committed" }
        );
        assert_eq!(
            state(&fixture)?,
            (
                if cancel {
                    "reversed".into()
                } else {
                    "captured".into()
                },
                2,
                i64::from(!cancel)
            )
        );
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_composed_approval_expiry_prevents_budget_capture() -> TestResult {
    let mut fixture = ready_approved(10)?;
    prepare(&mut fixture)?;
    let expires: i64 = fixture.fixture.store.connection()?.query_row(
        "SELECT proposal_created_at + 10 FROM threshold_approval_proposals",
        [],
        |row| row.get(0),
    )?;
    let command = command(&fixture)?;
    let error = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &fixture.operation,
            command.recovery_lease(),
            capture_request(&fixture),
            &fixture.fixture.fence,
            u64::try_from(expires)? * 1_000,
        )
        .expect_err("expired approval token captured a budget");
    assert!(
        error
            .to_string()
            .contains("currently valid proposal and tokens"),
        "{error}"
    );
    assert_eq!(approval_state(&fixture)?, "reserved");
    assert_eq!(state(&fixture)?, ("authorized".into(), 1, 0));
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_composed_approval_corruption_prevents_capture() -> TestResult {
    for mutation in [
        "DROP TRIGGER threshold_approval_tokens_no_delete; DELETE FROM threshold_approval_tokens;",
        "DROP TRIGGER threshold_approval_proposals_immutable;
         UPDATE threshold_approval_proposals SET policy_hash = printf('%064d', 0);",
        "DROP TRIGGER threshold_approval_tokens_immutable;
         PRAGMA ignore_check_constraints = ON;
         UPDATE threshold_approval_tokens SET token_json = zeroblob(262145);
         PRAGMA ignore_check_constraints = OFF;",
    ] {
        let mut fixture = ready_approved(300)?;
        prepare(&mut fixture)?;
        fixture
            .fixture
            .store
            .connection()?
            .execute_batch(mutation)?;
        let error = fixture
            .fixture
            .store
            .capture_invocation_and_commit_dispatch(
                &fixture.operation,
                command(&fixture)?.recovery_lease(),
                capture_request(&fixture),
                &fixture.fixture.fence,
                now_ms(),
            )
            .expect_err("corrupt approval evidence captured a budget");
        assert!(
            error.to_string().contains("threshold") || error.to_string().contains("approval"),
            "{error}"
        );
        assert_eq!(state(&fixture)?, ("authorized".into(), 1, 0));
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_composed_approval_rolls_back_when_nonce_commit_fails() -> TestResult {
    let mut fixture = ready_approved(300)?;
    prepare(&mut fixture)?;
    fixture.fixture.store.connection()?.execute_batch(
        "CREATE TEMP TRIGGER fail_nonce_commit BEFORE INSERT ON admission_execution_nonce_transitions
         WHEN NEW.kind = 'committed' BEGIN SELECT RAISE(ABORT, 'injected composed nonce commit'); END;"
    )?;
    let error = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &fixture.operation,
            command(&fixture)?.recovery_lease(),
            capture_request(&fixture),
            &fixture.fixture.fence,
            now_ms(),
        )
        .expect_err("nonce cutpoint");
    assert!(
        error.to_string().contains("injected composed nonce commit"),
        "{error}"
    );
    assert_eq!(approval_state(&fixture)?, "reserved");
    assert_eq!(state(&fixture)?, ("authorized".into(), 1, 0));
    Ok(())
}
