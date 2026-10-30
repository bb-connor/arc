//! Channel terminal projections rebase immutable evidence over a later checkpoint.

use super::*;

#[test]
fn channel_terminal_projection_rebases_immutable_evidence_over_a_later_checkpoint() -> TestResult<()>
{
    let fixture = build_fixture(7, "terminal-later-rebase")?;
    let kernel = Keypair::from_seed(&[36; 32]);
    let signed_outcome = sign_channel_terminal_outcome_commitment(
        &fixture.base.operation,
        &fixture.base.reservation,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &fixture.base.context,
        &kernel,
    )?;
    let outcome = verify_channel_terminal_outcome_commitment(
        &signed_outcome,
        &kernel.public_key(),
        &fixture.base.reservation,
        fixture.base.receipt.receipt(),
    )?;
    let mut later_view = fixture.base.advance.current_view().view().clone();
    later_view.checkpoint_sequence = later_view
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    later_view.checkpoint_digest = channel_digest("terminal-later-rebase-checkpoint");
    later_view.observed_at = 1_700;
    later_view.seal(&Keypair::from_seed(&[61; 32]))?;
    let later_view = verify_economic_state_view(later_view, &anchor_pins())?;
    let issued_at = 1_701;
    let transition = compose_channel_terminal_transition(
        fixture.base.advance.open(),
        &fixture.base.reservation,
        fixture.base.advance.next_state(),
        fixture.base.advance.receipt(),
        &outcome,
        &later_view,
        issued_at,
    )?;
    let anchored_advance = verified_terminal_batch(
        &later_view,
        fixture.base.operation.binding().operation_id().as_str(),
        transition.transitions().to_vec(),
        issued_at,
    )?;
    let advance = verify_channel_terminal_advance(
        fixture.base.advance.open(),
        &fixture.base.reservation,
        fixture.base.advance.prior_state(),
        fixture.base.advance.next_state(),
        fixture.base.advance.receipt(),
        &outcome,
        &anchored_advance,
    )?;
    assert_eq!(
        advance.obligation_atom(),
        fixture.base.advance.obligation_atom()
    );
    assert_eq!(advance.next_state(), fixture.base.advance.next_state());
    assert!(fixture.base.context.trusted_time_unix_ms < advance.batch_issued_at());

    let (channel, obligation) = VerifiedChannelTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &fixture.base.context,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &advance,
    )?;
    assert_eq!(
        obligation.as_ref().map(ObligationProjection::atom),
        fixture.base.atom.as_ref()
    );
    let projection =
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context: fixture.base.context.clone(),
            receipt: fixture.base.receipt.clone(),
            tool_outcome: Some(fixture.base.tool_outcome.clone()),
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: None,
            obligation,
            channel_terminal: Some(channel),
        }));
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &projection,
        &capabilities(),
        &kernel,
    )?;
    let verified = envelope.verify_integrity_embedded_key()?;
    assert_eq!(
        verified
            .channel_terminal()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?
            .batch_issued_at(),
        issued_at
    );
    Ok(())
}
