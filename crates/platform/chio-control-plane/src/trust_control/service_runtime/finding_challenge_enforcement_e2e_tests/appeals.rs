use super::*;

#[test]
fn finding_challenge_successful_appeal_reverses_before_impairment() -> TestResult {
    let case = upheld_liability()?;
    let identity = liability_identity(&case.finding_id, &case.deployment.allocation_id);
    let resolution = case.coordinator.resolve_appeal(
        &case.upheld.liability_key,
        &case.outcome,
        &identity,
        Some(&case.upheld.sealed),
        &case.governance.context(),
        &AppealDisposition::Successful {
            appeal_case: &case.governance.appeal_case,
            appeal_case_id: &case.governance.appeal_case.body.case_id,
        },
        &case.upheld.sanction_case_id,
        &case.upheld.hold,
        &hex64('7'),
        fixture_commit_time(NOW + 20),
    )?;
    let AppealResolution::ReversedBeforeImpairment { reversal } = resolution else {
        return Err("a timely successful appeal reverses the hold".into());
    };
    assert_eq!(
        reversal.evaluation.effective_state,
        OpenMarketPenaltyEffectiveState::Reversed
    );
    let liability = case
        .deployment
        .challenges
        .get_liability(&case.upheld.liability_key)?
        .ok_or("liability head is durable")?;
    assert_eq!(
        liability.state,
        FindingLiabilityState::ReversedBeforeImpairment
    );
    assert!(!liability.publication_pending);
    Ok(())
}
