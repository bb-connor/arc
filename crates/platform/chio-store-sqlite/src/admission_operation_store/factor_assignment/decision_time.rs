//! Preserve signed assignment decision time while requiring live authority.

use super::*;

pub(super) fn classify_live(
    transaction: &Transaction<'_>,
    current: &DurableObligationV1,
    submission: &VerifiedFactorAssignmentSubmission,
    commit: &FactorAssignmentCommitV1<'_>,
) -> Result<Option<AssignmentNotAppliedReasonV1>, AdmissionOperationStoreError> {
    let classify =
        |now| classify_not_applied(current, submission, commit.request, commit.offer, now);
    let reason = classify(commit.trusted_now_unix_ms)?;
    // If evidence expired in transit, do not apply it or rewrite a historical
    // reason using a timestamp the signer never supplied.
    if reason
        != classify(schema::authority_validation_time(
            transaction,
            commit.trusted_now_unix_ms,
        )?)?
    {
        return Err(invariant(
            "factor assignment evidence expired before authority commit",
        ));
    }
    Ok(reason)
}

fn classify_not_applied(
    current: &DurableObligationV1,
    submission: &VerifiedFactorAssignmentSubmission,
    request: &NormalizedAssignmentRequestV1,
    offer: &AssignmentOfferV1,
    trusted_now_unix_ms: u64,
) -> Result<Option<AssignmentNotAppliedReasonV1>, AdmissionOperationStoreError> {
    if trusted_now_unix_ms < submission.status_proof.body().issued_at_unix_ms()
        || trusted_now_unix_ms < submission.authorization.body().issued_at_unix_ms()
        || trusted_now_unix_ms < offer.issued_at_unix_ms()
        || trusted_now_unix_ms < request.effective_at_unix_ms()
    {
        return Err(invariant(
            "factor assignment artifacts are not yet effective",
        ));
    }
    classify_assignment_not_applied(&AssignmentNotAppliedClassificationV1 {
        atom: current.atom(),
        request,
        offer,
        authorization: &submission.authorization,
        status_proof: &submission.status_proof,
        observed_disposition: current.disposition(),
        observed_settlement_lifecycle: current.settlement_lifecycle(),
        observed_snapshot_version: current.snapshot_version(),
        observed_resource_fence: current.resource_fence(),
        decided_at_unix_ms: trusted_now_unix_ms,
    })
    .map_err(factor_error)
}
