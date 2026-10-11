use super::*;

pub(super) fn build_acknowledgement(
    commit: &FactorAssignmentCommitV1<'_>,
    authority: &FactorAssignmentVerificationAuthorityV1,
    submission: &VerifiedFactorAssignmentSubmission,
    current: &DurableObligationV1,
    successor: &ObligationDispositionRecordV1,
) -> Result<VerifiedAssignmentAcknowledgementV1, AdmissionOperationStoreError> {
    let agreement = submission.authorization.agreement();
    let body = AssignmentAcknowledgementBodyV1::new(AssignmentAcknowledgementInputV1 {
        operation_id: commit
            .operation
            .binding()
            .operation_id()
            .as_str()
            .to_owned(),
        normalized_request_digest: commit.request.digest().map_err(factor_error)?,
        agreement_id: agreement.body().agreement_id().to_owned(),
        agreement_body_digest: agreement.body_digest().to_owned(),
        obligation_id: current.atom().obligation_id().to_owned(),
        obligation_atom_digest: current.atom().digest().map_err(obligation_error)?,
        buyer_id: commit.request.buyer_id().to_owned(),
        buyer_settlement_destination_ref: commit
            .request
            .buyer_settlement_destination_ref()
            .to_owned(),
        assignment_authorization_set_digest: submission.authorization.digest().to_owned(),
        status_proof_digest: submission.status_proof.envelope_digest().to_owned(),
        prior_disposition_version: current.disposition().version(),
        prior_disposition_lifecycle_fence: current.disposition().lifecycle_fence(),
        prior_disposition_digest: current
            .disposition()
            .digest(current.atom())
            .map_err(obligation_error)?,
        resulting_disposition_version: successor.version(),
        resulting_disposition_lifecycle_fence: successor.lifecycle_fence(),
        resulting_disposition_digest: successor.digest(current.atom()).map_err(obligation_error)?,
        expected_snapshot_version: current.snapshot_version(),
        resulting_snapshot_version: current
            .snapshot_version()
            .checked_add(1)
            .ok_or_else(|| invariant("factor assignment snapshot version overflow"))?,
        expected_resource_fence: current.resource_fence(),
        resulting_resource_fence: current
            .resource_fence()
            .checked_add(1)
            .ok_or_else(|| invariant("factor assignment resource fence overflow"))?,
        authority_id: authority.result_authority_id.clone(),
        authority_key_epoch: authority.result_authority_key_epoch,
        effective_at_unix_ms: commit.request.effective_at_unix_ms(),
        due_at_unix_ms: current.atom().due_at_unix_ms(),
        acknowledged_at_unix_ms: commit.trusted_now_unix_ms,
    })
    .map_err(factor_error)?;
    let signed = SignedAssignmentAcknowledgementV1::sign(body, &commit.signing_authority.signer)
        .map_err(factor_error)?;
    verify_assignment_acknowledgement(
        &signed.canonical_bytes().map_err(factor_error)?,
        &AssignmentAcknowledgementVerificationV1 {
            atom: current.atom(),
            request: commit.request,
            claim: &submission.claim,
            offer: commit.offer,
            authorization: &submission.authorization,
            status_proof: &submission.status_proof,
            resulting_disposition: successor,
            trust: &authority.result_trust,
        },
    )
    .map_err(factor_error)
}

pub(super) fn build_not_applied(
    commit: &FactorAssignmentCommitV1<'_>,
    authority: &FactorAssignmentVerificationAuthorityV1,
    submission: &VerifiedFactorAssignmentSubmission,
    current: &DurableObligationV1,
    reason: AssignmentNotAppliedReasonV1,
) -> Result<VerifiedAssignmentNotAppliedV1, AdmissionOperationStoreError> {
    let agreement = submission.authorization.agreement();
    let body = AssignmentNotAppliedBodyV1::new(AssignmentNotAppliedInputV1 {
        operation_id: commit
            .operation
            .binding()
            .operation_id()
            .as_str()
            .to_owned(),
        normalized_request_digest: commit.request.digest().map_err(factor_error)?,
        agreement_id: agreement.body().agreement_id().to_owned(),
        agreement_body_digest: agreement.body_digest().to_owned(),
        obligation_id: current.atom().obligation_id().to_owned(),
        obligation_atom_digest: current.atom().digest().map_err(obligation_error)?,
        assignment_authorization_set_digest: submission.authorization.digest().to_owned(),
        status_proof_digest: submission.status_proof.envelope_digest().to_owned(),
        expected_disposition_version: commit.request.expected_disposition_version(),
        expected_disposition_lifecycle_fence: commit.request.expected_disposition_lifecycle_fence(),
        expected_settlement_lifecycle_version: commit
            .request
            .expected_settlement_lifecycle_version(),
        expected_settlement_lifecycle_fence: commit.request.expected_settlement_lifecycle_fence(),
        expected_snapshot_version: submission.status_proof.body().snapshot_version(),
        expected_resource_fence: submission.status_proof.body().resource_fence(),
        observed_disposition_version: current.disposition().version(),
        observed_disposition_lifecycle_fence: current.disposition().lifecycle_fence(),
        observed_disposition_digest: current
            .disposition()
            .digest(current.atom())
            .map_err(obligation_error)?,
        observed_settlement_lifecycle_version: current.settlement_lifecycle().version(),
        observed_settlement_lifecycle_fence: current.settlement_lifecycle().lifecycle_fence(),
        observed_settlement_lifecycle_digest: current
            .settlement_lifecycle()
            .digest(current.atom())
            .map_err(obligation_error)?,
        observed_snapshot_version: current.snapshot_version(),
        resource_fence: current.resource_fence(),
        reason,
        no_mutation_proof_digest: current.head_digest().to_owned(),
        authority_id: authority.result_authority_id.clone(),
        authority_key_epoch: authority.result_authority_key_epoch,
        decided_at_unix_ms: commit.trusted_now_unix_ms,
    })
    .map_err(factor_error)?;
    let signed = SignedAssignmentNotAppliedV1::sign(body, &commit.signing_authority.signer)
        .map_err(factor_error)?;
    verify_assignment_not_applied(
        &signed.canonical_bytes().map_err(factor_error)?,
        &AssignmentNotAppliedVerificationV1 {
            atom: current.atom(),
            request: commit.request,
            claim: &submission.claim,
            offer: commit.offer,
            authorization: &submission.authorization,
            status_proof: &submission.status_proof,
            observed_disposition: current.disposition(),
            observed_settlement_lifecycle: current.settlement_lifecycle(),
            observed_snapshot_version: current.snapshot_version(),
            observed_resource_fence: current.resource_fence(),
            no_mutation_proof_digest: current.head_digest(),
            trust: &authority.result_trust,
        },
    )
    .map_err(factor_error)
}
