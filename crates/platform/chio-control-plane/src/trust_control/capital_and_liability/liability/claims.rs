use super::*;

/// Operator-supplied predeclared roster policy for liability adjudication.
///
/// `roster_anchor` is the id or hash of the signed roster artifact that
/// `roster` was drawn from (for example a `chio-trust-market-context`
/// `AdjudicationJurisdictionReceipt`). It is recorded on the adjudication so
/// the audit trail shows which ex-ante roster was applied and the check is not
/// per-adjudication fabricable.
#[derive(Debug, Clone, Deserialize)]
pub struct RosterPolicy {
    pub roster: Vec<String>,
    pub allowed_decision_rules: Vec<String>,
    pub roster_anchor: String,
}

pub fn issue_signed_liability_claim_package(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimPackageIssueRequest,
) -> Result<SignedLiabilityClaimPackage, CliError> {
    let clock_now = unix_timestamp_now()?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_claim_package_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimPackage::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim package artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_package(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_response(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimResponseIssueRequest,
) -> Result<SignedLiabilityClaimResponse, CliError> {
    let clock_now = unix_timestamp_now()?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_claim_response_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimResponse::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim response artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_response(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_dispute(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimDisputeIssueRequest,
) -> Result<SignedLiabilityClaimDispute, CliError> {
    let clock_now = unix_timestamp_now()?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_claim_dispute_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimDispute::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim dispute artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_dispute(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_adjudication(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimAdjudicationIssueRequest,
    policy: &RosterPolicy,
) -> Result<SignedLiabilityClaimAdjudication, CliError> {
    let clock_now = unix_timestamp_now()?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_claim_adjudication_artifact(request, issued_at, policy)?;
    let signed = SignedLiabilityClaimAdjudication::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim adjudication artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_adjudication(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_payout_instruction(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimPayoutInstructionIssueRequest,
    policy: &RosterPolicy,
) -> Result<SignedLiabilityClaimPayoutInstruction, CliError> {
    let clock_now = unix_timestamp_now()?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_claim_payout_instruction_artifact(request, issued_at, policy)?;
    let signed =
        SignedLiabilityClaimPayoutInstruction::sign(artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability claim payout instruction artifact: {error}"
            ))
        })?;
    receipt_store
        .record_liability_claim_payout_instruction(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_payout_receipt(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimPayoutReceiptIssueRequest,
) -> Result<SignedLiabilityClaimPayoutReceipt, CliError> {
    let clock_now = unix_timestamp_now()?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_claim_payout_receipt_artifact(request, issued_at)?;
    let signed = SignedLiabilityClaimPayoutReceipt::sign(artifact, &keypair).map_err(|error| {
        CliError::cli_other_error(format!(
            "failed to sign liability claim payout receipt artifact: {error}"
        ))
    })?;
    receipt_store
        .record_liability_claim_payout_receipt(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_settlement_instruction(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimSettlementInstructionIssueRequest,
    policy: &RosterPolicy,
    capital_authority: &TrustedCapitalAuthority,
) -> Result<SignedLiabilityClaimSettlementInstruction, CliError> {
    let clock_now = unix_timestamp_now()?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_claim_settlement_instruction_artifact(
        request,
        issued_at,
        policy,
        capital_authority,
    )?;
    let signed =
        SignedLiabilityClaimSettlementInstruction::sign(artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability claim settlement instruction artifact: {error}"
            ))
        })?;
    receipt_store
        .record_liability_claim_settlement_instruction(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn issue_signed_liability_claim_settlement_receipt(
    receipt_store: &SqliteReceiptStore,
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
    request: &LiabilityClaimSettlementReceiptIssueRequest,
) -> Result<SignedLiabilityClaimSettlementReceipt, CliError> {
    let clock_now = unix_timestamp_now()?;
    let keypair = load_behavioral_feed_signing_keypair(authority_seed_path, authority_db_path)?;
    let issued_at = clock_now;
    let artifact = build_liability_claim_settlement_receipt_artifact(request, issued_at)?;
    let signed =
        SignedLiabilityClaimSettlementReceipt::sign(artifact, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "failed to sign liability claim settlement receipt artifact: {error}"
            ))
        })?;
    receipt_store
        .record_liability_claim_settlement_receipt(&signed)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    Ok(signed)
}

pub fn list_liability_claim_workflows(
    receipt_store: &SqliteReceiptStore,
    query: &LiabilityClaimWorkflowQuery,
) -> Result<LiabilityClaimWorkflowReport, CliError> {
    receipt_store
        .query_liability_claim_workflows(query)
        .map_err(|error| CliError::cli_other_error(error.to_string()))
}

fn build_liability_claim_evidence_refs(
    request: &LiabilityClaimPackageIssueRequest,
) -> Vec<LiabilityClaimEvidenceReference> {
    let mut refs = Vec::with_capacity(request.receipt_ids.len() + 4);
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::BoundCoverage,
        reference_id: request.bound_coverage.body.bound_coverage_id.clone(),
        observed_at: Some(request.bound_coverage.body.issued_at),
        locator: Some(format!(
            "policy:{}",
            request.bound_coverage.body.policy_number
        )),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ExposureLedger,
        reference_id: format!(
            "{}:{}",
            request.exposure.body.schema, request.exposure.body.generated_at
        ),
        observed_at: Some(request.exposure.body.generated_at),
        locator: request.exposure.body.filters.agent_subject.clone(),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::CreditBond,
        reference_id: request.bond.body.bond_id.clone(),
        observed_at: Some(request.bond.body.issued_at),
        locator: request.bond.body.report.filters.agent_subject.clone(),
    });
    refs.push(LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::CreditLossLifecycle,
        reference_id: request.loss_event.body.event_id.clone(),
        observed_at: Some(request.loss_event.body.issued_at),
        locator: Some(format!("{:?}", request.loss_event.body.event_kind)),
    });
    refs.extend(request.receipt_ids.iter().cloned().map(|receipt_id| {
        LiabilityClaimEvidenceReference {
            kind: LiabilityClaimEvidenceKind::Receipt,
            reference_id: receipt_id,
            observed_at: None,
            locator: None,
        }
    }));
    refs
}

fn build_liability_claim_package_artifact(
    request: &LiabilityClaimPackageIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimPackageArtifact, CliError> {
    let evidence_refs = build_liability_claim_evidence_refs(request);
    let artifact = LiabilityClaimPackageArtifact {
        schema: LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA.to_string(),
        claim_id: format!(
            "lcp-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_PACKAGE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.bound_coverage.body.bound_coverage_id,
                    &request.claimant,
                    request.claim_event_at,
                    &request.claim_amount,
                    &request.claim_ref,
                    &request.narrative,
                    &request.receipt_ids,
                    &request.bond.body.bond_id,
                    &request.loss_event.body.event_id,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        bound_coverage: request.bound_coverage.clone(),
        exposure: request.exposure.clone(),
        bond: request.bond.clone(),
        loss_event: request.loss_event.clone(),
        claimant: request.claimant.clone(),
        claim_event_at: request.claim_event_at,
        claim_amount: request.claim_amount.clone(),
        claim_ref: request.claim_ref.clone(),
        narrative: request.narrative.clone(),
        receipt_ids: request.receipt_ids.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_response_artifact(
    request: &LiabilityClaimResponseIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimResponseArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::BoundCoverage,
        reference_id: request
            .claim
            .body
            .bound_coverage
            .body
            .bound_coverage_id
            .clone(),
        observed_at: Some(request.claim.body.bound_coverage.body.issued_at),
        locator: Some(request.claim.body.claim_id.clone()),
    }];
    let artifact = LiabilityClaimResponseArtifact {
        schema: LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA.to_string(),
        claim_response_id: format!(
            "lcr-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_RESPONSE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.claim.body.claim_id,
                    &request.provider_response_ref,
                    request.disposition,
                    &request.covered_amount,
                    &request.response_note,
                    &request.denial_reason,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        claim: request.claim.clone(),
        provider_response_ref: request.provider_response_ref.clone(),
        disposition: request.disposition,
        covered_amount: request.covered_amount.clone(),
        response_note: request.response_note.clone(),
        denial_reason: request.denial_reason.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_dispute_artifact(
    request: &LiabilityClaimDisputeIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimDisputeArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ClaimResponse,
        reference_id: request.provider_response.body.claim_response_id.clone(),
        observed_at: Some(request.provider_response.body.issued_at),
        locator: Some(request.provider_response.body.claim.body.claim_id.clone()),
    }];
    let artifact = LiabilityClaimDisputeArtifact {
        schema: LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA.to_string(),
        dispute_id: format!(
            "lcd-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_DISPUTE_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.provider_response.body.claim_response_id,
                    &request.opened_by,
                    &request.reason,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        provider_response: request.provider_response.clone(),
        opened_by: request.opened_by.clone(),
        reason: request.reason.clone(),
        note: request.note.clone(),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_adjudication_artifact(
    request: &LiabilityClaimAdjudicationIssueRequest,
    issued_at: u64,
    policy: &RosterPolicy,
) -> Result<LiabilityClaimAdjudicationArtifact, CliError> {
    let evidence_refs = vec![LiabilityClaimEvidenceReference {
        kind: LiabilityClaimEvidenceKind::ClaimDispute,
        reference_id: request.dispute.body.dispute_id.clone(),
        observed_at: Some(request.dispute.body.issued_at),
        locator: Some(
            request
                .dispute
                .body
                .provider_response
                .body
                .claim
                .body
                .claim_id
                .clone(),
        ),
    }];
    let artifact = LiabilityClaimAdjudicationArtifact {
        schema: LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA.to_string(),
        adjudication_id: format!(
            "lca-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_ADJUDICATION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.dispute.body.dispute_id,
                    &request.adjudicator,
                    request.outcome,
                    &request.awarded_amount,
                    &request.note,
                    &request.decision_rule_ref,
                    &policy.roster_anchor,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        dispute: request.dispute.clone(),
        adjudicator: request.adjudicator.clone(),
        outcome: request.outcome,
        awarded_amount: request.awarded_amount.clone(),
        note: request.note.clone(),
        decision_rule_ref: request.decision_rule_ref.clone(),
        roster_anchor_ref: Some(policy.roster_anchor.clone()),
        evidence_refs,
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    artifact
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn liability_claim_adjudication_awarded_amount(
    adjudication: &SignedLiabilityClaimAdjudication,
) -> Result<MonetaryAmount, CliError> {
    match adjudication.body.outcome {
        LiabilityClaimAdjudicationOutcome::ClaimUpheld
        | LiabilityClaimAdjudicationOutcome::PartialSettlement => {
            adjudication.body.awarded_amount.clone().ok_or_else(|| {
                CliError::cli_other_error(
                    "claim payout instructions require adjudications with awarded_amount"
                        .to_string(),
                )
            })
        }
        LiabilityClaimAdjudicationOutcome::ProviderUpheld => Err(CliError::cli_other_error(
            "claim payout instructions require a payable adjudication outcome".to_string(),
        )),
    }
}

fn build_liability_claim_payout_instruction_artifact(
    request: &LiabilityClaimPayoutInstructionIssueRequest,
    issued_at: u64,
    policy: &RosterPolicy,
) -> Result<LiabilityClaimPayoutInstructionArtifact, CliError> {
    request
        .adjudication
        .body
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
    let payout_amount = liability_claim_adjudication_awarded_amount(&request.adjudication)?;
    let artifact = LiabilityClaimPayoutInstructionArtifact {
        schema: LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        payout_instruction_id: format!(
            "lpi-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_PAYOUT_INSTRUCTION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.adjudication.body.adjudication_id,
                    &request.capital_instruction.body.instruction_id,
                    &payout_amount,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        adjudication: request.adjudication.clone(),
        capital_instruction: request.capital_instruction.clone(),
        payout_amount,
        note: request.note.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_payout_receipt_artifact(
    request: &LiabilityClaimPayoutReceiptIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimPayoutReceiptArtifact, CliError> {
    let artifact = LiabilityClaimPayoutReceiptArtifact {
        schema: LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
        payout_receipt_id: format!(
            "lprc-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_PAYOUT_RECEIPT_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.payout_instruction.body.payout_instruction_id,
                    &request.payout_receipt_ref,
                    request.reconciliation_state,
                    &request.observed_execution,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        payout_instruction: request.payout_instruction.clone(),
        payout_receipt_ref: request.payout_receipt_ref.clone(),
        reconciliation_state: request.reconciliation_state,
        observed_execution: request.observed_execution.clone(),
        note: request.note.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_settlement_instruction_artifact(
    request: &LiabilityClaimSettlementInstructionIssueRequest,
    issued_at: u64,
    policy: &RosterPolicy,
    capital_authority: &TrustedCapitalAuthority,
) -> Result<LiabilityClaimSettlementInstructionArtifact, CliError> {
    request
        .payout_receipt
        .body
        .payout_instruction
        .body
        .adjudication
        .body
        .validate_against_roster(
            &policy.roster,
            &policy.allowed_decision_rules,
            &policy.roster_anchor,
        )
        .map_err(CliError::cli_other_error)?;
    chio_kernel::validate_capital_execution_envelope(
        &request.authority_chain,
        &request.execution_window,
        &request.rail,
        issued_at,
    )
    .map_err(CliError::cli_other_error)?;
    let artifact = LiabilityClaimSettlementInstructionArtifact {
        schema: LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA.to_string(),
        settlement_instruction_id: format!(
            "lcsi-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_SETTLEMENT_INSTRUCTION_ARTIFACT_SCHEMA,
                    issued_at,
                    &request.payout_receipt.body.payout_receipt_id,
                    &request.capital_book.body.subject_key,
                    request.settlement_kind,
                    &request.settlement_amount,
                    &request.topology,
                    &request.authority_chain,
                    &request.execution_window,
                    &request.rail,
                    &request.settlement_reference,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        payout_receipt: request.payout_receipt.clone(),
        capital_book: request.capital_book.clone(),
        settlement_kind: request.settlement_kind,
        settlement_amount: request.settlement_amount.clone(),
        topology: request.topology.clone(),
        authority_chain: request.authority_chain.clone(),
        execution_window: request.execution_window.clone(),
        rail: request.rail.clone(),
        settlement_reference: request.settlement_reference.clone(),
        note: request.note.clone(),
    };
    artifact
        .validate_with_capital_authority(capital_authority)
        .map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

fn build_liability_claim_settlement_receipt_artifact(
    request: &LiabilityClaimSettlementReceiptIssueRequest,
    issued_at: u64,
) -> Result<LiabilityClaimSettlementReceiptArtifact, CliError> {
    let artifact = LiabilityClaimSettlementReceiptArtifact {
        schema: LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA.to_string(),
        settlement_receipt_id: format!(
            "lcsr-{}",
            sha256_hex(
                &canonical_json_bytes(&(
                    LIABILITY_CLAIM_SETTLEMENT_RECEIPT_ARTIFACT_SCHEMA,
                    issued_at,
                    &request
                        .settlement_instruction
                        .body
                        .settlement_instruction_id,
                    &request.settlement_receipt_ref,
                    request.reconciliation_state,
                    &request.observed_execution,
                    &request.observed_payer_id,
                    &request.observed_payee_id,
                    &request.note,
                ))
                .map_err(|error| CliError::cli_other_error(error.to_string()))?
            )
        ),
        issued_at,
        settlement_instruction: request.settlement_instruction.clone(),
        settlement_receipt_ref: request.settlement_receipt_ref.clone(),
        reconciliation_state: request.reconciliation_state,
        observed_execution: request.observed_execution.clone(),
        observed_payer_id: request.observed_payer_id.clone(),
        observed_payee_id: request.observed_payee_id.clone(),
        note: request.note.clone(),
    };
    artifact.validate().map_err(CliError::cli_other_error)?;
    Ok(artifact)
}

#[cfg(test)]
#[path = "claims/tests.rs"]
mod tests;
