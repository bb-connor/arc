//! Public decision artifacts bind to original native execution and observed claim.
use super::{
    evidence::{self, Evidence, Submission},
    execution_evidence::Bundle,
    native::Native,
    settlement::{Action, ActionRequest, Prepared},
    verification::{self, Decision},
    verifier_operator::Enrollment,
};
use crate::common::{self, digest, Result};
use chio_core_types::{
    canonical_json_bytes, receipt::execution_evidence::verify_pre_settlement_execution_receipt,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const REQUEST_SCHEMA: &str = "chio.experimental.funded-verifier-request.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub submission: Submission,
    pub execution: Bundle,
    pub input: String,
    pub original_output: Value,
    pub output: Value,
    pub claim: Prepared,
}

/// Authenticate public commitments without claiming private source-preimage replay.
pub(super) fn original(enrollment: &Enrollment, request: &Request, now: u64) -> Result<Evidence> {
    super::verifier_operator::validate_enrollment(enrollment, now)?;
    if request.schema != REQUEST_SCHEMA
        || request.input.len() > 65536
        || canonical_json_bytes(request)?.len() > super::wire::MAX_ARTIFACT_BYTES
    {
        return Err("verifier request exceeds the bounded public profile".into());
    }
    let policy = &enrollment.policy;
    let agreement = &enrollment.agreement.body;
    let binding = &request.submission.body.binding;
    let receipt = &request.execution.receipt;
    let metadata = verify_pre_settlement_execution_receipt(
        receipt,
        std::slice::from_ref(&policy.provider_key),
    )?;
    let allocation = super::allocation::allocation_id(
        &policy.domain.chain_id,
        &policy.domain.escrow,
        &agreement.terms()?,
    )?;
    let mut parameters = serde_json::json!({"input":request.input});
    if let Some(terms) = &agreement.capture_waiver_terms {
        parameters[chio_kernel::payment::CAPTURE_WAIVER_TERMS_ARGUMENT] =
            serde_json::json!(digest(terms)?);
    }
    if binding.allocation_id != allocation
        || binding.agreement_sha256 != digest(agreement)?
        || binding.authority_uuid != policy.authority_uuid
        || metadata.authority_uuid != binding.authority_uuid
        || metadata.operation_id != binding.operation_id
        || metadata.hold_id != binding.hold_id
        || metadata.authorization_id != binding.authorization_id
        || binding.authorization_id != super::rail::authorization_id(&allocation)?
        || metadata.request_id != agreement.request_id
        || metadata.request_sha256 != agreement.request_sha256
        || binding.request_sha256 != agreement.request_sha256
        || metadata.outcome_id != binding.outcome_id
        || metadata.raw_outcome_sha256 != binding.raw_outcome_sha256
        || binding.expires_at != agreement.work.refund_after
        || receipt.timestamp >= binding.expires_at
        || receipt.policy_hash != digest(policy)?
        || receipt.tool_server != super::native::SERVER
        || receipt.tool_name != "review"
        || canonical_json_bytes(&receipt.action.parameters)? != canonical_json_bytes(&parameters)?
        || receipt.content_hash != digest(&request.original_output)?
        || metadata.resolved_output_sha256 != digest(&request.original_output)?
        || request
            .execution
            .checkpoints
            .iter()
            .any(|c| c.body.issued_at >= binding.expires_at)
    {
        return Err(
            "public verifier evidence changes original agreement or native identity".into(),
        );
    }
    super::checkpoint_handoff::validate_authorities(
        &policy.finding_context,
        &request.execution,
        now,
    )?;
    let original = Evidence {
        binding: binding.clone(),
        input: request.input.clone(),
        output: request.original_output.clone(),
        execution: Some(request.execution.clone()),
    };
    evidence::verify_blobs(
        &canonical_json_bytes(&request.submission)?,
        &original,
        policy,
        request.input.as_bytes(),
        &canonical_json_bytes(&request.output)?,
        now,
    )?;
    Ok(original)
}

pub(super) fn action(enrollment: &Enrollment, request: &Request) -> Result<ActionRequest> {
    Ok(ActionRequest {
        action: Action::Submit,
        allocation_id: request.submission.body.binding.allocation_id.clone(),
        terms: enrollment.agreement.validate_public(&enrollment.policy)?,
        commitment: Some(format!("0x{}", digest(&request.submission)?)),
        decision: None,
    })
}

pub(super) fn verify_claim_identity(
    decision: &Decision,
    claim: &super::settlement_observer::Verified,
) -> Result<()> {
    if decision.body.claim_transaction_hash != claim.transaction_hash
        || decision.body.claim_block_hash != claim.block_hash
        || decision.body.binding.allocation_id != claim.allocation_id
        || claim.commitment.as_deref() != Some(&decision.body.commitment)
        || claim.action != Action::Submit
    {
        return Err("verifier decision changes the independently observed original claim".into());
    }
    Ok(())
}

pub(super) fn export(native: &Native, request: &chio_kernel::ToolCallRequest) -> Result<Request> {
    let original = native.evidence(request)?;
    let allocation = &original.binding.allocation_id;
    let submission: Submission = native
        .journal
        .retained(allocation, "submission")?
        .ok_or("original submission missing")?;
    let output = evidence::decode(&native.journal.blob(&submission.body.output_sha256)?)?;
    let claim = native
        .journal
        .retained(allocation, "submit")?
        .ok_or("original prepared claim missing")?;
    let handoff = Request {
        schema: REQUEST_SCHEMA.into(),
        submission,
        execution: original.execution.ok_or("execution evidence missing")?,
        input: original.input,
        original_output: original.output,
        output,
        claim,
    };
    let entry = native
        .journal
        .by_request(&request.request_id)?
        .ok_or("original agreement missing")?;
    let enrollment = Enrollment {
        schema: super::verifier_operator::ENROLLMENT_SCHEMA.into(),
        policy: native.policy.clone(),
        agreement: entry.agreement,
    };
    self::original(&enrollment, &handoff, common::now()?)?;
    super::settlement::validate(
        &handoff.claim,
        &action(&enrollment, &handoff)?,
        &native.policy,
    )?;
    native
        .journal
        .retain_before(allocation, "verifier-request", &handoff, &["decision"])?;
    Ok(handoff)
}

pub(super) fn import(
    native: &Native,
    request: &chio_kernel::ToolCallRequest,
    decision: &Decision,
) -> Result<()> {
    let entry = native
        .journal
        .by_request(&request.request_id)?
        .ok_or("original agreement missing")?;
    let handoff: Request = native
        .journal
        .retained(&entry.allocation, "verifier-request")?
        .ok_or("original verifier request missing")?;
    let submission: Submission = native
        .journal
        .retained(&entry.allocation, "submission")?
        .ok_or("original submission missing")?;
    let prepared: Prepared = native
        .journal
        .retained(&entry.allocation, "submit")?
        .ok_or("original prepared claim missing")?;
    if canonical_json_bytes(&submission)? != canonical_json_bytes(&handoff.submission)?
        || canonical_json_bytes(&prepared)? != canonical_json_bytes(&handoff.claim)?
    {
        return Err("verifier handoff lost original submission or claim custody".into());
    }
    let enrollment = Enrollment {
        schema: super::verifier_operator::ENROLLMENT_SCHEMA.into(),
        policy: native.policy.clone(),
        agreement: entry.agreement,
    };
    let at = decision.body.finding_assessment.evaluated_at;
    original(&enrollment, &handoff, at)?;
    verification::verify_decision(decision, &submission, &native.policy, &native.journal)?;
    if let Some(retained) = native
        .journal
        .retained::<Decision>(&entry.allocation, "decision")?
    {
        if canonical_json_bytes(&retained)? != canonical_json_bytes(decision)? {
            return Err("imported verifier decision conflicts with original custody".into());
        }
        return Ok(());
    }
    let started = common::now()?;
    let observed = native.source.observe_transaction(&prepared)?;
    let claim = super::settlement_observer::verify(
        &native.policy,
        &action(&enrollment, &handoff)?,
        &prepared,
        &observed,
        started,
        common::now()?,
    )?;
    verify_claim_identity(decision, &claim)?;
    if claim.chain_time <= enrollment.agreement.body.work.challenge_until
        || claim.chain_time > enrollment.agreement.body.work.resolve_by
    {
        return Err(
            "new verifier decision import is outside the original resolution window".into(),
        );
    }
    native
        .journal
        .retain(&entry.allocation, "decision", decision)
}
