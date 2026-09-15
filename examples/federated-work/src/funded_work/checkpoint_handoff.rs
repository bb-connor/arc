//! Public artifact handoff for the original single-receipt checkpoint log.
use super::{execution_evidence as execution, finding_acceptance as finding, native::Native};
use crate::common::{self, digest, Result};
use chio_core_types::{canonical_json_bytes, receipt::body::ChioReceipt};
use chio_finding::FindingReceiptRole;
use chio_kernel::ToolCallRequest;
use serde::{Deserialize, Serialize};

pub const REQUEST_SCHEMA: &str = "chio.experimental.execution-checkpoint-request.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub context_sha256: String,
    pub receipt: ChioReceipt,
}

/// Retain before disclosure. Export never needs the checkpoint or status seeds.
pub(super) fn export(native: &Native, request: &ToolCallRequest) -> Result<Request> {
    if !execution::enabled(&native.policy) {
        return Err("external checkpoint requires the execution context".into());
    }
    let original = native.original_evidence(request)?;
    let receipt = native.kernel.export_durable_execution_evidence(request)?;
    if receipt.content_hash != digest(&original.output)? {
        return Err("checkpoint request differs from original output".into());
    }
    let handoff = Request {
        schema: REQUEST_SCHEMA.into(),
        context_sha256: digest(&native.policy.finding_context)?,
        receipt,
    };
    if canonical_json_bytes(&handoff)?.len() > super::wire::MAX_ARTIFACT_BYTES {
        return Err("checkpoint request exceeds bounded profile".into());
    }
    let allocation = &original.binding.allocation_id;
    native.journal.retain_before(
        allocation,
        "execution-request",
        &handoff,
        &[
            "execution-checkpoint",
            "execution-evidence",
            "submission",
            "decision",
        ],
    )?;
    Ok(handoff)
}

/// Authenticate every public authority before retaining external custody.
pub(super) fn import(
    native: &Native,
    request: &ToolCallRequest,
    bundle: &execution::Bundle,
) -> Result<()> {
    let original = native.original_evidence(request)?;
    let allocation = &original.binding.allocation_id;
    let handoff: Request = native
        .journal
        .retained(allocation, "execution-request")?
        .ok_or("original checkpoint handoff unavailable")?;
    if handoff.schema != REQUEST_SCHEMA
        || handoff.context_sha256 != digest(&native.policy.finding_context)?
        || canonical_json_bytes(&handoff.receipt)? != canonical_json_bytes(&bundle.receipt)?
        || canonical_json_bytes(&bundle.receipt)?
            != canonical_json_bytes(&native.kernel.export_durable_execution_evidence(request)?)?
        || bundle.receipt.content_hash != digest(&original.output)?
    {
        return Err("checkpoint response differs from original handoff".into());
    }
    execution::validate(bundle, &native.policy, &original.binding, request)?;
    if let Some(retained) = native
        .journal
        .retained::<execution::Bundle>(allocation, "execution-evidence")?
    {
        if canonical_json_bytes(&retained)? != canonical_json_bytes(bundle)? {
            return Err("checkpoint response conflicts with original custody".into());
        }
        // Exact custody replay is historical; fresh claim checks still use now.
        execution::retained(&native.policy, &original.binding, &native.journal)?;
        validate_authorities(&native.policy.finding_context, bundle, observed_at(bundle)?)?;
        return Ok(());
    }
    for kind in ["submission", "decision"] {
        if native
            .journal
            .retained::<serde_json::Value>(allocation, kind)?
            .is_some()
        {
            return Err("execution custody disappeared after Finding issuance".into());
        }
    }
    validate_authorities(&native.policy.finding_context, bundle, common::now()?)?;
    native
        .journal
        .put_blob(&canonical_json_bytes(&original.output)?)?;
    let [checkpoint] = bundle.checkpoints.as_slice() else {
        return Err("checkpoint response must contain one checkpoint".into());
    };
    native
        .journal
        .retain(allocation, "execution-checkpoint", checkpoint)?;
    native
        .journal
        .retain(allocation, "execution-evidence", bundle)?;
    Ok(())
}

pub(super) fn observed_at(bundle: &execution::Bundle) -> Result<u64> {
    bundle
        .signer_statuses
        .iter()
        .map(|s| s.body.observed_at)
        .max()
        .ok_or_else(|| "checkpoint response standing missing".into())
}

pub(super) fn validate_authorities(
    context: &finding::AcceptanceContext,
    bundle: &execution::Bundle,
    now: u64,
) -> Result<()> {
    finding::validate_context(
        context,
        &context.profile.body.verifier_report_signer.key,
        &context.admitted_kernel_key,
        now,
    )?;
    finding::validate_execution_bundle(context, bundle)?;
    chio_core_types::receipt::execution_evidence::verify_pre_settlement_execution_receipt(
        &bundle.receipt,
        std::slice::from_ref(&context.admitted_kernel_key),
    )?;
    let checkpoint = &bundle.checkpoints[0];
    if bundle.receipt.timestamp > checkpoint.body.issued_at
        || checkpoint.body.previous_checkpoint_sha256.is_some()
        || checkpoint.body.chain_root.is_none()
        || bundle.inclusion.proof.tree_size != 1
        || bundle.inclusion.proof.leaf_index != 0
    {
        return Err("external checkpoint exceeds original one-leaf profile".into());
    }
    chio_finding_verifier::verify_checkpoint_membership(
        &[chio_finding_verifier::ResolvedReceiptEvidence {
            receipt: bundle.receipt.clone(),
            canonical_receipt_bytes: canonical_json_bytes(&bundle.receipt)?,
            inclusion_proof: bundle.inclusion.clone(),
        }],
        &bundle.checkpoints,
        &bundle.transparency,
        &context.profile.body,
        &execution::checkpoint_ref(bundle)?,
    )?;
    let production = context
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|r| r.role == FindingReceiptRole::Production)
        .ok_or("production authority missing")?;
    let mut standing = context.governance_standing.clone();
    standing
        .signed_statuses
        .extend(bundle.signer_statuses.iter().cloned());
    for (policy, acted_at) in [
        (&production.policy, bundle.receipt.timestamp),
        (
            &context.profile.body.checkpoint_logs[0].signer,
            checkpoint.body.issued_at,
        ),
    ] {
        chio_finding_verifier::verify_status_operator_standing(
            policy,
            acted_at,
            now,
            Some(&standing),
        )
        .map_err(|reason| format!("external execution authority standing invalid: {reason}"))?;
    }
    Ok(())
}
