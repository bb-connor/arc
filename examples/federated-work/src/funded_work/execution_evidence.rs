//! Canonical custody of one original execution receipt and its checkpoint.
use super::{agreement::Policy, evidence::Binding, journal::Journal, native::Native};
use crate::common::{self, digest, Result};
use chio_core_types::{
    canonical_json_bytes,
    receipt::{
        body::ChioReceipt, execution_evidence::verify_pre_settlement_execution_receipt,
        lineage::SignedExportEnvelope,
    },
};
use chio_finding::{
    FindingAuthorityStatus, FindingReceiptRole, SignedFindingAuthorityStatus,
    FINDING_AUTHORITY_STATUS_SCHEMA_V1,
};
use chio_kernel::checkpoint::{
    CheckpointTransparencySummary, KernelCheckpoint, ReceiptInclusionProof,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const BUNDLE_SCHEMA: &str = "chio.experimental.funded-execution-bundle.v1";

/// The local profile uses one pre-agreed checkpoint log per native authority.
/// Exact custody survives process recovery without refreshing signed standing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bundle {
    pub schema: String,
    pub receipt: ChioReceipt,
    pub checkpoints: Vec<KernelCheckpoint>,
    pub inclusion: ReceiptInclusionProof,
    pub transparency: CheckpointTransparencySummary,
    pub signer_statuses: Vec<SignedFindingAuthorityStatus>,
}

pub(super) fn enabled(policy: &Policy) -> bool {
    policy.finding_context.schema == super::finding_acceptance::EXECUTION_CONTEXT_SCHEMA
}

pub(super) fn checkpoint_ref(bundle: &Bundle) -> Result<String> {
    let [checkpoint] = bundle.checkpoints.as_slice() else {
        return Err("execution profile requires one checkpoint".into());
    };
    Ok(format!(
        "{}#{}",
        chio_kernel::checkpoint::checkpoint_log_id(checkpoint),
        checkpoint.body.checkpoint_seq
    ))
}

/// Authenticate the original public source bindings independently of the
/// financial decision. The actual Finding verifier supplies standing and facets.
pub(super) fn validate(
    bundle: &Bundle,
    policy: &Policy,
    binding: &Binding,
    request: &chio_kernel::ToolCallRequest,
) -> Result<()> {
    if !enabled(policy)
        || bundle.schema != BUNDLE_SCHEMA
        || canonical_json_bytes(bundle)?.len() > super::wire::MAX_ARTIFACT_BYTES
    {
        return Err("unsupported or oversized execution evidence bundle".into());
    }
    let metadata = verify_pre_settlement_execution_receipt(
        &bundle.receipt,
        std::slice::from_ref(&policy.provider_key),
    )?;
    if metadata.authority_uuid != policy.authority_uuid
        || metadata.authority_uuid != binding.authority_uuid
        || metadata.operation_id != binding.operation_id
        || metadata.request_id != request.request_id
        || metadata.request_sha256 != binding.request_sha256
        || metadata.request_sha256 != digest(request)?
        || metadata.hold_id != binding.hold_id
        || metadata.authorization_id != binding.authorization_id
        || metadata.outcome_id != binding.outcome_id
        || metadata.raw_outcome_sha256 != binding.raw_outcome_sha256
        || bundle.receipt.tool_server != super::native::SERVER
        || bundle.receipt.tool_name != "review"
        || bundle.receipt.capability_id != request.capability.id
        || bundle.receipt.policy_hash != digest(policy)?
        || digest(&bundle.receipt.action.parameters)? != digest(&request.arguments)?
        || bundle.receipt.timestamp < request.capability.issued_at
        || bundle.receipt.timestamp >= binding.expires_at
    {
        return Err("execution evidence differs from original native source".into());
    }
    let [checkpoint] = bundle.checkpoints.as_slice() else {
        return Err("execution profile requires one checkpoint".into());
    };
    if checkpoint.body.checkpoint_seq != 1
        || checkpoint.body.batch_start_seq != 1
        || checkpoint.body.batch_end_seq != 1
        || checkpoint.body.tree_size != 1
        || checkpoint.body.previous_checkpoint_sha256.is_some()
        || checkpoint.body.chain_root.is_none()
        || bundle.inclusion.receipt_seq != 1
        || bundle.inclusion.checkpoint_seq != 1
        || bundle.inclusion.leaf_index != 0
        || bundle.inclusion.proof.leaf_index != 0
        || bundle.inclusion.proof.tree_size != 1
        || bundle.signer_statuses.len() != 2
        || bundle.receipt.timestamp > checkpoint.body.issued_at
        || checkpoint.body.issued_at >= binding.expires_at
    {
        return Err("execution checkpoint exceeds original bounded profile".into());
    }
    let resolved = chio_finding_verifier::ResolvedReceiptEvidence {
        receipt: bundle.receipt.clone(),
        canonical_receipt_bytes: canonical_json_bytes(&bundle.receipt)?,
        inclusion_proof: bundle.inclusion.clone(),
    };
    chio_finding_verifier::verify_checkpoint_membership(
        &[resolved],
        &bundle.checkpoints,
        &bundle.transparency,
        &policy.finding_context.profile.body,
        &checkpoint_ref(bundle)?,
    )?;
    Ok(())
}

/// Resolve custody against the original buyer/provider agreement on every
/// decision replay, including after financial settlement.
pub(super) fn retained(
    policy: &Policy,
    binding: &Binding,
    journal: &Journal,
) -> Result<Option<Bundle>> {
    let bundle: Option<Bundle> = journal.retained(&binding.allocation_id, "execution-evidence")?;
    if !enabled(policy) {
        if bundle.is_some() {
            return Err("legacy context cannot consume execution evidence".into());
        }
        return Ok(None);
    }
    let bundle = bundle.ok_or("required original execution evidence unavailable")?;
    let entry = journal
        .by_operation(&binding.operation_id)?
        .ok_or("original execution allocation unavailable")?;
    entry.agreement.validate(policy, &entry.request)?;
    if entry.allocation != binding.allocation_id
        || digest(&entry.agreement.body)? != binding.agreement_sha256
        || binding.expires_at != entry.agreement.body.work.refund_after
        || entry.hold.as_deref() != Some(binding.hold_id.as_str())
        || super::rail::authorization_id(&entry.allocation)? != binding.authorization_id
    {
        return Err("execution custody changed original funding identity".into());
    }
    validate(&bundle, policy, binding, &entry.request)?;
    validate_checkpoint_custody(&bundle, binding, journal)?;
    Ok(Some(bundle))
}

fn validate_checkpoint_custody(
    bundle: &Bundle,
    binding: &Binding,
    journal: &Journal,
) -> Result<()> {
    let checkpoint: KernelCheckpoint = journal
        .retained(&binding.allocation_id, "execution-checkpoint")?
        .ok_or("original execution checkpoint custody unavailable")?;
    if canonical_json_bytes(&bundle.checkpoints)? != canonical_json_bytes(&[checkpoint])? {
        return Err("execution bundle changed the first retained checkpoint".into());
    }
    Ok(())
}

/// A new claim authenticates evidence at the present time. Already accepted
/// work instead replays the retained decision at its original evaluation time.
pub(super) fn verify_claim(
    policy: &Policy,
    journal: &Journal,
    entry: &super::journal::Entry,
    submission: &super::evidence::Submission,
) -> Result<()> {
    let bundle = retained(policy, &submission.body.binding, journal)?
        .ok_or("execution claim has no original evidence")?;
    let output = super::evidence::decode(&journal.blob(&bundle.receipt.content_hash)?)?;
    let original = super::evidence::Evidence {
        binding: submission.body.binding.clone(),
        input: entry.request.arguments["input"]
            .as_str()
            .ok_or("original input missing")?
            .to_owned(),
        output,
        execution: Some(bundle.clone()),
    };
    super::evidence::verify(
        &canonical_json_bytes(submission)?,
        &original,
        policy,
        journal,
    )?;
    let assessment = super::finding_acceptance::evaluate_with_evidence(
        &canonical_json_bytes(&submission.body.finding)?,
        &policy.finding_context,
        &entry.agreement.body.finding_context_sha256,
        &[],
        common::now()?,
        Some(&bundle),
    )?;
    if assessment.outcome != super::finding_acceptance::Outcome::Accepted {
        return Err("original execution evidence cannot authorize a claim".into());
    }
    Ok(())
}

/// Export never dispatches or settles. A fresh export is checkpointed before
/// Finding issuance; replay authenticates the retained native projection first.
pub(super) fn retain(
    native: &Native,
    state: &Path,
    request: &chio_kernel::ToolCallRequest,
    binding: &Binding,
    output: &serde_json::Value,
    checkpoint: &super::Checkpoint,
) -> Result<Bundle> {
    checkpoint("before-execution-evidence")?;
    let receipt = native.kernel.export_durable_execution_evidence(request)?;
    checkpoint("after-execution-evidence")?;
    let metadata = verify_pre_settlement_execution_receipt(
        &receipt,
        std::slice::from_ref(&native.policy.provider_key),
    )?;
    if metadata.resolved_output_sha256 != digest(output)? {
        return Err("funded W0 output differs from native guard-approved value".into());
    }
    native.journal.put_blob(&canonical_json_bytes(output)?)?;
    if let Some(bundle) = native
        .journal
        .retained::<Bundle>(&binding.allocation_id, "execution-evidence")?
    {
        if canonical_json_bytes(&bundle.receipt)? != canonical_json_bytes(&receipt)? {
            return Err("execution custody differs from the original native projection".into());
        }
        validate(&bundle, &native.policy, binding, request)?;
        validate_checkpoint_custody(&bundle, binding, &native.journal)?;
        return Ok(bundle);
    }
    for kind in ["submission", "decision"] {
        if native
            .journal
            .retained::<serde_json::Value>(&binding.allocation_id, kind)?
            .is_some()
        {
            return Err("execution custody disappeared after Finding issuance".into());
        }
    }
    let key = common::key(&state.join("checkpoint"))?;
    let context = &native.policy.finding_context;
    let [log] = context.profile.body.checkpoint_logs.as_slice() else {
        return Err("execution context requires one pinned log".into());
    };
    if key.public_key() != log.signer.key {
        return Err("checkpoint signer differs from original context".into());
    }
    // Native receipt-store checkpoints intentionally share the receipt signer.
    // This separately pinned one-leaf log uses the common checkpoint builder
    // and immutable original journal custody without changing that store rule.
    let signed = match native
        .journal
        .retained::<KernelCheckpoint>(&binding.allocation_id, "execution-checkpoint")?
    {
        Some(signed) => signed,
        None => {
            let signed = chio_kernel::checkpoint::build_checkpoint(
                1,
                1,
                1,
                &[canonical_json_bytes(&receipt)?],
                &key,
            )?;
            native
                .journal
                .retain(&binding.allocation_id, "execution-checkpoint", &signed)?;
            signed
        }
    };
    checkpoint("after-execution-checkpoint")?;
    let tree =
        chio_core_types::merkle::MerkleTree::from_leaves(&[canonical_json_bytes(&receipt)?])?;
    let inclusion = chio_kernel::checkpoint::build_inclusion_proof(&tree, 0, 1, 1)?;
    let checkpoints = vec![signed];
    let transparency = chio_kernel::checkpoint::validate_checkpoint_transparency(&checkpoints)?;
    let status_key = common::key(&state.join("status"))?;
    if status_key.public_key() != context.governance_standing.status_authority.key {
        return Err("status signer differs from original context".into());
    }
    let production = context
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|p| p.role == FindingReceiptRole::Production)
        .ok_or("production signer missing")?;
    let observed_at = common::now()?;
    if observed_at < checkpoints[0].body.issued_at || observed_at < receipt.timestamp {
        return Err("status observation precedes signed execution artifacts".into());
    }
    let signer_statuses = [&production.policy, &log.signer]
        .into_iter()
        .map(|policy| {
            SignedExportEnvelope::sign(
                FindingAuthorityStatus {
                    schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.into(),
                    status_ref: policy.revocation_status_ref.clone(),
                    authority_id: policy.authority_id.clone(),
                    key: policy.key.clone(),
                    key_epoch: policy.key_epoch,
                    revoked_from: None,
                    observed_at,
                },
                &status_key,
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let bundle = Bundle {
        schema: BUNDLE_SCHEMA.into(),
        receipt,
        checkpoints,
        inclusion,
        transparency,
        signer_statuses,
    };
    validate(&bundle, &native.policy, binding, request)?;
    native
        .journal
        .retain(&binding.allocation_id, "execution-evidence", &bundle)?;
    checkpoint("after-execution-custody")?;
    Ok(bundle)
}
