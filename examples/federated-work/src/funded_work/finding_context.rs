//! Pre-agreement local authority provisioning for legacy and execution contexts.
use super::*;

/// Legacy local fixture with discarded checkpoint and standing private keys.
pub fn fixture_context(
    verifier_key: &PublicKey,
    kernel_key: &PublicKey,
    now: u64,
    expires_at: u64,
) -> Result<AcceptanceContext> {
    build_context(
        verifier_key,
        kernel_key,
        Keypair::generate().public_key(),
        ContextSigners {
            governance: &Keypair::generate(),
            status: &Keypair::generate(),
        },
        now,
        expires_at,
        false,
    )
}

/// Pins the retained external checkpoint and status signers before agreement.
/// The generated governance private key is discarded after signing this context.
pub fn fixture_execution_context(
    verifier_key: &PublicKey,
    kernel_key: &PublicKey,
    checkpoint_key: PublicKey,
    status: &Keypair,
    now: u64,
    expires_at: u64,
) -> Result<AcceptanceContext> {
    let context = build_context(
        verifier_key,
        kernel_key,
        checkpoint_key,
        ContextSigners {
            governance: &Keypair::generate(),
            status,
        },
        now,
        expires_at,
        true,
    )?;
    validate_context(&context, verifier_key, kernel_key, now)?;
    Ok(context)
}

pub struct ContextSigners<'a> {
    pub governance: &'a Keypair,
    pub status: &'a Keypair,
}

/// Sign the same bounded profile with externally held governance/status keys.
pub fn signed_execution_context(
    verifier: &PublicKey,
    kernel: &PublicKey,
    checkpoint: PublicKey,
    signers: ContextSigners<'_>,
    now: u64,
    expires: u64,
) -> Result<AcceptanceContext> {
    let context = build_context(verifier, kernel, checkpoint, signers, now, expires, true)?;
    validate_context(&context, verifier, kernel, now)?;
    Ok(context)
}

fn authority(key: PublicKey, role: &str, now: u64, expires_at: u64) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("funded-w0-fixture/{role}"),
        key,
        key_epoch: 1,
        valid_from: now,
        valid_until: expires_at,
        rotation_policy_ref: format!("funded-w0-fixture/rotation/{role}"),
        revocation_status_ref: format!("funded-w0-fixture/status/{role}"),
    }
}

fn build_context(
    verifier_key: &PublicKey,
    kernel_key: &PublicKey,
    checkpoint_key: PublicKey,
    signers: ContextSigners<'_>,
    now: u64,
    expires_at: u64,
    execution: bool,
) -> Result<AcceptanceContext> {
    if now >= expires_at || expires_at - now > 86400 {
        return Err("Finding fixture trust requires a bounded one-day window".into());
    }
    let ContextSigners { governance, status } = signers;
    let new_authority = |role| authority(Keypair::generate().public_key(), role, now, expires_at);
    let governance_authority = authority(governance.public_key(), "governance", now, expires_at);
    let checkpoint = authority(checkpoint_key, "checkpoint", now, expires_at);
    let mut body = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.into(),
        profile_id: String::new(),
        governance_authority: governance.public_key(),
        operator: "funded-w0-fixture".into(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: authority(kernel_key.clone(), "production", now, expires_at),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: new_authority("delivery"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: new_authority("replay"),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id: finding_checkpoint_log_id(&checkpoint.key),
            signer: checkpoint,
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "unavailable:funded-w0-fixture".into(),
            key_hex: "00".repeat(32),
            registry_ref: "unavailable:funded-w0-fixture".into(),
            key_epoch: 1,
            valid_from: now,
            valid_until: expires_at,
            revocation_status_ref: "unavailable:funded-w0-fixture".into(),
        },
        allowed_runner_manifests: vec![digest(&"funded-w0-no-replay-runner")?],
        required_receipt_semantics: if execution {
            chio_core_types::receipt::execution_evidence::PRE_SETTLEMENT_EXECUTION_PROFILE
        } else {
            "chio.mediated_spend.v1"
        }
        .into(),
        resolver_policy_ref: if execution {
            "funded-w0-execution-evidence-v1"
        } else {
            "funded-w0-empty-evidence-v1"
        }
        .into(),
        retention_policy_ref: "funded-w0-journal-v1".into(),
        resource_caps: FindingResourceCaps {
            max_recipe_bytes: 262144,
            max_evidence_receipts: 1,
            max_runtime_secs: 60,
            max_memory_bytes: 16777216,
        },
        predicate_engine: FINDING_PREDICATE_ENGINE_CHIO_REPLAY_V1.into(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: context_floor(execution),
        verifier_report_signer: authority(verifier_key.clone(), "verifier", now, expires_at),
        purchase_authority: new_authority("purchase"),
        failed_delivery_authority: new_authority("failed-delivery"),
        issued_at: now,
        expires_at,
    };
    body.profile_id = compute_profile_id(&body)?;
    let profile = SignedExportEnvelope::sign(body, governance)?;
    let standing = SignedExportEnvelope::sign(
        FindingAuthorityStatus {
            schema: FINDING_AUTHORITY_STATUS_SCHEMA_V1.into(),
            status_ref: governance_authority.revocation_status_ref.clone(),
            authority_id: governance_authority.authority_id.clone(),
            key: governance.public_key(),
            key_epoch: 1,
            revoked_from: None,
            observed_at: now,
        },
        status,
    )?;
    Ok(AcceptanceContext {
        schema: if execution {
            EXECUTION_CONTEXT_SCHEMA
        } else {
            CONTEXT_SCHEMA
        }
        .into(),
        governance_authority,
        profile,
        governance_standing: FindingCheckpointSignerStatusTrust {
            signed_statuses: vec![standing],
            status_authority: authority(status.public_key(), "authority-status", now, expires_at),
            max_age_secs: expires_at - now,
        },
        admitted_kernel_key: kernel_key.clone(),
        collateral_authority: new_authority("collateral"),
    })
}
