use super::*;
use chio_core_types::capability::scope::MonetaryAmount;

fn fixture() -> Result<(AcceptanceContext, Finding, Keypair)> {
    let signer = Keypair::generate();
    let context = fixture_context(
        &Keypair::generate().public_key(),
        &Keypair::generate().public_key(),
        100,
        1000,
    )?;
    let mut finding = Finding {
        schema: FINDING_SCHEMA_V1.into(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "security:openapi:authentication-declarations".into(),
            context_sha256: "11".repeat(32),
            outcome_class: FindingOutcomeClass::PositiveResult,
        },
        guarantee_class: FindingGuaranteeClass::Asserted,
        payload_sha256: "22".repeat(32),
        payload_media_type: "application/json".into(),
        evidence_receipt_ids: Vec::new(),
        evidence_checkpoint_ref: "unavailable:pre-settlement".into(),
        evidence_cost: MonetaryAmount {
            units: 100,
            currency: "USD".into(),
        },
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Asserted,
        replay_recipe_sha256: None,
        intent_commitment_receipt_id: None,
        bond_ref: "unbacked:experimental-funded-w0".into(),
        status_feed_ref: "unavailable:experimental-funded-w0".into(),
        license_ref: None,
        price_hint_ref: None,
        issuer: signer.public_key(),
        issued_at: 100,
        expires_at: 1000,
        signature: String::new(),
    };
    finding.finding_id = compute_finding_id(&finding)?;
    Ok((context, sign_finding(finding, &signer)?, signer))
}

#[test]
fn asserted_w0_has_exact_derived_facets_and_no_backing_upgrade() -> Result<()> {
    let (context, finding, _) = fixture()?;
    let pin = digest(&context)?;
    let result = evaluate_finding(&finding, &context, &pin, &[], 110)?;
    assert_eq!(result.outcome, Outcome::Accepted);
    assert_eq!(result.facets.len(), 13);
    for kind in [
        FindingFacetKind::ReceiptAuthenticity,
        FindingFacetKind::CheckpointMembership,
        FindingFacetKind::SettledSpendBacking,
        FindingFacetKind::BondBacking,
        FindingFacetKind::StatusLiveness,
        FindingFacetKind::RuntimeAssuranceBacking,
    ] {
        assert!(result
            .facets
            .iter()
            .any(|f| f.facet == kind && f.outcome != FindingFacetOutcome::Verified));
    }
    validate_assessment(&result, &finding, &context, &[])?;
    Ok(())
}

#[test]
fn missing_required_and_unsupported_facets_deny() -> Result<()> {
    let (context, finding, _) = fixture()?;
    for (kind, outcome) in [
        (FindingFacetKind::SettledSpendBacking, Outcome::Unavailable),
        (FindingFacetKind::BondBacking, Outcome::Unavailable),
        (FindingFacetKind::IssuerLineage, Outcome::Unsupported),
    ] {
        let result = evaluate_finding(&finding, &context, &digest(&context)?, &[kind], 110)?;
        assert_eq!(result.outcome, outcome);
    }
    Ok(())
}

#[test]
fn changed_claim_and_optional_failed_facet_deny() -> Result<()> {
    let (context, mut finding, signer) = fixture()?;
    finding.evidence_class = FindingEvidenceClass::Observed;
    finding.evidence_receipt_ids = vec!["unresolved:receipt".into()];
    finding.finding_id = compute_finding_id(&finding)?;
    finding = sign_finding(finding, &signer)?;
    let result = evaluate_finding(&finding, &context, &digest(&context)?, &[], 110)?;
    assert_eq!(result.outcome, Outcome::Rejected);
    assert_eq!(
        classify(&result.facets, &[FindingFacetKind::ArtifactIntegrity]),
        Outcome::Rejected
    );
    assert!(result
        .facets
        .iter()
        .any(|f| f.facet == FindingFacetKind::GuaranteeConsistency
            && f.outcome == FindingFacetOutcome::Failed));
    Ok(())
}

#[test]
fn changed_trust_profile_and_standing_fail_closed() -> Result<()> {
    let (mut context, finding, _) = fixture()?;
    let pin = digest(&context)?;
    context.profile.body.operator.push_str("-changed");
    assert!(evaluate_finding(&finding, &context, &pin, &[], 110).is_err());
    assert!(evaluate_finding(&finding, &context, &digest(&context)?, &[], 110).is_err());
    let (mut context, finding, _) = fixture()?;
    context.governance_standing.signed_statuses.clear();
    assert!(evaluate_finding(&finding, &context, &digest(&context)?, &[], 110).is_err());
    Ok(())
}

#[test]
fn raw_ingress_and_relabelled_assessment_deny() -> Result<()> {
    let (context, finding, _) = fixture()?;
    let pin = digest(&context)?;
    let raw = serde_json::to_vec_pretty(&finding)?;
    assert!(evaluate(&raw, &context, &pin, &[], 110).is_err());
    let mut result = evaluate_finding(
        &finding,
        &context,
        &pin,
        &[FindingFacetKind::BondBacking],
        110,
    )?;
    result.outcome = Outcome::Accepted;
    assert!(validate_assessment(
        &result,
        &finding,
        &context,
        &[FindingFacetKind::BondBacking]
    )
    .is_err());
    Ok(())
}

#[test]
fn trust_time_and_authentication_cannot_be_refreshed_by_evaluator() -> Result<()> {
    let (context, finding, _) = fixture()?;
    assert!(evaluate_finding(&finding, &context, &digest(&context)?, &[], 99).is_err());
    assert!(evaluate_finding(&finding, &context, &digest(&context)?, &[], 1000).is_err());
    let mut changed = context.clone();
    changed.governance_standing.signed_statuses[0]
        .body
        .observed_at = 110;
    assert!(evaluate_finding(&finding, &changed, &digest(&changed)?, &[], 110).is_err());
    changed = context;
    changed.governance_authority.key = Keypair::generate().public_key();
    assert!(evaluate_finding(&finding, &changed, &digest(&changed)?, &[], 110).is_err());
    Ok(())
}

#[test]
fn context_admission_checks_independent_role_pins_and_time() -> Result<()> {
    let (context, _, _) = fixture()?;
    let verifier = &context.profile.body.verifier_report_signer.key;
    let kernel = &context.admitted_kernel_key;
    validate_context(&context, verifier, kernel, 110)?;
    assert!(validate_context(&context, &Keypair::generate().public_key(), kernel, 110).is_err());
    assert!(validate_context(&context, verifier, &Keypair::generate().public_key(), 110).is_err());
    assert!(validate_context(&context, verifier, kernel, 1000).is_err());
    let mut changed = context.clone();
    changed.profile.body.required_facets.pop();
    assert!(validate_context(&changed, verifier, kernel, 110).is_err());
    Ok(())
}

#[test]
fn retained_assessment_uses_historical_authority_window() -> Result<()> {
    let (context, finding, _) = fixture()?;
    let assessment = evaluate_finding(&finding, &context, &digest(&context)?, &[], 110)?;
    assert!(validate_context(
        &context,
        &context.profile.body.verifier_report_signer.key,
        &context.admitted_kernel_key,
        1001
    )
    .is_err());
    validate_assessment(&assessment, &finding, &context, &[])?;
    let mut forged = assessment;
    forged.evaluated_at = 1001;
    assert!(validate_assessment(&forged, &finding, &context, &[]).is_err());
    Ok(())
}

#[test]
fn invented_optional_verified_facet_cannot_be_authorized_by_resigning() -> Result<()> {
    let (context, finding, _) = fixture()?;
    let mut assessment = evaluate_finding(&finding, &context, &digest(&context)?, &[], 110)?;
    let facet = assessment
        .facets
        .iter_mut()
        .find(|f| f.facet == FindingFacetKind::BondBacking)
        .ok_or("bond facet missing")?;
    facet.outcome = FindingFacetOutcome::Verified;
    assert_eq!(assessment.outcome, Outcome::Accepted);
    assert!(validate_assessment(&assessment, &finding, &context, &[]).is_err());
    Ok(())
}

#[test]
fn invented_evidence_digest_cannot_be_authorized_by_resigning() -> Result<()> {
    let (context, finding, _) = fixture()?;
    let mut assessment = evaluate_finding(&finding, &context, &digest(&context)?, &[], 110)?;
    assessment.resolved_evidence_bundle_sha256 = "00".repeat(32);
    assert!(validate_assessment(&assessment, &finding, &context, &[]).is_err());
    Ok(())
}

#[test]
fn execution_context_pins_external_keys_and_requires_receipts_before_agreement() -> Result<()> {
    let verifier = Keypair::generate();
    let kernel = Keypair::generate();
    let checkpoint = Keypair::generate();
    let status = Keypair::generate();
    let context = fixture_execution_context(
        &verifier.public_key(),
        &kernel.public_key(),
        checkpoint.public_key(),
        &status,
        100,
        1000,
    )?;
    assert_eq!(
        context.schema,
        "chio.experimental.funded-finding-context.v2"
    );
    assert_eq!(
        context.profile.body.required_receipt_semantics,
        "chio.pre_settlement_execution.v1"
    );
    assert_eq!(
        context.profile.body.checkpoint_logs[0].signer.key,
        checkpoint.public_key()
    );
    assert_eq!(
        context.governance_standing.status_authority.key,
        status.public_key()
    );
    assert_eq!(
        context.profile.body.required_facets,
        vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::GuaranteeConsistency,
        ]
    );
    validate_context(&context, &verifier.public_key(), &kernel.public_key(), 110)?;
    let (_, finding, _) = fixture()?;
    let assessment = evaluate_finding(&finding, &context, &digest(&context)?, &[], 110)?;
    assert_eq!(assessment.outcome, Outcome::Unavailable);
    Ok(())
}

fn execution_fixture() -> Result<(
    AcceptanceContext,
    Finding,
    super::super::execution_evidence::Bundle,
)> {
    use chio_core_types::receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::{ToolOrigin, TrustLevel},
    };
    use chio_kernel::checkpoint::{
        build_checkpoint, build_checkpoint_transparency, build_inclusion_proof,
    };
    let verifier = Keypair::generate();
    let kernel = Keypair::generate();
    let checkpoint_key = Keypair::generate();
    let status = Keypair::generate();
    let context = fixture_execution_context(
        &verifier.public_key(),
        &kernel.public_key(),
        checkpoint_key.public_key(),
        &status,
        100,
        1000,
    )?;
    let hash = "ab".repeat(32);
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: 101,
            capability_id: "cap-1".into(),
            tool_server: "native".into(),
            tool_name: "test".into(),
            action: ToolCallAction::from_parameters(serde_json::json!({"input":1}))?,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: hash.clone(),
            policy_hash: hash.clone(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "receipt_semantics": {"profile":"chio.pre_settlement_execution.v1"},
                "execution_evidence": {
                    "schema":"chio.execution_evidence.v1", "phase":"execution_confirmed",
                    "authority_uuid":"authority-1", "operation_id":"operation-1", "request_id":"request-1",
                    "request_binding_hash":hash, "request_sha256":hash, "hold_id":"hold-1",
                    "authorization_id":"authorization-1", "outcome_id":hash, "raw_outcome_sha256":hash,
                    "resolved_output_sha256":hash, "post_return_evaluation_sha256":hash,
                    "post_guard_decision_sha256":hash, "pricing_verdict_sha256":hash
                }
            })),
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        &kernel,
    )?;
    let leaves = vec![canonical_json_bytes(&receipt)?];
    let tree = chio_core_types::MerkleTree::from_leaves(&leaves)?;
    let mut checkpoint = build_checkpoint(1, 1, 1, &leaves, &checkpoint_key)?;
    checkpoint.body.issued_at = 102;
    checkpoint.signature = checkpoint_key.sign(&canonical_json_bytes(&checkpoint.body)?);
    let production = &context
        .profile
        .body
        .receipt_signers
        .iter()
        .find(|r| r.role == FindingReceiptRole::Production)
        .ok_or("production role missing")?
        .policy;
    let signer_statuses = [production, &context.profile.body.checkpoint_logs[0].signer]
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
                    observed_at: 104,
                },
                &status,
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let bundle = super::super::execution_evidence::Bundle {
        schema: super::super::execution_evidence::BUNDLE_SCHEMA.into(),
        receipt,
        transparency: build_checkpoint_transparency(std::slice::from_ref(&checkpoint))?,
        checkpoints: vec![checkpoint],
        inclusion: build_inclusion_proof(&tree, 0, 1, 1)?,
        signer_statuses,
    };
    let (_, mut finding, signer) = fixture()?;
    finding.issued_at = 103;
    finding.evidence_receipt_ids = vec![bundle.receipt.id.clone()];
    finding.evidence_checkpoint_ref = format!(
        "{}#1",
        finding_checkpoint_log_id(&checkpoint_key.public_key())
    );
    finding.signature.clear();
    finding.finding_id = compute_finding_id(&finding)?;
    Ok((context, sign_finding(finding, &signer)?, bundle))
}

#[test]
fn execution_evidence_is_required_and_assessment_replays_exact_bundle() -> Result<()> {
    let (context, finding, evidence) = execution_fixture()?;
    let raw = canonical_json_bytes(&finding)?;
    let pin = digest(&context)?;
    let assessment = evaluate_with_evidence(&raw, &context, &pin, &[], 110, Some(&evidence))?;
    assert_eq!(assessment.outcome, Outcome::Accepted);
    for kind in [
        FindingFacetKind::ReceiptAuthenticity,
        FindingFacetKind::CheckpointMembership,
    ] {
        assert!(assessment
            .facets
            .iter()
            .any(|f| f.facet == kind && f.outcome == FindingFacetOutcome::Verified));
    }
    validate_assessment_with_evidence(&assessment, &finding, &context, &[], Some(&evidence))?;
    assert!(validate_assessment_with_evidence(&assessment, &finding, &context, &[], None).is_err());
    for kind in [
        FindingFacetKind::MeteredExposureBacking,
        FindingFacetKind::SettledSpendBacking,
    ] {
        let result = evaluate_with_evidence(&raw, &context, &pin, &[kind], 110, Some(&evidence))?;
        assert_eq!(result.outcome, Outcome::Unavailable);
    }
    let mut changed = evidence.clone();
    changed.inclusion.receipt_seq = 2;
    assert!(validate_assessment_with_evidence(
        &assessment,
        &finding,
        &context,
        &[],
        Some(&changed)
    )
    .is_err());
    let changed_result = evaluate_with_evidence(&raw, &context, &pin, &[], 110, Some(&changed));
    assert!(changed_result.is_err() || changed_result?.outcome != Outcome::Accepted);
    Ok(())
}

#[test]
fn execution_context_rejects_extra_and_foreign_standing_and_legacy_profile_mixing() -> Result<()> {
    let (context, finding, evidence) = execution_fixture()?;
    let raw = canonical_json_bytes(&finding)?;
    let pin = digest(&context)?;
    for mutation in ["extra", "missing", "foreign", "reordered", "early"] {
        let mut changed = evidence.clone();
        match mutation {
            "extra" => changed
                .signer_statuses
                .push(changed.signer_statuses[0].clone()),
            "missing" => {
                changed.signer_statuses.pop();
            }
            "foreign" => changed.signer_statuses[0].body.key = Keypair::generate().public_key(),
            "reordered" => changed.signer_statuses.reverse(),
            _ => changed.signer_statuses[0].body.observed_at = 100,
        }
        let result = evaluate_with_evidence(&raw, &context, &pin, &[], 110, Some(&changed));
        assert!(
            result.is_err() || result?.outcome != Outcome::Accepted,
            "{mutation}"
        );
    }
    let (legacy, legacy_finding, _) = fixture()?;
    assert!(evaluate_with_evidence(
        &canonical_json_bytes(&legacy_finding)?,
        &legacy,
        &digest(&legacy)?,
        &[],
        110,
        Some(&evidence)
    )
    .is_err());
    Ok(())
}

#[test]
fn execution_context_rejects_aliased_receipt_checkpoint_and_status_keys() -> Result<()> {
    let verifier = Keypair::generate();
    let kernel = Keypair::generate();
    let checkpoint = Keypair::generate();
    let status = Keypair::generate();
    assert!(fixture_execution_context(
        &verifier.public_key(),
        &kernel.public_key(),
        kernel.public_key(),
        &status,
        100,
        1000
    )
    .is_err());
    assert!(fixture_execution_context(
        &verifier.public_key(),
        &kernel.public_key(),
        checkpoint.public_key(),
        &kernel,
        100,
        1000
    )
    .is_err());
    assert!(fixture_execution_context(
        &verifier.public_key(),
        &kernel.public_key(),
        checkpoint.public_key(),
        &verifier,
        100,
        1000
    )
    .is_err());
    Ok(())
}
