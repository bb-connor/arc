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
