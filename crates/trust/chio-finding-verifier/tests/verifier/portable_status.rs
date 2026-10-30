//! Portable live status proofs: standing, freshness, feed binding and report pinning.

use super::*;

#[test]
fn portable_status_proof_verifies_and_is_pinned_into_signed_report() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    let mut trust = trust_roots(&fx);
    trust.trusted_time = freshness.now;
    install_status_operator_standing(&fx, &mut trust, &authorization, freshness.now)?;
    trust.status_operator_authorization = Some(authorization);
    trust.status_freshness_policy = Some(freshness);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Verified)
    );
    assert_eq!(
        draft.replay_recipe_input_sha256(),
        Some(sha256_hex(&fx.recipe_bytes).as_str())
    );
    assert_eq!(
        draft.status_proof_input_sha256(),
        Some(sha256_hex(&status_bytes).as_str())
    );

    let signed =
        sign_finding_verifier_report(&draft, &trust, "chio-finding-verifier/0.1", &fx.verifier)?;
    verify_signed_verifier_report(&signed, &fx.verifier.public_key())?;
    assert_eq!(
        signed.body.replay_recipe_input_sha256.as_deref(),
        draft.replay_recipe_input_sha256()
    );
    assert_eq!(
        signed.body.status_proof_input_sha256.as_deref(),
        draft.status_proof_input_sha256()
    );
    Ok(())
}

#[test]
fn portable_status_proof_rejects_revoked_operator_standing() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    let mut trust = trust_roots(&fx);
    trust.trusted_time = freshness.now;
    install_status_operator_standing(&fx, &mut trust, &authorization, freshness.now)?;
    let standing = trust
        .checkpoint_signer_status
        .as_mut()
        .ok_or("missing signer-status trust")?
        .signed_statuses
        .iter_mut()
        .find(|status| status.body.authority_id == authorization.operator.authority_id)
        .ok_or("status operator standing missing")?;
    standing.body.revoked_from = Some(freshness.now);
    *standing = SignedExportEnvelope::sign(standing.body.clone(), &fx.checkpoint_status_authority)?;
    trust.status_operator_authorization = Some(authorization);
    trust.status_freshness_policy = Some(freshness);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let status = draft
        .facets()
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::StatusLiveness)
        .ok_or("status-liveness facet missing")?;
    assert_eq!(status.outcome, FindingFacetOutcome::Failed);
    assert!(status.reason.contains("status operator is revoked"));
    Ok(())
}

#[test]
fn resolved_bundle_commitment_includes_status_authorization_and_freshness() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let mut baseline_trust = trust_roots(&fx);
    baseline_trust.trusted_time = freshness.now;
    install_status_operator_standing(&fx, &mut baseline_trust, &authorization, freshness.now)?;
    baseline_trust.status_operator_authorization = Some(authorization.clone());
    baseline_trust.status_freshness_policy = Some(freshness);
    let baseline = verify_finding_evidence(&fx.raw_finding, &baseline_trust, &evidence)?;
    assert_eq!(
        baseline.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Verified)
    );

    let baseline_authorization = authorization.clone();
    let mut alternate_authorization = authorization;
    alternate_authorization.operator.rotation_policy_ref =
        "status-rotation-policy/alternate".to_owned();
    let mut authorization_trust = trust_roots(&fx);
    authorization_trust.trusted_time = freshness.now;
    install_status_operator_standing(
        &fx,
        &mut authorization_trust,
        &alternate_authorization,
        freshness.now,
    )?;
    authorization_trust.status_operator_authorization = Some(alternate_authorization);
    authorization_trust.status_freshness_policy = Some(freshness);
    let authorization_changed =
        verify_finding_evidence(&fx.raw_finding, &authorization_trust, &evidence)?;
    assert_eq!(
        authorization_changed.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        baseline.resolved_evidence_bundle_sha256(),
        authorization_changed.resolved_evidence_bundle_sha256()
    );

    let mut freshness_trust = trust_roots(&fx);
    freshness_trust.trusted_time = freshness.now;
    install_status_operator_standing(
        &fx,
        &mut freshness_trust,
        &baseline_authorization,
        freshness.now,
    )?;
    freshness_trust.status_operator_authorization = Some(baseline_authorization);
    freshness_trust.status_freshness_policy = Some(FindingStatusFreshnessPolicy {
        now: freshness.now,
        max_epoch_age_secs: freshness.max_epoch_age_secs + 1,
    });
    let freshness_changed = verify_finding_evidence(&fx.raw_finding, &freshness_trust, &evidence)?;
    assert_eq!(
        freshness_changed.facet_outcome(FindingFacetKind::StatusLiveness),
        Some(FindingFacetOutcome::Verified)
    );
    assert_ne!(
        baseline.resolved_evidence_bundle_sha256(),
        freshness_changed.resolved_evidence_bundle_sha256()
    );
    Ok(())
}

#[test]
fn portable_status_proof_rejects_a_clock_different_from_report_evaluation() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) = portable_live_status_proof(&finding.finding_id)?;
    let mut trust = trust_roots(&fx);
    trust.status_operator_authorization = Some(authorization);
    trust.status_freshness_policy = Some(freshness);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let status = draft
        .facets()
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::StatusLiveness)
        .ok_or("status-liveness facet missing")?;
    assert_eq!(status.outcome, FindingFacetOutcome::Failed);
    assert!(
        status.reason.contains("report evaluation time"),
        "unexpected reason: {}",
        status.reason
    );
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}

#[test]
fn portable_status_proof_must_bind_the_findings_declared_feed() -> TestResult {
    let fx = fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    let (status_bytes, authorization, freshness) =
        portable_live_status_proof_for_feed(&finding.finding_id, "status-feed/substituted")?;
    let mut trust = trust_roots(&fx);
    trust.trusted_time = freshness.now;
    trust.status_operator_authorization = Some(authorization);
    trust.status_freshness_policy = Some(freshness);
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.status_proof_input = Some(&status_bytes);

    let draft = verify_finding_evidence(&fx.raw_finding, &trust, &evidence)?;
    let status = draft
        .facets()
        .iter()
        .find(|facet| facet.facet == FindingFacetKind::StatusLiveness)
        .ok_or("status-liveness facet missing")?;
    assert_eq!(status.outcome, FindingFacetOutcome::Failed);
    assert!(
        status.reason.contains("Finding status feed"),
        "unexpected reason: {}",
        status.reason
    );
    assert!(!draft.satisfies_required_facets(&fx.profile.body));
    Ok(())
}
