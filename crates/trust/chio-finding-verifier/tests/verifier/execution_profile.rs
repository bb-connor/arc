use super::*;

const EXECUTION_PROFILE: &str = "chio.pre_settlement_execution.v1";

fn bundle<'a>(
    fx: &'a Fixture,
    receipts: Vec<ResolvedReceiptEvidence>,
) -> FindingEvidenceBundle<'a> {
    let mut evidence = super::bundle(fx, receipts);
    // The legacy fixture's recipe and collateral bind its original Finding
    // and profile. This execution-only fixture supplies neither authority.
    evidence.recipe_preimage = None;
    evidence.bond_snapshot = None;
    evidence
}

fn execution_fixture() -> Result<Fixture, Box<dyn Error>> {
    let mut fx = fixture()?;
    let mut profile = fx.profile.body.clone();
    profile.required_receipt_semantics = EXECUTION_PROFILE.to_owned();
    profile.required_facets = vec![
        FindingFacetKind::ArtifactIntegrity,
        FindingFacetKind::ReceiptAuthenticity,
        FindingFacetKind::CheckpointMembership,
        FindingFacetKind::GuaranteeConsistency,
    ];
    fx.profile = resign_profile(profile)?;
    for (index, evidence) in fx.receipts.iter_mut().enumerate() {
        let mut body = evidence.receipt.body();
        body.tool_origin = chio_core_types::receipt::kinds::ToolOrigin::ChioInternal;
        body.metadata = Some(serde_json::json!({"execution_evidence": {
            "schema": "chio.execution_evidence.v1",
            "phase": "execution_confirmed",
            "authority_uuid": "11111111-1111-4111-8111-111111111111",
            "operation_id": format!("operation-{index}"),
            "request_id": format!("request-{index}"),
            "request_binding_hash": HEX64,
            "request_sha256": HEX64,
            "hold_id": format!("hold-{index}"),
            "authorization_id": format!("authorization-{index}"),
            "outcome_id": "07".repeat(32),
            "raw_outcome_sha256": HEX64,
            "resolved_output_sha256": body.content_hash,
            "post_return_evaluation_sha256": HEX64,
            "post_guard_decision_sha256": HEX64,
            "pricing_verdict_sha256": HEX64
        }, "receipt_semantics": {"profile": EXECUTION_PROFILE}}));
        evidence.receipt = ChioReceipt::sign(body, &keypair(21))?;
    }
    rebind_execution_evidence(&mut fx)?;
    Ok(fx)
}

/// Rebuild the authenticated checkpoint and Finding after an intentional signed
/// receipt change, so a negative case reaches the semantic check under test.
fn rebind_execution_evidence(fx: &mut Fixture) -> TestResult {
    let leaves = fx
        .receipts
        .iter()
        .map(|evidence| canonical_json_bytes(&evidence.receipt))
        .collect::<Result<Vec<_>, _>>()?;
    let tree = MerkleTree::from_leaves(&leaves)?;
    fx.checkpoint = checkpoint_at(
        build_checkpoint(1, 1, u64::try_from(leaves.len())?, &leaves, &keypair(23))?,
        1_750_000_001,
        &keypair(23),
    )?;
    fx.checkpoint_transparency =
        build_checkpoint_transparency(std::slice::from_ref(&fx.checkpoint))?;
    for (index, evidence) in fx.receipts.iter_mut().enumerate() {
        evidence.canonical_receipt_bytes = leaves[index].clone();
        evidence.inclusion_proof =
            build_inclusion_proof(&tree, index, 1, u64::try_from(index + 1)?)?;
    }
    let mut finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    finding.evidence_receipt_ids = fx
        .receipts
        .iter()
        .map(|evidence| evidence.receipt.id.clone())
        .collect();
    finding.evidence_checkpoint_ref = format!("{}#1", checkpoint_log_id(&fx.checkpoint));
    finding.guarantee_class = FindingGuaranteeClass::Asserted;
    finding.evidence_class = FindingEvidenceClass::Asserted;
    finding.replay_recipe_sha256 = None;
    finding.signature.clear();
    finding.finding_id = compute_finding_id(&finding)?;
    fx.raw_finding = String::from_utf8(canonical_json_bytes(&sign_finding(finding, &fx.issuer)?)?)?;
    Ok(())
}

#[test]
fn execution_receipts_verify_authenticity_and_membership_without_financial_backing() -> TestResult {
    let fx = execution_fixture()?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.nonce_resolver = &NoNonceEvidence;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust_roots(&fx), &evidence)?;
    for kind in [
        FindingFacetKind::ArtifactIntegrity,
        FindingFacetKind::ReceiptAuthenticity,
        FindingFacetKind::CheckpointMembership,
        FindingFacetKind::GuaranteeConsistency,
    ] {
        assert_eq!(
            draft.facet_outcome(kind),
            Some(FindingFacetOutcome::Verified),
            "{kind:?}"
        );
    }
    for kind in [
        FindingFacetKind::MeteredExposureBacking,
        FindingFacetKind::SettledSpendBacking,
    ] {
        assert_eq!(
            draft.facet_outcome(kind),
            Some(FindingFacetOutcome::Unavailable),
            "{kind:?}"
        );
    }
    Ok(())
}

fn assert_failed_authenticity(fx: &Fixture, evidence: &FindingEvidenceBundle<'_>) -> TestResult {
    let draft = verify_finding_evidence(&fx.raw_finding, &trust_roots(fx), evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Failed)
    );
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::CheckpointMembership),
        Some(FindingFacetOutcome::Failed)
    );
    for kind in [
        FindingFacetKind::MeteredExposureBacking,
        FindingFacetKind::SettledSpendBacking,
    ] {
        assert_ne!(
            draft.facet_outcome(kind),
            Some(FindingFacetOutcome::Verified)
        );
    }
    Ok(())
}

#[test]
fn execution_profile_rejects_missing_and_mixed_production_receipts() -> TestResult {
    let fx = execution_fixture()?;
    assert_failed_authenticity(&fx, &bundle(&fx, Vec::new()))?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.receipts[0] = fixture()?.receipts.remove(0);
    assert_failed_authenticity(&fx, &evidence)?;
    Ok(())
}

#[test]
fn execution_receipt_rejects_signed_financial_or_foreign_profile_metadata() -> TestResult {
    for field in [
        "financial",
        "budget_authority",
        "mediated_spend",
        "foreign_schema",
        "foreign_profile",
        "missing_profile",
        "missing_metadata",
        "wrong_phase",
        "unknown_field",
        "wrong_output",
    ] {
        let mut fx = execution_fixture()?;
        let mut body = fx.receipts[0].receipt.body();
        let metadata = body.metadata.as_mut().ok_or("execution metadata missing")?;
        match field {
            "foreign_profile" => {
                metadata["receipt_semantics"]["profile"] =
                    serde_json::json!("chio.mediated_spend.v1")
            }
            "missing_profile" => {
                metadata
                    .as_object_mut()
                    .ok_or("metadata object missing")?
                    .remove("receipt_semantics");
            }
            "missing_metadata" => {
                metadata
                    .as_object_mut()
                    .ok_or("metadata object missing")?
                    .remove("execution_evidence");
            }
            "foreign_schema" => {
                metadata["execution_evidence"]["schema"] =
                    serde_json::json!("chio.foreign_execution.v1")
            }
            "wrong_phase" => metadata["execution_evidence"]["phase"] = serde_json::json!("settled"),
            "unknown_field" => {
                metadata["execution_evidence"]["spend_units"] = serde_json::json!(10)
            }
            "wrong_output" => {
                metadata["execution_evidence"]["resolved_output_sha256"] = serde_json::json!(HEX64)
            }
            _ => {
                metadata[field] =
                    serde_json::json!({"cost_charged": 1, "settlement_status": "settled"})
            }
        }
        fx.receipts[0].receipt = ChioReceipt::sign(body, &keypair(21))?;
        rebind_execution_evidence(&mut fx)?;
        assert_failed_authenticity(&fx, &bundle(&fx, clone_receipts(&fx)))?;
    }
    Ok(())
}

#[test]
fn execution_receipt_rejects_unsigned_source_hash_and_signature_mutations() -> TestResult {
    let fx = execution_fixture()?;
    for field in [
        "operation_id",
        "request_id",
        "hold_id",
        "outcome_id",
        "content_hash",
        "parameter_hash",
        "signature",
    ] {
        let mut evidence = bundle(&fx, clone_receipts(&fx));
        let receipt = &mut evidence.receipts[0].receipt;
        match field {
            "content_hash" => receipt.content_hash = HEX64.to_owned(),
            "parameter_hash" => receipt.action.parameter_hash = HEX64.to_owned(),
            "signature" => receipt.signature = keypair(21).sign(b"forged execution receipt"),
            _ => {
                receipt.metadata.as_mut().ok_or("metadata missing")?["execution_evidence"][field] =
                    serde_json::json!("substituted-source")
            }
        }
        evidence.receipts[0].canonical_receipt_bytes =
            canonical_json_bytes(&evidence.receipts[0].receipt)?;
        assert_failed_authenticity(&fx, &evidence)?;
    }
    Ok(())
}

#[test]
fn execution_receipt_rejects_resigned_source_substitution_against_original_finding() -> TestResult {
    let fx = execution_fixture()?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    let mut body = evidence.receipts[0].receipt.body();
    body.metadata.as_mut().ok_or("metadata missing")?["execution_evidence"]["operation_id"] =
        serde_json::json!("foreign-operation");
    evidence.receipts[0].receipt = ChioReceipt::sign(body, &keypair(21))?;
    evidence.receipts[0].canonical_receipt_bytes =
        canonical_json_bytes(&evidence.receipts[0].receipt)?;
    assert_failed_authenticity(&fx, &evidence)?;
    Ok(())
}

#[test]
fn execution_receipts_preserve_raw_bytes_and_checkpoint_wrapper_checks() -> TestResult {
    let fx = execution_fixture()?;
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    let mut raw: serde_json::Value =
        serde_json::from_slice(&evidence.receipts[0].canonical_receipt_bytes)?;
    raw["unknown_authority"] = serde_json::json!(true);
    evidence.receipts[0].canonical_receipt_bytes = canonical_json_bytes(&raw)?;
    assert_failed_authenticity(&fx, &evidence)?;
    for mutation in [
        "missing_checkpoint",
        "wrapper_sequence",
        "missing_transparency",
        "late_checkpoint",
    ] {
        let mut evidence = bundle(&fx, clone_receipts(&fx));
        match mutation {
            "missing_checkpoint" => evidence.checkpoints.clear(),
            "wrapper_sequence" => evidence.receipts[0].inclusion_proof.receipt_seq += 1,
            "missing_transparency" => {
                evidence.checkpoint_transparency = build_checkpoint_transparency(&[])?
            }
            _ => {
                evidence.checkpoints[0] =
                    checkpoint_at(evidence.checkpoints[0].clone(), 1_750_000_003, &keypair(23))?;
                evidence.checkpoint_transparency =
                    build_checkpoint_transparency(&evidence.checkpoints)?;
            }
        }
        let draft = verify_finding_evidence(&fx.raw_finding, &trust_roots(&fx), &evidence)?;
        assert_eq!(
            draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
            Some(FindingFacetOutcome::Verified)
        );
        assert_eq!(
            draft.facet_outcome(FindingFacetKind::CheckpointMembership),
            Some(FindingFacetOutcome::Failed),
            "{mutation}"
        );
    }
    Ok(())
}

#[test]
fn execution_receipts_reject_revoked_unadmitted_and_unpinned_signers() -> TestResult {
    let fx = execution_fixture()?;
    for mutation in [
        "revoked",
        "unadmitted",
        "unpinned",
        "expired",
        "missing_status",
    ] {
        let mut trust = trust_roots(&fx);
        match mutation {
            "unadmitted" => trust
                .admitted_kernel_keys
                .retain(|key| *key != keypair(21).public_key()),
            "unpinned" | "expired" => {
                let mut profile = trust.profile.body.clone();
                let signer = profile
                    .receipt_signers
                    .iter_mut()
                    .find(|signer| signer.role == FindingReceiptRole::Production)
                    .ok_or("production signer missing")?;
                if mutation == "unpinned" {
                    signer.policy.key = keypair(61).public_key();
                } else {
                    signer.policy.valid_until = trust.trusted_time;
                }
                trust.profile = resign_profile(profile)?;
            }
            _ => {
                let statuses = &mut trust
                    .checkpoint_signer_status
                    .as_mut()
                    .ok_or("status trust missing")?
                    .signed_statuses;
                if mutation == "missing_status" {
                    statuses.retain(|status| status.body.authority_id != "authority-production");
                } else {
                    let status = statuses
                        .iter_mut()
                        .find(|status| status.body.authority_id == "authority-production")
                        .ok_or("production status missing")?;
                    status.body.revoked_from = Some(status.body.observed_at - 1);
                    status.signature = fx
                        .checkpoint_status_authority
                        .sign(&canonical_json_bytes(&status.body)?);
                }
            }
        }
        let draft =
            verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
        assert_eq!(
            draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
            Some(FindingFacetOutcome::Failed),
            "{mutation}"
        );
    }
    Ok(())
}

#[test]
fn execution_receipts_cannot_be_substituted_under_legacy_spend_profile() -> TestResult {
    let fx = execution_fixture()?;
    let mut trust = trust_roots(&fx);
    let mut profile = trust.profile.body.clone();
    profile.required_receipt_semantics = "chio.mediated_spend.v1".to_owned();
    trust.profile = resign_profile(profile)?;
    let draft =
        verify_finding_evidence(&fx.raw_finding, &trust, &bundle(&fx, clone_receipts(&fx)))?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Failed)
    );
    Ok(())
}

#[test]
fn execution_profile_preserves_delivery_spend_and_nonce_requirements() -> TestResult {
    let fx = execution_fixture()?;
    let finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    for valid_nonce in [true, false] {
        let delivery = resolved_delivery(
            &fx,
            &finding.payload_sha256,
            Some(finding_delivery_overlay(&finding.finding_id)),
        )?;
        let mut resolver = nonce_resolver_with_delivery(&fx, &delivery)?;
        if !valid_nonce {
            let nonce = resolver.nonces.last_mut().ok_or("delivery nonce missing")?;
            nonce.nonce.expires_at = i64::try_from(delivery.receipt.receipt.timestamp)?;
            nonce.signature = keypair(12).sign(&canonical_json_bytes(&nonce.nonce)?);
        }
        let mut evidence = bundle(&fx, clone_receipts(&fx));
        evidence.finding_delivery = Some(delivery);
        evidence.nonce_resolver = &resolver;
        let draft = verify_finding_evidence(&fx.raw_finding, &trust_roots(&fx), &evidence)?;
        assert_eq!(
            draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
            Some(if valid_nonce {
                FindingFacetOutcome::Verified
            } else {
                FindingFacetOutcome::Failed
            })
        );
        assert_eq!(
            draft.facet_outcome(FindingFacetKind::MeteredExposureBacking),
            Some(FindingFacetOutcome::Unavailable)
        );
    }
    Ok(())
}

#[test]
fn execution_receipts_do_not_evaluate_unrelated_nonce_as_optional_financial_failure() -> TestResult
{
    struct UnrelatedNonce(SignedExecutionNonce);
    impl FindingNonceResolver for UnrelatedNonce {
        fn nonce_for(&self, _receipt: &ChioReceipt) -> Option<&SignedExecutionNonce> {
            Some(&self.0)
        }
    }
    let fx = execution_fixture()?;
    let unrelated = UnrelatedNonce(fx.nonce_resolver.nonces[0].clone());
    let mut evidence = bundle(&fx, clone_receipts(&fx));
    evidence.nonce_resolver = &unrelated;
    let draft = verify_finding_evidence(&fx.raw_finding, &trust_roots(&fx), &evidence)?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Verified)
    );
    for kind in [
        FindingFacetKind::MeteredExposureBacking,
        FindingFacetKind::SettledSpendBacking,
    ] {
        assert_eq!(
            draft.facet_outcome(kind),
            Some(FindingFacetOutcome::Unavailable)
        );
    }
    Ok(())
}

#[test]
fn execution_receipts_cannot_back_a_metered_attested_claim() -> TestResult {
    let mut fx = execution_fixture()?;
    let mut finding: Finding = serde_json::from_str(&fx.raw_finding)?;
    finding.guarantee_class = FindingGuaranteeClass::MeteredAttested;
    finding.signature.clear();
    finding.finding_id = compute_finding_id(&finding)?;
    fx.raw_finding = String::from_utf8(canonical_json_bytes(&sign_finding(finding, &fx.issuer)?)?)?;
    let draft = verify_finding_evidence(
        &fx.raw_finding,
        &trust_roots(&fx),
        &bundle(&fx, clone_receipts(&fx)),
    )?;
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::ReceiptAuthenticity),
        Some(FindingFacetOutcome::Verified)
    );
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::GuaranteeConsistency),
        Some(FindingFacetOutcome::Failed)
    );
    assert_eq!(
        draft.facet_outcome(FindingFacetKind::MeteredExposureBacking),
        Some(FindingFacetOutcome::Unavailable)
    );
    Ok(())
}
