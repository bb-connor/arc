#[test]
fn buyer_review_package_rejects_missing_hydrated_parent_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    proof_package["toolReceipts"]
        .as_array_mut()
        .ok_or_else(|| io::Error::other("fixture proof package missing tool receipts"))?
        .remove(0);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_proof_package_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_signed_receipt_with_unbound_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    proof_package["toolReceipts"][0]["unsignedShadow"] = serde_json::json!("not-signed");
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_proof_package_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_claimed_governance_digest_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    proof_package["governanceReceipts"][0]["digest"] = serde_json::json!("0".repeat(64));
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_proof_package_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_lineage_bundle_without_packet_statement(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let mut alternate_lineage = lineage.clone();
    alternate_lineage.statement_id = "lineage-alternate".to_string();
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: alternate_lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: alternate_lineage.child_receipt_sha256.clone(),
        statements: vec![alternate_lineage],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_lineage_bundle_incomplete")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_runtime_report_without_matching_dsse_step(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (mut package, mut sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;
    let mut runtime_report: RuntimeWorkflowRunReport = serde_json::from_slice(
        &sources
            .iter()
            .find(|source| source.role == "runtime_run_report")
            .ok_or_else(|| io::Error::other("missing runtime_run_report source"))?
            .bytes,
    )?;
    runtime_report.step_evidence[0].bilateral_dsse_sha256 = "f".repeat(64);
    replace_review_source(
        &mut package,
        &mut sources,
        "runtime_run_report",
        &runtime_report,
    )?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_runtime_report_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_runtime_proof_input_trust_hash_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let (mut package, mut sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;
    let source = sources
        .iter()
        .find(|source| source.role == "proof_regeneration_input")
        .ok_or_else(|| io::Error::other("missing proof regeneration input"))?;
    let mut input: RuntimeProofRegenerationInput = serde_json::from_slice(&source.bytes)?;
    input.trust_bundle_sha256 = "0".repeat(64);
    replace_review_source(
        &mut package,
        &mut sources,
        "proof_regeneration_input",
        &input,
    )?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_runtime_report_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_runtime_manifest_artifact_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let (mut package, mut sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;
    let source = sources
        .iter()
        .find(|source| source.role == "runtime_evidence_manifest")
        .ok_or_else(|| io::Error::other("missing runtime evidence manifest"))?;
    let mut manifest: RuntimeEvidenceManifest = serde_json::from_slice(&source.bytes)?;
    let proof_entry = manifest
        .entries
        .iter_mut()
        .find(|entry| entry.role == "proof_package")
        .ok_or_else(|| io::Error::other("missing proof package manifest entry"))?;
    proof_entry.byte_count = proof_entry.byte_count.saturating_add(1);
    replace_review_source(
        &mut package,
        &mut sources,
        "runtime_evidence_manifest",
        &manifest,
    )?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_runtime_report_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_missing_strict_dsse_envelope(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (mut package, mut sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;
    package
        .artifacts
        .retain(|artifact| artifact.role != "bilateral_dsse_envelope");
    sources.retain(|source| source.role != "bilateral_dsse_envelope");

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_missing_artifact_role")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_non_strict_dsse_envelope() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let compatibility_dsse = serde_json::json!({
        "payloadType": "application/vnd.in-toto+json",
        "payload": "not-a-strict-chio-payload",
        "signatures": []
    });
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    proof_package["bilateralEnvelopes"] = serde_json::json!([compatibility_dsse]);
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &proof_package["bilateralEnvelopes"][0],
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_non_strict_dsse")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_tampered_strict_dsse_signature_when_peer_keys_available(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    dsse.envelope.signatures[0].sig = dsse.envelope.signatures[1].sig.clone();
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_strict_dsse_signer_kernel_mismatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut attacker_bilateral = bilateral.clone();
    attacker_bilateral.signer_kernel_ids[0] = "kernel.attacker".to_string();
    let dsse =
        strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &attacker_bilateral)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_binding_mismatch")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_duplicate_strict_dsse_signature_keyids(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    dsse.envelope.signatures[1].keyid = dsse.envelope.signatures[0].keyid.clone();
    packet.bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::canonical::canonical_json_bytes(&dsse.envelope)?,
    );
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_same_key_strict_dsse_trust_material(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    let mut proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let Some(bindings) = proof_package
        .get_mut("peerLadderBindings")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Err(Box::new(io::Error::other(
            "proof package did not contain peer ladder bindings",
        )));
    };
    bindings[1]["publicKey"] = serde_json::json!(dsse.signer_a_public_key.to_hex());
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_signature_invalid")
    );
    Ok(())
}

#[test]
fn buyer_review_package_rejects_strict_dsse_policy_verdict_disagreement(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut packet, lineage, continuation, admission, bilateral) = buyer_fixture()?;
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    };
    let mut dsse = strict_dsse_fixture_with_keys(&packet, &lineage_bundle, &admission, &bilateral)?;
    dsse.envelope = strict_dsse_with_policy_disagreement(&dsse)?;
    let proof_package = proof_package_with_peer_keys(&bilateral, &dsse);
    let bilateral_dsse_envelope = serde_json::to_value(&dsse.envelope)?;
    packet.bilateral_dsse_sha256 = chio_core_types::crypto::sha256_hex(
        &chio_core_types::crypto::canonical_json_bytes(&dsse.envelope)?,
    );
    let (package, sources, verifier_trust_bundle) =
        buyer_review_sources_with_strict_dsse(BuyerReviewStrictDsseSources {
            packet: &mut packet,
            lineage: &lineage,
            continuation: &continuation,
            admission: &admission,
            bilateral: &bilateral,
            lineage_bundle: &lineage_bundle,
            bilateral_dsse_envelope: &bilateral_dsse_envelope,
            proof_package: &proof_package,
        })?;

    let report = verify_review_for_test(&package, &sources, &verifier_trust_bundle)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("chio_buyer_review_strict_dsse_binding_mismatch")
    );
    Ok(())
}

#[test]
fn receipt_lineage_bundle_rejects_asserted_required_edge() -> Result<(), Box<dyn std::error::Error>>
{
    let (_, mut lineage, _, _, _) = buyer_fixture()?;
    lineage.schema = CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string();
    let accepted = verify_receipt_lineage_bundle(&ReceiptLineageBundle {
        schema: CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-1".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage.clone()],
    })?;
    assert!(accepted);

    lineage.evidence_class = "asserted".to_string();
    let err = match verify_receipt_lineage_bundle(&ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-2".to_string(),
        root_receipt_sha256: lineage.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage.child_receipt_sha256.clone(),
        statements: vec![lineage],
    }) {
        Ok(_) => {
            return Err(Box::new(io::Error::other(
                "asserted lineage bundle unexpectedly passed",
            )));
        }
        Err(error) => error,
    };
    assert_eq!(err.code(), "chio_lineage_bundle_unverified_edge");
    Ok(())
}
