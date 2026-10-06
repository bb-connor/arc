//! Real signed-bundle regressions for ACP certificate completeness.

use super::*;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn signed_entry(
    signer: &Keypair,
    seq: u64,
) -> Result<ComplianceReceiptEntry, chio_core::error::Error> {
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: 100 + seq,
            capability_id: "bundle-capability".into(),
            tool_server: "acp-proxy".into(),
            tool_name: "fs/read_text_file".into(),
            action: ToolCallAction::from_parameters(serde_json::json!({"sequence": seq}))?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "bundle-content".into(),
            policy_hash: "bundle-policy".into(),
            evidence: Vec::new(),
            metadata: Some(
                serde_json::json!({"receipt_context": {"session_id": "bundle-session"}}),
            ),
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
        },
        signer,
    )?;
    Ok(ComplianceReceiptEntry {
        receipt,
        seq,
        entry_seq: None,
    })
}

fn valid_fixture() -> Result<(ComplianceCertificate, ComplianceConfig), Box<dyn std::error::Error>>
{
    let signer = Keypair::from_seed(&[71; 32]);
    let entries = [signed_entry(&signer, 1)?];
    let config = ComplianceConfig {
        trusted_kernel_keys: std::collections::BTreeSet::from([signer.public_key().to_hex()]),
        ..ComplianceConfig::default()
    };
    let certificate = generate_compliance_certificate(
        "bundle-session",
        &entries,
        &config,
        &signer,
        &AcpClock::default(),
    )?;
    Ok((certificate, config))
}

#[test]
fn compliance_bundle_full_mode_refuses_absent_receipts() -> TestResult {
    let (certificate, config) = valid_fixture()?;
    let result =
        verify_compliance_certificate(&certificate, VerificationMode::FullBundle, None, &config);
    assert!(
        !result.passed,
        "FullBundle silently downgraded to Lightweight: {}",
        result.summary
    );
    Ok(())
}

#[test]
fn compliance_bundle_full_mode_refuses_empty_receipts() -> TestResult {
    let (certificate, config) = valid_fixture()?;
    let result = verify_compliance_certificate(
        &certificate,
        VerificationMode::FullBundle,
        Some(&[]),
        &config,
    );
    assert!(
        !result.passed,
        "FullBundle accepted an empty receipt set: {}",
        result.summary
    );
    Ok(())
}

fn signed_fixture(
    sequences: &[u64],
) -> Result<
    (
        Keypair,
        Vec<ComplianceReceiptEntry>,
        ComplianceConfig,
        ComplianceCertificate,
    ),
    Box<dyn std::error::Error>,
> {
    let signer = Keypair::from_seed(&[71; 32]);
    let entries = sequences
        .iter()
        .map(|seq| signed_entry(&signer, *seq))
        .collect::<Result<Vec<_>, _>>()?;
    let config = ComplianceConfig {
        trusted_kernel_keys: std::collections::BTreeSet::from([signer.public_key().to_hex()]),
        ..ComplianceConfig::default()
    };
    let certificate = generate_compliance_certificate(
        "bundle-session",
        &entries,
        &config,
        &signer,
        &AcpClock::default(),
    )?;
    Ok((signer, entries, config, certificate))
}

#[test]
fn compliance_bundle_refuses_receipt_count_mismatch() -> TestResult {
    let (signer, mut entries, config, certificate) = signed_fixture(&[1])?;
    entries.push(signed_entry(&signer, 2)?);
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed,
        "an extra individually valid receipt changed the certified set"
    );
    Ok(())
}

#[test]
fn compliance_bundle_refuses_same_count_signed_substitution() -> TestResult {
    let (signer, mut entries, config, certificate) = signed_fixture(&[1])?;
    let mut body = entries[0].receipt.body();
    body.id.clear();
    body.action = ToolCallAction::from_parameters(serde_json::json!({"different_action": true}))?;
    entries[0].receipt = ChioReceipt::sign(body, &signer)?;
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed,
        "a same-count validly signed replacement was accepted"
    );
    Ok(())
}

#[test]
fn compliance_bundle_refuses_reordering_and_duplicate_receipts() -> TestResult {
    let (_signer, mut entries, config, certificate) = signed_fixture(&[1, 2])?;
    entries.reverse();
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed,
        "the certified order was ignored"
    );
    entries[1] = entries[0].clone();
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed,
        "duplicate receipts were accepted as a complete set"
    );
    Ok(())
}

#[test]
fn compliance_bundle_refuses_changed_compliance_profile() -> TestResult {
    let (_signer, entries, mut config, certificate) = signed_fixture(&[1])?;
    config.budget_limit = 9;
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed,
        "a different verifier profile was not bound to the certificate"
    );
    Ok(())
}

#[test]
fn compliance_bundle_accepts_original_interleaved_global_sequences() -> TestResult {
    let (_signer, entries, config, certificate) = signed_fixture(&[1, 3])?;
    assert_eq!(
        entries.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
        [1, 3]
    );
    let verified = verify_compliance_certificate(
        &certificate,
        VerificationMode::FullBundle,
        Some(&entries),
        &config,
    );
    assert!(
        verified.passed,
        "valid selected rows were renumbered or required global adjacency: {}",
        verified.summary
    );
    Ok(())
}

#[test]
fn compliance_bundle_without_profile_does_not_assert_guard_or_scope_checks() -> TestResult {
    let (_signer, entries, config, certificate) = signed_fixture(&[1])?;
    assert!(
        !certificate.body.scope_compliant,
        "no scope profile was evaluated"
    );
    assert!(
        !certificate.body.guards_compliant,
        "no required guard profile was evaluated"
    );
    assert!(
        !certificate.body.budget_compliant,
        "no invocation ceiling was evaluated"
    );
    assert!(
        verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed,
        "integrity-only verification still verifies the actual committed set"
    );
    Ok(())
}

#[test]
fn compliance_bundle_refuses_signed_time_coverage_mismatch() -> TestResult {
    let (signer, entries, config, mut certificate) = signed_fixture(&[1])?;
    certificate.body.issued_at = 50;
    certificate.signature = signer.sign(&canonical_json_bytes(&certificate.body)?);
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed,
        "signed evidence was issued before its purported receipt history"
    );
    Ok(())
}

#[test]
fn compliance_bundle_refuses_mixed_tenants_without_an_explicit_tenant_filter() -> TestResult {
    let (signer, mut entries, config, _certificate) = signed_fixture(&[1, 2])?;
    let mut body = entries[1].receipt.body();
    body.id.clear();
    body.tenant_id = Some("different-tenant".into());
    entries[1].receipt = ChioReceipt::sign(body, &signer)?;
    assert!(
        generate_compliance_certificate(
            "bundle-session",
            &entries,
            &config,
            &signer,
            &AcpClock::default()
        )
        .is_err(),
        "a shared session name hid mixed tenant histories"
    );
    Ok(())
}

#[test]
fn compliance_bundle_refuses_negative_required_guard_evidence_on_an_allow() -> TestResult {
    let (signer, mut entries, mut config, _certificate) = signed_fixture(&[1])?;
    let mut body = entries[0].receipt.body();
    body.id.clear();
    body.evidence = vec![chio_core::receipt::metadata::GuardEvidence {
        guard_name: "required-guard".into(),
        verdict: false,
        details: None,
    }];
    entries[0].receipt = ChioReceipt::sign(body, &signer)?;
    config.required_guards = vec!["required-guard".into()];
    assert!(
        generate_compliance_certificate(
            "bundle-session",
            &entries,
            &config,
            &signer,
            &AcpClock::default()
        )
        .is_err(),
        "a recorded negative guard result was certified as guard-compliant"
    );
    Ok(())
}

#[test]
fn compliance_bundle_commits_trace_refusals_without_treating_them_as_invocations() -> TestResult {
    let (signer, mut entries, mut config, _certificate) = signed_fixture(&[1])?;
    let mut body = entries[0].receipt.body();
    body.id.clear();
    body.evidence = vec![chio_core::receipt::metadata::GuardEvidence {
        guard_name: "required-guard".into(),
        verdict: true,
        details: None,
    }];
    entries[0].receipt = ChioReceipt::sign(body, &signer)?;
    let mut refusal = signed_entry(&signer, 2)?;
    let mut body = refusal.receipt.body();
    body.id.clear();
    body.tool_name = "not-an-authorized-invocation".into();
    body.decision = None;
    body.receipt_kind = ReceiptKind::TraceObservation;
    body.boundary_class = BoundaryClass::DetectOnly;
    body.observation_outcome = Some(chio_core::receipt::kinds::ObservationOutcome::Observed);
    body.trust_level = TrustLevel::Verified;
    body.metadata = Some(serde_json::json!({"protocol_refusal": {
        "schema":"chio.session.protocol-refusal.v1", "session_id":"bundle-session"
    }}));
    refusal.receipt = ChioReceipt::sign(body, &signer)?;
    entries.push(refusal);
    config.budget_limit = 1;
    config.required_guards = vec!["required-guard".into()];
    config.authorized_scopes = vec!["fs/".into()];
    let certificate = generate_compliance_certificate(
        "bundle-session",
        &entries,
        &config,
        &signer,
        &AcpClock::default(),
    )?;
    assert_eq!(certificate.body.receipt_count, 2);
    let value = serde_json::to_value(&certificate.body)?;
    assert_eq!(
        value["invocation_count"], 1,
        "trace evidence was counted as an allowed mediated receipt"
    );
    assert!(
        verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed
    );
    Ok(())
}

#[test]
fn compliance_bundle_legacy_is_signature_only_and_never_full() -> TestResult {
    let (signer, entries, config, mut certificate) = signed_fixture(&[1])?;
    certificate.body.schema = COMPLIANCE_CERTIFICATE_SCHEMA_V1.into();
    certificate.body.receipt_set_digest = None;
    certificate.body.compliance_profile_digest = None;
    certificate.body.invocation_count = None;
    certificate.body.checks = None;
    certificate.body.coverage = None;
    certificate.body.scope_compliant = true;
    certificate.body.budget_compliant = true;
    certificate.body.guards_compliant = true;
    certificate.signature = signer.sign(&canonical_json_bytes(&certificate.body)?);
    let bytes = serde_json::to_vec(&certificate)?;
    let decoded: ComplianceCertificate = serde_json::from_slice(&bytes)?;
    let limited =
        verify_compliance_certificate(&decoded, VerificationMode::Lightweight, None, &config);
    assert!(
        limited.passed,
        "legacy signed bytes lost compatibility: {}",
        limited.summary
    );
    assert!(limited.summary.contains("legacy") && limited.summary.contains("not reverified"));
    assert!(
        !verify_compliance_certificate(
            &decoded,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed
    );
    Ok(())
}

#[test]
fn compliance_bundle_preserves_source_identity_in_authenticated_claim_order() -> TestResult {
    let signer = Keypair::from_seed(&[71; 32]);
    let mut first = signed_entry(&signer, 1)?;
    let mut second = signed_entry(&signer, 2)?;
    first.seq = 20;
    second.seq = 10;
    first.entry_seq = Some(30);
    second.entry_seq = Some(40);
    let entries = [first, second];
    let config = ComplianceConfig {
        trusted_kernel_keys: std::collections::BTreeSet::from([signer.public_key().to_hex()]),
        ..ComplianceConfig::default()
    };
    let certificate = generate_compliance_certificate(
        "bundle-session",
        &entries,
        &config,
        &signer,
        &AcpClock::default(),
    )?;
    assert_eq!([entries[0].seq, entries[1].seq], [20, 10]);
    assert!(
        verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed
    );
    Ok(())
}

#[test]
fn compliance_bundle_refuses_wrong_session_tenant_or_signing_pin() -> TestResult {
    let (signer, entries, mut config, certificate) = signed_fixture(&[1])?;
    config.expected_tenant_id = Some("other-tenant".into());
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed
    );
    config.expected_tenant_id = None;
    config.trusted_kernel_keys =
        std::collections::BTreeSet::from([Keypair::from_seed(&[72; 32]).public_key().to_hex()]);
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed
    );
    config.trusted_kernel_keys = std::collections::BTreeSet::from([signer.public_key().to_hex()]);
    let mut wrong = entries.clone();
    let mut body = wrong[0].receipt.body();
    body.id.clear();
    body.metadata = Some(serde_json::json!({"receipt_context":{"session_id":"another-session"}}));
    wrong[0].receipt = ChioReceipt::sign(body, &signer)?;
    assert!(
        !verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&wrong),
            &config
        )
        .passed
    );
    Ok(())
}

#[test]
fn compliance_bundle_uses_trusted_verification_clock() -> TestResult {
    struct UnavailableClock;
    impl chio_security_types::clock::Clock for UnavailableClock {
        fn read(
            &self,
        ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
        {
            Err(chio_security_types::clock::ClockError::Unavailable)
        }
    }
    let (_signer, entries, config, certificate) = signed_fixture(&[1])?;
    let clock = AcpClock::new(std::sync::Arc::new(UnavailableClock));
    let result = verify_compliance_certificate_with_clock(
        &certificate,
        VerificationMode::FullBundle,
        Some(&entries),
        &config,
        &clock,
    );
    assert!(!result.passed);
    assert!(result
        .summary
        .contains("trusted-time verification unavailable"));
    Ok(())
}

#[test]
fn compliance_bundle_checks_exact_server_and_tool_profile_targets() -> TestResult {
    let (signer, entries, mut config, _certificate) = signed_fixture(&[1])?;
    config.authorized_tool_targets = vec![ComplianceToolTarget {
        server_id: "other-server".into(),
        tool_name: "fs/read_text_file".into(),
    }];
    assert!(matches!(
        generate_compliance_certificate(
            "bundle-session",
            &entries,
            &config,
            &signer,
            &AcpClock::default()
        ),
        Err(ComplianceCertificateError::ScopeViolation { .. })
    ));
    config.authorized_tool_targets[0].server_id = "acp-proxy".into();
    let certificate = generate_compliance_certificate(
        "bundle-session",
        &entries,
        &config,
        &signer,
        &AcpClock::default(),
    )?;
    assert!(certificate.body.scope_compliant);
    assert!(
        verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config
        )
        .passed
    );
    Ok(())
}

#[test]
fn compliance_bundle_preflight_refuses_oversized_typed_input_before_signature_work() -> TestResult {
    let (signer, mut entries, config, certificate) = signed_fixture(&[1])?;
    entries[0].receipt.metadata = Some(serde_json::json!({
        "receipt_context":{"session_id":"bundle-session"},
        "oversized":"x".repeat(1024*1024+1)
    }));
    assert!(
        matches!(
            generate_compliance_certificate(
                "bundle-session",
                &entries,
                &config,
                &signer,
                &AcpClock::default()
            ),
            Err(ComplianceCertificateError::Bundle(
                ComplianceBundleError::CapacityExceeded
            ))
        ),
        "unbounded typed payload reached body/signature serialization before refusal"
    );
    let result = verify_compliance_certificate(
        &certificate,
        VerificationMode::FullBundle,
        Some(&entries),
        &config,
    );
    assert!(!result.passed);
    assert_eq!(
        result.receipts_reverified, 0,
        "oversized input reached receipt signature verification"
    );
    let mut oversized_certificate = certificate.clone();
    oversized_certificate.body.session_id = "x".repeat(1024 * 1024 + 1);
    let lightweight = verify_compliance_certificate(
        &oversized_certificate,
        VerificationMode::Lightweight,
        None,
        &config,
    );
    assert!(!lightweight.passed);
    assert_eq!(lightweight.receipts_reverified, 0);
    assert!(lightweight.summary.contains("certificate bounds"));
    Ok(())
}

#[test]
fn compliance_bundle_preflight_refuses_deep_typed_input_before_body_clone() -> TestResult {
    let (signer, mut entries, config, certificate) = signed_fixture(&[1])?;
    let mut nested = serde_json::Value::Null;
    for _ in 0..130 {
        nested = serde_json::json!([nested]);
    }
    entries[0].receipt.action.parameters = nested;
    assert!(
        matches!(
            generate_compliance_certificate(
                "bundle-session",
                &entries,
                &config,
                &signer,
                &AcpClock::default()
            ),
            Err(ComplianceCertificateError::Bundle(
                ComplianceBundleError::CapacityExceeded
            ))
        ),
        "deep typed JSON reached recursive body serialization before refusal"
    );
    let result = verify_compliance_certificate(
        &certificate,
        VerificationMode::FullBundle,
        Some(&entries),
        &config,
    );
    assert!(!result.passed);
    assert_eq!(
        result.receipts_reverified, 0,
        "deep input reached receipt signature verification"
    );
    Ok(())
}

#[test]
fn compliance_bundle_accepts_exact_receipt_byte_boundary() -> TestResult {
    let (signer, mut entries, config, _) = signed_fixture(&[1])?;
    let mut body = entries[0].receipt.body();
    body.id.clear();
    body.metadata = Some(serde_json::json!({
        "receipt_context":{"session_id":"bundle-session"},
        "numbers":[0.0, -0.0, 1.0, 0.000001],
        "unicode":"\u{00e9} \u{1f4a0} \u{2028} \0",
        "padding":""
    }));
    let base = ChioReceipt::sign(body, &signer)?;
    let base_size = chio_core::canonical::canonical_json_bytes(&base)?.len();
    let mut body = base.body();
    body.id.clear();
    body.metadata.as_mut().ok_or("missing metadata")?["padding"] =
        serde_json::Value::String("x".repeat(1024 * 1024 - base_size));
    entries[0].receipt = ChioReceipt::sign(body, &signer)?;
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&entries[0].receipt)?.len(),
        1024 * 1024
    );
    let certificate = generate_compliance_certificate(
        "bundle-session",
        &entries,
        &config,
        &signer,
        &AcpClock::default(),
    )?;
    assert!(
        verify_compliance_certificate(
            &certificate,
            VerificationMode::FullBundle,
            Some(&entries),
            &config,
        )
        .passed
    );
    let mut body = entries[0].receipt.body();
    body.id.clear();
    body.metadata.as_mut().ok_or("missing metadata")?["padding"] =
        serde_json::Value::String("x".repeat(1024 * 1024 - base_size + 1));
    entries[0].receipt = ChioReceipt::sign(body, &signer)?;
    assert!(matches!(
        generate_compliance_certificate(
            "bundle-session",
            &entries,
            &config,
            &signer,
            &AcpClock::default(),
        ),
        Err(ComplianceCertificateError::Bundle(
            ComplianceBundleError::CapacityExceeded
        ))
    ));
    Ok(())
}

#[test]
fn compliance_bundle_refuses_oversized_signature_material_before_receipt_work() -> TestResult {
    let (signer, mut entries, config, certificate) = signed_fixture(&[1])?;
    entries[0].receipt.signature =
        chio_core::crypto::Signature::from_p256_der(&vec![0; 1024 * 1024]);
    let result = verify_compliance_certificate(
        &certificate,
        VerificationMode::FullBundle,
        Some(&entries),
        &config,
    );
    assert!(!result.passed);
    assert_eq!(
        result.receipts_reverified, 0,
        "oversized typed signature reached receipt verification"
    );
    assert!(matches!(
        generate_compliance_certificate(
            "bundle-session",
            &entries,
            &config,
            &signer,
            &AcpClock::default(),
        ),
        Err(ComplianceCertificateError::Bundle(
            ComplianceBundleError::CapacityExceeded
        ))
    ));
    Ok(())
}

#[test]
fn compliance_bundle_lightweight_refuses_weak_test_anchor() -> TestResult {
    let (_, _, config, mut certificate) = signed_fixture(&[1])?;
    let healthy =
        verify_compliance_certificate(&certificate, VerificationMode::Lightweight, None, &config);
    assert!(healthy.passed && healthy.certificate_signature_valid);
    // Existing core crypto validation vectors, applied only to this offline fixture.
    let mut anchor_bytes = [0; 32];
    anchor_bytes[0] = 1;
    let anchor = chio_core::crypto::PublicKey::from_bytes(&anchor_bytes)?;
    assert!(anchor.is_weak_ed25519());
    let mut signature_bytes = [0; 64];
    signature_bytes[0] = 1;
    certificate.signer_key = anchor.clone();
    certificate.body.kernel_key = anchor.clone();
    certificate.signature = chio_core::crypto::Signature::from_bytes(&signature_bytes);
    let weak_config = ComplianceConfig {
        trusted_kernel_keys: std::collections::BTreeSet::from([anchor.to_hex()]),
        ..ComplianceConfig::default()
    };
    let result = verify_compliance_certificate(
        &certificate,
        VerificationMode::Lightweight,
        None,
        &weak_config,
    );
    assert!(
        result.body_consistent,
        "control body must remain consistent"
    );
    assert!(
        !result.passed,
        "weak test anchor passed envelope verification"
    );
    assert!(!result.certificate_signature_valid);
    assert_eq!(
        result.verification_scope,
        CertificateVerificationScope::Unverified
    );
    Ok(())
}
