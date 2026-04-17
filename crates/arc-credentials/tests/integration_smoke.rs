use arc_core::crypto::Keypair;
use arc_credentials::{
    build_agent_passport, create_passport_presentation_challenge,
    create_signed_passport_verifier_policy, ensure_signed_passport_verifier_policy_active,
    issue_reputation_credential, respond_to_passport_presentation_challenge, verify_agent_passport,
    verify_passport_presentation_response, ArcCredentialEvidence, AttestationWindow,
    CredentialError, PassportPresentationOptions, PassportVerifierPolicy,
};
use arc_did::DidArc;
use arc_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};

fn did_from_public_key(public_key: arc_core::PublicKey) -> DidArc {
    DidArc::from_public_key(public_key).expect("ed25519 key")
}

fn sample_scorecard(subject_key: &str) -> LocalReputationScorecard {
    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: 1_710_000_000,
        boundary_pressure: BoundaryPressureMetrics {
            deny_ratio: MetricValue::Known(0.1),
            policies_observed: 1,
            receipts_observed: 3,
        },
        resource_stewardship: ResourceStewardshipMetrics {
            average_utilization: MetricValue::Known(0.6),
            fit_score: MetricValue::Known(0.9),
            capped_grants_observed: 1,
        },
        least_privilege: LeastPrivilegeMetrics {
            score: MetricValue::Known(0.8),
            capabilities_observed: 1,
        },
        history_depth: HistoryDepthMetrics {
            score: MetricValue::Known(0.7),
            receipt_count: 3,
            active_days: 3,
            first_seen: Some(1_709_900_000),
            last_seen: Some(1_710_000_000),
            span_days: 3,
            activity_ratio: MetricValue::Known(1.0),
        },
        specialization: SpecializationMetrics {
            score: MetricValue::Known(0.5),
            distinct_tools: 2,
        },
        delegation_hygiene: DelegationHygieneMetrics {
            score: MetricValue::Known(0.9),
            delegations_observed: 1,
            scope_reduction_rate: MetricValue::Known(1.0),
            ttl_reduction_rate: MetricValue::Known(1.0),
            budget_reduction_rate: MetricValue::Known(1.0),
        },
        reliability: ReliabilityMetrics {
            score: MetricValue::Known(0.95),
            completion_rate: MetricValue::Known(1.0),
            cancellation_rate: MetricValue::Known(0.0),
            incompletion_rate: MetricValue::Known(0.0),
            receipts_observed: 3,
        },
        incident_correlation: IncidentCorrelationMetrics {
            score: MetricValue::Unknown,
            incidents_observed: None,
        },
        composite_score: MetricValue::Known(0.82),
        effective_weight_sum: 0.9,
    }
}

fn sample_evidence() -> ArcCredentialEvidence {
    ArcCredentialEvidence {
        query: AttestationWindow {
            since: Some(1_709_900_000),
            until: 1_710_000_000,
        },
        receipt_count: 3,
        receipt_ids: vec![
            "rcpt-1".to_string(),
            "rcpt-2".to_string(),
            "rcpt-3".to_string(),
        ],
        checkpoint_roots: vec!["abc123".to_string()],
        receipt_log_urls: vec!["https://trust.example.com/v1/receipts".to_string()],
        lineage_records: 1,
        uncheckpointed_receipts: 0,
        runtime_attestation: None,
    }
}

#[test]
fn passport_issue_verify_and_present_round_trip() {
    let issuer = Keypair::from_seed(&[1_u8; 32]);
    let holder = Keypair::from_seed(&[7_u8; 32]);
    let holder_did = did_from_public_key(holder.public_key());
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&holder.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .expect("issue reputation credential");
    let passport =
        build_agent_passport(&holder_did.to_string(), vec![credential]).expect("build passport");

    let verification = verify_agent_passport(&passport, 1_710_000_100).expect("verify passport");
    assert_eq!(verification.subject, holder_did.to_string());
    assert_eq!(verification.credential_count, 1);

    let challenge = create_passport_presentation_challenge(
        "https://verifier.example.com",
        "nonce-123",
        1_710_000_110,
        1_710_000_410,
        PassportPresentationOptions::default(),
        Some(PassportVerifierPolicy {
            min_receipt_count: Some(1),
            ..PassportVerifierPolicy::default()
        }),
    )
    .expect("build challenge");
    let response =
        respond_to_passport_presentation_challenge(&holder, &passport, &challenge, 1_710_000_120)
            .expect("respond to challenge");
    let verification =
        verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
            .expect("verify presentation response");

    assert!(verification.accepted);
    assert!(verification.policy_evaluated);
    assert_eq!(verification.subject, holder_did.to_string());
    assert_eq!(verification.credential_count, 1);
}

#[test]
fn presentation_rejects_holder_mismatch() {
    let issuer = Keypair::from_seed(&[1_u8; 32]);
    let holder = Keypair::from_seed(&[7_u8; 32]);
    let wrong_holder = Keypair::from_seed(&[9_u8; 32]);
    let holder_did = did_from_public_key(holder.public_key());
    let credential = issue_reputation_credential(
        &issuer,
        sample_scorecard(&holder.public_key().to_hex()),
        sample_evidence(),
        1_710_000_000,
        1_710_086_400,
    )
    .expect("issue credential");
    let passport =
        build_agent_passport(&holder_did.to_string(), vec![credential]).expect("build passport");
    let challenge = create_passport_presentation_challenge(
        "https://verifier.example.com",
        "nonce-123",
        1_710_000_110,
        1_710_000_410,
        PassportPresentationOptions::default(),
        None,
    )
    .expect("build challenge");

    let error = respond_to_passport_presentation_challenge(
        &wrong_holder,
        &passport,
        &challenge,
        1_710_000_120,
    )
    .expect_err("wrong holder should fail closed");

    assert!(matches!(error, CredentialError::PresentationHolderMismatch));
}

#[test]
fn signed_verifier_policy_activation_window_is_inclusive() {
    let signer = Keypair::from_seed(&[3_u8; 32]);
    let document = create_signed_passport_verifier_policy(
        &signer,
        "rp-default",
        "https://verifier.example.com",
        1_710_000_000,
        1_710_000_300,
        PassportVerifierPolicy::default(),
    )
    .expect("sign verifier policy");

    ensure_signed_passport_verifier_policy_active(&document, 1_710_000_000)
        .expect("created_at boundary should be valid");
    ensure_signed_passport_verifier_policy_active(&document, 1_710_000_300)
        .expect("expires_at boundary should be valid");
}
