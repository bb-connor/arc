#[cfg(test)]
mod tests {
    use super::*;
    use pact_reputation::{LocalReputationScorecard, MetricValue};

    fn sample_scorecard(subject_key: &str) -> LocalReputationScorecard {
        LocalReputationScorecard {
            subject_key: subject_key.to_string(),
            computed_at: 1_710_000_000,
            boundary_pressure: pact_reputation::BoundaryPressureMetrics {
                deny_ratio: MetricValue::Known(0.1),
                policies_observed: 1,
                receipts_observed: 3,
            },
            resource_stewardship: pact_reputation::ResourceStewardshipMetrics {
                average_utilization: MetricValue::Known(0.6),
                fit_score: MetricValue::Known(0.9),
                capped_grants_observed: 1,
            },
            least_privilege: pact_reputation::LeastPrivilegeMetrics {
                score: MetricValue::Known(0.8),
                capabilities_observed: 1,
            },
            history_depth: pact_reputation::HistoryDepthMetrics {
                score: MetricValue::Known(0.7),
                receipt_count: 3,
                active_days: 3,
                first_seen: Some(1_709_900_000),
                last_seen: Some(1_710_000_000),
                span_days: 3,
                activity_ratio: MetricValue::Known(1.0),
            },
            specialization: pact_reputation::SpecializationMetrics {
                score: MetricValue::Known(0.5),
                distinct_tools: 2,
            },
            delegation_hygiene: pact_reputation::DelegationHygieneMetrics {
                score: MetricValue::Known(0.9),
                delegations_observed: 1,
                scope_reduction_rate: MetricValue::Known(1.0),
                ttl_reduction_rate: MetricValue::Known(1.0),
                budget_reduction_rate: MetricValue::Known(1.0),
            },
            reliability: pact_reputation::ReliabilityMetrics {
                score: MetricValue::Known(0.95),
                completion_rate: MetricValue::Known(1.0),
                cancellation_rate: MetricValue::Known(0.0),
                incompletion_rate: MetricValue::Known(0.0),
                receipts_observed: 3,
            },
            incident_correlation: pact_reputation::IncidentCorrelationMetrics {
                score: MetricValue::Unknown,
                incidents_observed: None,
            },
            composite_score: MetricValue::Known(0.82),
            effective_weight_sum: 0.9,
        }
    }

    fn sample_evidence() -> PactCredentialEvidence {
        PactCredentialEvidence {
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
        }
    }

    #[test]
    fn issued_credential_verifies_against_issuer_did() {
        let issuer = Keypair::from_seed(&[9u8; 32]);
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");

        verify_reputation_credential(&credential, 1_710_010_000).expect("verify");
    }

    #[test]
    fn passport_verification_accepts_multi_issuer_bundle() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential_a = issue_reputation_credential(
            &Keypair::from_seed(&[1u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &Keypair::from_seed(&[2u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );

        let passport = build_agent_passport(&did.to_string(), vec![credential_a, credential_b])
            .expect("multi-issuer passport");
        let verification = verify_agent_passport(&passport, 1_710_010_000).expect("verify");
        assert_eq!(verification.issuer, None);
        assert_eq!(verification.issuer_count, 2);
        assert_eq!(verification.issuers.len(), 2);
    }

    #[test]
    fn verifier_policy_reports_mixed_multi_issuer_results() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer_a = Keypair::from_seed(&[1u8; 32]);
        let issuer_b = Keypair::from_seed(&[2u8; 32]);
        let credential_a = issue_reputation_credential(
            &issuer_a,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &issuer_b,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential_a, credential_b])
                .expect("passport");
        let accepted_issuer = passport.credentials[0].unsigned.issuer.clone();
        let rejected_issuer = passport.credentials[1].unsigned.issuer.clone();

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [accepted_issuer.clone()].into_iter().collect(),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluation");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.verification.issuer_count, 2);
        assert_eq!(evaluation.matched_credential_indexes, vec![0]);
        assert_eq!(evaluation.matched_issuers, vec![accepted_issuer.clone()]);
        assert_eq!(evaluation.credential_results[0].issuer, accepted_issuer);
        assert!(evaluation.credential_results[0].accepted);
        assert_eq!(evaluation.credential_results[1].issuer, rejected_issuer);
        assert!(!evaluation.credential_results[1].accepted);
    }

    #[test]
    fn verifier_policy_rejects_multi_issuer_bundle_when_no_credential_matches() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let credential_a = issue_reputation_credential(
            &Keypair::from_seed(&[1u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_900_000_000,
            1_900_086_400,
        )
        .expect("credential");
        let credential_b = issue_reputation_credential(
            &Keypair::from_seed(&[2u8; 32]),
            sample_scorecard(&subject),
            sample_evidence(),
            1_900_000_000,
            1_900_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential_a, credential_b])
                .expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_900_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [
                    "did:pact:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        .to_string(),
                ]
                .into_iter()
                .collect(),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluation");

        assert!(!evaluation.accepted);
        assert!(evaluation.matched_credential_indexes.is_empty());
        assert!(evaluation.matched_issuers.is_empty());
        assert_eq!(evaluation.credential_results.len(), 2);
        assert!(evaluation
            .credential_results
            .iter()
            .all(|result| !result.accepted));
    }

    #[test]
    fn presentation_can_filter_credentials_by_issuer() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");

        let presented = present_agent_passport(
            &passport,
            &PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
        )
        .expect("presented passport");

        assert_eq!(presented.credentials.len(), 1);
        verify_agent_passport(&presented, 1_710_010_000).expect("verify presented passport");
    }

    #[test]
    fn verifier_policy_accepts_matching_single_issuer_passport() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                issuer_allowlist: [passport.credentials[0].unsigned.issuer.clone()]
                    .into_iter()
                    .collect(),
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                max_boundary_pressure: Some(0.20),
                min_receipt_count: Some(3),
                min_lineage_records: Some(1),
                min_history_days: Some(3),
                max_attestation_age_days: Some(7),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.matched_credential_indexes, vec![0]);
        assert!(evaluation.credential_results[0].accepted);
    }

    #[test]
    fn verifier_policy_rejects_unknown_metric_and_stale_attestation() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let mut evidence = sample_evidence();
        evidence.uncheckpointed_receipts = 1;
        evidence.receipt_log_urls.clear();
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject),
            evidence,
            1_710_000_000,
            1_720_000_000,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_712_000_000,
            &PassportVerifierPolicy {
                min_composite_score: Some(0.90),
                max_attestation_age_days: Some(1),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(!evaluation.accepted);
        assert!(evaluation.matched_credential_indexes.is_empty());
        let reasons = &evaluation.credential_results[0].reasons;
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("composite_score")),
            "expected composite score rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("uncheckpointed")),
            "expected checkpoint rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("receipt log URLs")),
            "expected receipt-log rejection"
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("attestation_age_days")),
            "expected attestation-age rejection"
        );
    }

    #[test]
    fn verifier_policy_accepts_if_any_credential_matches_without_fake_aggregation() {
        let subject = Keypair::from_seed(&[7u8; 32]).public_key().to_hex();
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let mut weaker = sample_scorecard(&subject);
        weaker.composite_score = MetricValue::Known(0.40);
        weaker.reliability.score = MetricValue::Known(0.60);
        let stronger = sample_scorecard(&subject);

        let weak_credential = issue_reputation_credential(
            &issuer,
            weaker,
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("weak credential");
        let strong_credential = issue_reputation_credential(
            &issuer,
            stronger,
            sample_evidence(),
            1_710_000_100,
            1_710_086_400,
        )
        .expect("strong credential");
        let subject_did = DidPact::from_public_key(
            pact_core::PublicKey::from_hex(&subject).expect("subject public key"),
        );
        let passport = build_agent_passport(
            &subject_did.to_string(),
            vec![weak_credential, strong_credential],
        )
        .expect("passport");

        let evaluation = evaluate_agent_passport(
            &passport,
            1_710_010_000,
            &PassportVerifierPolicy {
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                ..PassportVerifierPolicy::default()
            },
        )
        .expect("evaluate");

        assert!(evaluation.accepted);
        assert_eq!(evaluation.matched_credential_indexes, vec![1]);
        assert!(!evaluation.credential_results[0].accepted);
        assert!(evaluation.credential_results[1].accepted);
    }

    #[test]
    fn challenge_bound_presentation_verifies_and_evaluates_policy() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
            Some(PassportVerifierPolicy {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                min_composite_score: Some(0.80),
                min_reliability: Some(0.90),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            }),
        )
        .expect("challenge");

        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");
        let verification =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
                .expect("verify");

        assert_eq!(verification.subject, subject_did.to_string());
        assert_eq!(verification.verifier, "https://rp.example.com");
        assert_eq!(verification.nonce, "nonce-123");
        assert_eq!(verification.credential_count, 1);
        assert!(verification.accepted);
        assert!(
            verification
                .policy_evaluation
                .as_ref()
                .expect("policy evaluation")
                .accepted
        );
    }

    #[test]
    fn challenge_bound_presentation_rejects_holder_mismatch() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");

        let error = respond_to_passport_presentation_challenge(
            &Keypair::from_seed(&[8u8; 32]),
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect_err("holder mismatch should fail");
        assert!(matches!(error, CredentialError::PresentationHolderMismatch));
    }

    #[test]
    fn challenge_bound_presentation_rejects_tampered_signature() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");
        let mut response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");
        response.challenge.nonce = "tampered".to_string();

        let error = verify_passport_presentation_response(&response, None, 1_710_000_120)
            .expect_err("tampered signature should fail");
        assert!(matches!(
            error,
            CredentialError::InvalidPresentationSignature
        ));
    }

    #[test]
    fn challenge_bound_presentation_rejects_expired_challenge() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport =
            build_agent_passport(&subject_did.to_string(), vec![credential]).expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_150,
            PassportPresentationOptions::default(),
            None,
        )
        .expect("challenge");
        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");

        let error =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_200)
                .expect_err("expired challenge should fail");
        assert!(matches!(error, CredentialError::ChallengeExpired));
    }

    #[test]
    fn challenge_bound_presentation_reports_policy_rejection_without_structural_failure() {
        let subject = Keypair::from_seed(&[7u8; 32]);
        let issuer = Keypair::from_seed(&[1u8; 32]);
        let credential = issue_reputation_credential(
            &issuer,
            sample_scorecard(&subject.public_key().to_hex()),
            sample_evidence(),
            1_710_000_000,
            1_710_086_400,
        )
        .expect("credential");
        let subject_did = DidPact::from_public_key(subject.public_key());
        let passport = build_agent_passport(&subject_did.to_string(), vec![credential.clone()])
            .expect("passport");
        let challenge = create_passport_presentation_challenge(
            "https://rp.example.com",
            "nonce-123",
            1_710_000_050,
            1_710_000_350,
            PassportPresentationOptions {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                max_credentials: Some(1),
            },
            Some(PassportVerifierPolicy {
                issuer_allowlist: [credential.unsigned.issuer.clone()].into_iter().collect(),
                min_composite_score: Some(0.99),
                require_checkpoint_coverage: true,
                require_receipt_log_urls: true,
                ..PassportVerifierPolicy::default()
            }),
        )
        .expect("challenge");
        let response = respond_to_passport_presentation_challenge(
            &subject,
            &passport,
            &challenge,
            1_710_000_100,
        )
        .expect("response");

        let verification =
            verify_passport_presentation_response(&response, Some(&challenge), 1_710_000_120)
                .expect("verify");

        assert!(!verification.accepted);
        assert!(
            !verification
                .policy_evaluation
                .as_ref()
                .expect("policy evaluation")
                .accepted
        );
    }
}
