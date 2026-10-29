//! Proptest invariants for Agent Passport verification.
//!
//! Named invariants (gated by `scripts/check-proptest-coverage.sh`):
//!
//! 1. `passport_verify_idempotent_on_well_formed`
//! 2. `passport_signature_breaks_under_any_subject_mutation`

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::BTreeSet;

use chio_core::crypto::Keypair;
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, trusted_issuers_from_keys,
    verify_agent_passport, AttestationWindow, ChioCredentialEvidence,
};
use chio_did::DidChio;
use chio_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};
use proptest::prelude::*;

/// Build a `ProptestConfig` whose case count honours the `PROPTEST_CASES`
/// environment variable used by the CI lanes (`256` for PR, `4096` for
/// nightly). When the variable is unset or unparseable we fall back to
/// the local default so cargo test stays fast. Without this helper, a
/// per-block `ProptestConfig::with_cases(...)` literal would override the
/// env-var derived default that proptest reads at startup.
fn proptest_config_for_lane(default_cases: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(default_cases);
    ProptestConfig::with_cases(cases)
}

// ----------------------------------------------------------------------------
// Strategies and fixtures.
// ----------------------------------------------------------------------------

const ISSUED_AT: u64 = 1_710_000_000;
const VALID_UNTIL: u64 = 1_710_086_400;
const VERIFY_NOW: u64 = 1_710_010_000;

fn fixed_scorecard(subject_key: &str) -> LocalReputationScorecard {
    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: ISSUED_AT,
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
            last_seen: Some(ISSUED_AT),
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

fn fixed_evidence() -> ChioCredentialEvidence {
    ChioCredentialEvidence {
        query: AttestationWindow {
            since: Some(1_709_900_000),
            until: ISSUED_AT,
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

fn build_well_formed_passport(
    subject_seed: [u8; 32],
    issuer_seed: [u8; 32],
) -> Result<chio_credentials::AgentPassport, chio_credentials::CredentialError> {
    let subject = Keypair::from_seed(&subject_seed);
    let issuer = Keypair::from_seed(&issuer_seed);
    let credential = issue_reputation_credential(
        &issuer,
        fixed_scorecard(&subject.public_key().to_hex()),
        fixed_evidence(),
        ISSUED_AT,
        VALID_UNTIL,
    )?;
    let subject_did = DidChio::from_public_key(subject.public_key())?;
    build_agent_passport(&subject_did.to_string(), vec![credential])
}

fn trusted_issuers(
    issuer_seed: [u8; 32],
) -> Result<BTreeSet<String>, chio_credentials::CredentialError> {
    trusted_issuers_from_keys(&[Keypair::from_seed(&issuer_seed).public_key()])
}

fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    // Avoid the all-zero seed which is not a curve-valid scalar in some
    // edge cases. Restricting to non-zero high byte is sufficient and keeps
    // strategies cheap to shrink.
    prop::array::uniform32(1u8..=255)
}

// ----------------------------------------------------------------------------
// Invariant 1: passport_verify_idempotent_on_well_formed
//
// Verifying a well-formed passport twice returns the same verdict. Encodes the
// "verification is pure / no hidden state mutation" requirement.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    #[test]
    fn passport_verify_idempotent_on_well_formed(
        subject_seed in arb_seed(),
        issuer_seed in arb_seed(),
    ) {
        prop_assume!(subject_seed != issuer_seed);
        let passport = match build_well_formed_passport(subject_seed, issuer_seed) {
            Ok(passport) => passport,
            Err(_) => return Ok(()),
        };
        let trusted = match trusted_issuers(issuer_seed) {
            Ok(trusted) => trusted,
            Err(_) => return Ok(()),
        };

        let first = verify_agent_passport(&passport, &trusted, VERIFY_NOW);
        let second = verify_agent_passport(&passport, &trusted, VERIFY_NOW);

        match (first, second) {
            (Ok(left), Ok(right)) => {
                prop_assert_eq!(left, right);
            }
            (Err(left), Err(right)) => {
                // Both branches should fail identically. Compare display form
                // since CredentialError does not implement PartialEq.
                prop_assert_eq!(left.to_string(), right.to_string());
            }
            (left, right) => {
                prop_assert!(
                    false,
                    "verify_agent_passport produced divergent verdicts: {:?} vs {:?}",
                    left.map(|_| "Ok"),
                    right.map(|_| "Ok"),
                );
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Invariant 2: passport_signature_breaks_under_any_subject_mutation
//
// Mutating any field of the passport's subject and re-verifying yields a
// signature-failure verdict (no field is silently ignored by the signature).
//
// The native passport is unsigned but each contained credential is Ed25519
// signed over its canonical-JSON body, which includes credential_subject (id
// + scorecard). Mutating any of those fields, or the passport-level subject
// string itself, must therefore break verification.
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum SubjectMutation {
    PassportSubject,
    CredentialSubjectId,
    ScorecardSubjectKey,
    CompositeScore,
    ReliabilityScore,
    LeastPrivilegeScore,
    DelegationHygieneScore,
    BoundaryPressureDenyRatio,
}

fn arb_subject_mutation() -> impl Strategy<Value = SubjectMutation> {
    prop_oneof![
        Just(SubjectMutation::PassportSubject),
        Just(SubjectMutation::CredentialSubjectId),
        Just(SubjectMutation::ScorecardSubjectKey),
        Just(SubjectMutation::CompositeScore),
        Just(SubjectMutation::ReliabilityScore),
        Just(SubjectMutation::LeastPrivilegeScore),
        Just(SubjectMutation::DelegationHygieneScore),
        Just(SubjectMutation::BoundaryPressureDenyRatio),
    ]
}

fn apply_subject_mutation(
    passport: &mut chio_credentials::AgentPassport,
    mutation: SubjectMutation,
) {
    match mutation {
        SubjectMutation::PassportSubject => {
            // Replace the passport subject with a different DID-shaped value.
            passport.subject = format!("{}-mutated", passport.subject);
        }
        SubjectMutation::CredentialSubjectId => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential.unsigned.credential_subject.id =
                    format!("{}-mutated", credential.unsigned.credential_subject.id);
            }
        }
        SubjectMutation::ScorecardSubjectKey => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                let key = &mut credential.unsigned.credential_subject.metrics.subject_key;
                if key.is_empty() {
                    key.push('a');
                } else {
                    key.push('!');
                }
            }
        }
        SubjectMutation::CompositeScore => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .composite_score = MetricValue::Known(0.123_456);
            }
        }
        SubjectMutation::ReliabilityScore => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .reliability
                    .score = MetricValue::Known(0.111_111);
            }
        }
        SubjectMutation::LeastPrivilegeScore => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .least_privilege
                    .score = MetricValue::Known(0.222_222);
            }
        }
        SubjectMutation::DelegationHygieneScore => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .delegation_hygiene
                    .score = MetricValue::Known(0.333_333);
            }
        }
        SubjectMutation::BoundaryPressureDenyRatio => {
            if let Some(credential) = passport.credentials.get_mut(0) {
                credential
                    .unsigned
                    .credential_subject
                    .metrics
                    .boundary_pressure
                    .deny_ratio = MetricValue::Known(0.987_654);
            }
        }
    }
}

proptest! {
    #![proptest_config(proptest_config_for_lane(48))]

    #[test]
    fn passport_signature_breaks_under_any_subject_mutation(
        subject_seed in arb_seed(),
        issuer_seed in arb_seed(),
        mutation in arb_subject_mutation(),
    ) {
        prop_assume!(subject_seed != issuer_seed);
        let mut passport = match build_well_formed_passport(subject_seed, issuer_seed) {
            Ok(passport) => passport,
            Err(_) => return Ok(()),
        };
        let trusted = match trusted_issuers(issuer_seed) {
            Ok(trusted) => trusted,
            Err(_) => return Ok(()),
        };

        // Sanity: the unmutated passport verifies.
        prop_assert!(verify_agent_passport(&passport, &trusted, VERIFY_NOW).is_ok());

        apply_subject_mutation(&mut passport, mutation);

        let verdict = verify_agent_passport(&passport, &trusted, VERIFY_NOW);
        prop_assert!(
            verdict.is_err(),
            "mutating {:?} must invalidate the passport verification",
            mutation,
        );
    }
}
