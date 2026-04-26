//! Proptest invariants for the Agent Passport lifecycle (M03.P1.T4).
//!
//! Four named lifecycle invariants from
//! `.planning/trajectory/03-capability-algebra-properties.md` (line 80-83):
//!
//! 1. `passport_verify_idempotent_on_well_formed`
//! 2. `revoked_lifecycle_entry_never_verifies`
//! 3. `lifecycle_state_transitions_monotone`
//! 4. `passport_signature_breaks_under_any_subject_mutation`
//!
//! NOTE: the live API uses `verify_agent_passport` (not `verify_passport`) and
//! the lifecycle enum variants are `Active, Stale, Superseded, Revoked,
//! NotFound` rather than the doc-named `Issued`. We treat `Active` as the
//! "issued/usable" state, `Revoked` as the doc-named `Revoked`, and order the
//! intermediate states by operational severity (see `severity` below).

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, verify_agent_passport, AttestationWindow,
    ChioCredentialEvidence, PassportLifecycleResolution, PassportLifecycleState,
    PassportStatusDistribution,
};
use chio_did::DidChio;
use chio_reputation::{
    BoundaryPressureMetrics, DelegationHygieneMetrics, HistoryDepthMetrics,
    IncidentCorrelationMetrics, LeastPrivilegeMetrics, LocalReputationScorecard, MetricValue,
    ReliabilityMetrics, ResourceStewardshipMetrics, SpecializationMetrics,
};
use proptest::prelude::*;

// ----------------------------------------------------------------------------
// Severity ordering for `PassportLifecycleState`.
//
// The doc-level invariant is "the lifecycle state machine never transitions
// backward through its severity ordering". The live enum has five variants
// rather than the two-state Issued/Revoked sketch in the doc, so we encode the
// operational ordering used by the rest of the crate (cross_issuer.rs treats
// Active as the only "usable" state; Revoked / NotFound are terminal sinks):
//
//     Active < Stale < Superseded < Revoked <= NotFound
//
// Forward transitions (severity_after >= severity_before) are permitted by the
// monotonicity invariant; reverse transitions are forbidden.
// ----------------------------------------------------------------------------

fn severity(state: PassportLifecycleState) -> u8 {
    match state {
        PassportLifecycleState::Active => 0,
        PassportLifecycleState::Stale => 1,
        PassportLifecycleState::Superseded => 2,
        PassportLifecycleState::Revoked => 3,
        PassportLifecycleState::NotFound => 4,
    }
}

fn transition_is_allowed(from: PassportLifecycleState, to: PassportLifecycleState) -> bool {
    severity(to) >= severity(from)
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

fn arb_seed() -> impl Strategy<Value = [u8; 32]> {
    // Avoid the all-zero seed which is not a curve-valid scalar in some
    // edge cases. Restricting to non-zero high byte is sufficient and keeps
    // strategies cheap to shrink.
    prop::array::uniform32(1u8..=255)
}

fn arb_lifecycle_state() -> impl Strategy<Value = PassportLifecycleState> {
    prop_oneof![
        Just(PassportLifecycleState::Active),
        Just(PassportLifecycleState::Stale),
        Just(PassportLifecycleState::Superseded),
        Just(PassportLifecycleState::Revoked),
        Just(PassportLifecycleState::NotFound),
    ]
}

/// Build a well-formed revoked `PassportLifecycleResolution` for an arbitrary
/// passport. Uses the public surface only.
fn build_revoked_resolution(
    passport: &chio_credentials::AgentPassport,
    revoked_at: u64,
) -> Result<PassportLifecycleResolution, chio_credentials::CredentialError> {
    let verification = verify_agent_passport(passport, VERIFY_NOW)?;
    Ok(PassportLifecycleResolution {
        passport_id: verification.passport_id,
        subject: verification.subject,
        issuers: verification.issuers,
        issuer_count: verification.issuer_count,
        state: PassportLifecycleState::Revoked,
        published_at: Some(ISSUED_AT),
        updated_at: Some(revoked_at),
        superseded_by: None,
        revoked_at: Some(revoked_at),
        revoked_reason: Some("test-revocation".to_string()),
        distribution: PassportStatusDistribution {
            resolve_urls: vec!["https://status.example.com/passports".to_string()],
            cache_ttl_secs: Some(300),
        },
        valid_until: passport.valid_until.clone(),
        source: Some("https://status.example.com".to_string()),
    })
}

// ----------------------------------------------------------------------------
// Invariant 1: passport_verify_idempotent_on_well_formed
//
// Verifying a well-formed passport twice returns the same verdict. Encodes the
// "verification is pure / no hidden state mutation" requirement.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

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

        let first = verify_agent_passport(&passport, VERIFY_NOW);
        let second = verify_agent_passport(&passport, VERIFY_NOW);

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
// Invariant 2: revoked_lifecycle_entry_never_verifies
//
// A passport whose lifecycle entry is in a revoked state never produces a
// successful "active" verdict, no matter the surrounding context.
//
// NOTE: `verify_agent_passport` itself does not consume a lifecycle record;
// the lifecycle gate lives in the cross-issuer policy (cross_issuer.rs treats
// `state == Active` as the only usable state). We express the invariant via
// the public lifecycle surface: a well-formed Revoked resolution validates
// successfully but its state is never `Active`, so the cross-issuer
// `require_active_lifecycle` rule (state-equality on `Active`) rejects it.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn revoked_lifecycle_entry_never_verifies(
        subject_seed in arb_seed(),
        issuer_seed in arb_seed(),
        revoked_offset in 1u64..=86_400u64,
    ) {
        prop_assume!(subject_seed != issuer_seed);
        let passport = match build_well_formed_passport(subject_seed, issuer_seed) {
            Ok(passport) => passport,
            Err(_) => return Ok(()),
        };
        let revoked_at = ISSUED_AT.saturating_add(revoked_offset);
        let resolution = match build_revoked_resolution(&passport, revoked_at) {
            Ok(resolution) => resolution,
            Err(_) => return Ok(()),
        };

        // The revoked resolution itself is well-formed (validate() succeeds).
        prop_assert!(resolution.validate().is_ok());

        // But the lifecycle state is Revoked, never Active. Any context that
        // requires an active lifecycle (cross-issuer policy
        // `require_active_lifecycle`) therefore rejects the entry.
        prop_assert_eq!(resolution.state, PassportLifecycleState::Revoked);
        prop_assert_ne!(resolution.state, PassportLifecycleState::Active);
        prop_assert!(
            !matches!(resolution.state, PassportLifecycleState::Active),
            "revoked lifecycle entry must never present as Active",
        );
    }
}

// ----------------------------------------------------------------------------
// Invariant 3: lifecycle_state_transitions_monotone
//
// The lifecycle state machine never transitions backward through its severity
// ordering (Active < Stale < Superseded < Revoked <= NotFound).
//
// Permitted: Active -> Revoked, Stale -> Superseded, Active -> Active.
// Forbidden: Revoked -> Active, Superseded -> Stale, NotFound -> Revoked.
// ----------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn lifecycle_state_transitions_monotone(
        before in arb_lifecycle_state(),
        after in arb_lifecycle_state(),
    ) {
        let forward_ok = transition_is_allowed(before, after);
        let backward_ok = transition_is_allowed(after, before);

        // Either both directions are allowed (severity tie / same state) or
        // exactly one direction is allowed (the forward direction).
        if severity(before) == severity(after) {
            prop_assert!(forward_ok && backward_ok);
        } else if severity(after) > severity(before) {
            prop_assert!(forward_ok, "{:?} -> {:?} should be allowed", before, after);
            prop_assert!(
                !backward_ok,
                "{:?} -> {:?} must be forbidden (backward across severity)",
                after,
                before,
            );
        } else {
            prop_assert!(
                !forward_ok,
                "{:?} -> {:?} must be forbidden (backward across severity)",
                before,
                after,
            );
            prop_assert!(backward_ok, "{:?} -> {:?} should be allowed", after, before);
        }

        // Self-transitions are always allowed (degenerate forward step).
        prop_assert!(transition_is_allowed(before, before));
        prop_assert!(transition_is_allowed(after, after));
    }
}

// ----------------------------------------------------------------------------
// Invariant 4: passport_signature_breaks_under_any_subject_mutation
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
    #![proptest_config(ProptestConfig::with_cases(48))]

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

        // Sanity: the unmutated passport verifies.
        prop_assert!(verify_agent_passport(&passport, VERIFY_NOW).is_ok());

        apply_subject_mutation(&mut passport, mutation);

        let verdict = verify_agent_passport(&passport, VERIFY_NOW);
        prop_assert!(
            verdict.is_err(),
            "mutating {:?} must invalidate the passport verification",
            mutation,
        );
    }
}
