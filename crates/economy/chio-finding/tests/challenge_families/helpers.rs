use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, canonical_json_string};
use chio_finding::{
    sign_audit_seed_witness, compute_audit_epoch_id, compute_audit_report_id,
    compute_challenge_id, compute_enforcement_id, compute_snapshot_id,
    derive_audit_seed_commitment, derive_outcome_id, FindingAffectedDelivery, FindingAuditEpoch,
    FindingAuditReport, FindingBuyerSubmission, FindingChallenge, FindingChallengeAuthorization,
    FindingChallengeAuthorizationKind, FindingChallengeEnforcement, FindingChallengeEvidence,
    FindingChallengeFacet, FindingChallengeOutcome, FindingChallengeStanding,
    FindingChallengeVerdict, FindingCheckpointRef, FindingDigestMismatchFacet,
    FindingDisputeBondClass, FindingDisputeFeeEvent, FindingDisputeFeeTerminal,
    FindingDisputeLockRef, FindingEffectIntentBinding, FindingEffectIntentKind,
    FindingEnforcementDestination, FindingError, FindingFinalizedBondSnapshot, FindingMissedAudit,
    FindingObservedFinality, FindingPenaltyCalculation, FindingPredicate, FindingReceiptRef,
    FindingRecipeEnvironment, FindingRecipePhase, FindingRecipePhaseKind,
    FindingReplayContradictionFacet, FindingReplayObservation, FindingReplayPredicateResult,
    FindingReplayRecipeInput, FindingReplayReproduction, FindingReplayTerminalResult,
    FindingResourceCaps, FindingVaultReference, FindingVenueAuditAuthorization,
    FINDING_AUDIT_EPOCH_SCHEMA_V1, FINDING_AUDIT_REPORT_SCHEMA_V1,
    FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1, FINDING_CHALLENGE_OUTCOME_SCHEMA_V1,
    FINDING_CHALLENGE_SCHEMA_V1, FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1,
    FINDING_REPLAY_OBSERVATION_SCHEMA_V1, FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
};
use serde_json::{json, Value};
use std::error::Error;
use std::path::PathBuf;

pub(crate) type TestResult = Result<(), Box<dyn Error>>;

pub(crate) const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub(crate) const HEX64_ALT: &str =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
pub(crate) const HEX64_THIRD: &str =
    "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
pub(crate) const SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
pub(crate) const ABOVE_I_JSON_MAX: u64 = 9_007_199_254_740_992;

/// Every artifact family this lane registers. The round-trip coverage
/// assertion is keyed on this list, so a family added to the lane without a
/// value that reaches its registered schema fails here.
pub(crate) const CHALLENGE_LANE_FAMILIES: [&str; 8] = [
    "audit-epoch",
    "audit-report",
    "audit-round-authorization",
    "challenge",
    "challenge-enforcement",
    "challenge-outcome",
    "finalized-bond-snapshot",
    "replay-observation",
];

pub(crate) fn refusal<T, E: std::fmt::Debug>(result: Result<T, E>) -> E {
    match result {
        Ok(_) => panic!("input was accepted"),
        Err(error) => error,
    }
}

pub(crate) fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

pub(crate) fn schema_path(family: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-finding/v1")
        .join(format!("{family}.schema.json"))
}

pub(crate) fn validate_family_schema(
    family: &str,
    value: &Value,
) -> Result<(), chio_spec_validate::ValidateError> {
    let path = schema_path(family);
    let schema = chio_spec_validate::load_json(&path)?;
    chio_spec_validate::validate_value(&path, &schema, &path, value)
}

pub(crate) fn assert_family_schema_rejects(family: &str, value: &Value, case: &str) -> TestResult {
    match validate_family_schema(family, value) {
        Err(chio_spec_validate::ValidateError::SchemaViolation(_, _, _)) => Ok(()),
        Err(err) => Err(err.into()),
        Ok(()) => Err(std::io::Error::other(format!(
            "{family} schema accepted invalid case: {case}"
        ))
        .into()),
    }
}

/// The exact document a verifier reads: the artifact's canonical bytes,
/// parsed back. Schema conformance is checked over those bytes rather than
/// over an in-memory value that never crossed the wire.
pub(crate) fn canonical_document<T: serde::Serialize>(
    artifact: &T,
) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(&canonical_json_bytes(artifact)?)?)
}

pub(crate) fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

pub(crate) fn recipe_body(profile_envelope_sha256: &str) -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: profile_envelope_sha256.to_string(),
        context_sha256: HEX64.to_string(),
        payload_sha256: HEX64.to_string(),
        runner_server: "finding-server".to_string(),
        runner_tool: "finding.replay".to_string(),
        runner_manifest_sha256: HEX64.to_string(),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: HEX64.to_string(),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: HEX64_ALT.to_string(),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: HEX64.to_string(),
        environment: FindingRecipeEnvironment {
            runtime_image_sha256: HEX64.to_string(),
            platform: "linux/amd64".to_string(),
            network_policy: "deny_all".to_string(),
            clock_policy: "fixed:1700000000".to_string(),
            randomness_policy: "seed:42".to_string(),
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
        },
        resource_bounds: FindingResourceCaps {
            max_recipe_bytes: 262_144,
            max_evidence_receipts: 64,
            max_runtime_secs: 900,
            max_memory_bytes: 2_147_483_648,
        },
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: HEX64.to_string(),
        claimed_verdict: chio_finding::FindingClaimedVerdict::PredicateHolds,
    }
}

pub(crate) fn observation_body(
    recipe_digest: &str,
    profile_envelope_sha256: &str,
    phase: FindingRecipePhaseKind,
    run_id: &str,
) -> FindingReplayObservation {
    FindingReplayObservation {
        schema: FINDING_REPLAY_OBSERVATION_SCHEMA_V1.to_string(),
        recipe_digest: recipe_digest.to_string(),
        verifier_profile_digest: profile_envelope_sha256.to_string(),
        phase_id: phase,
        runner_manifest_digest: HEX64.to_string(),
        resolved_input_bundle_digest: match phase {
            FindingRecipePhaseKind::Baseline => HEX64.to_string(),
            FindingRecipePhaseKind::Candidate => HEX64_ALT.to_string(),
        },
        environment_digest: HEX64_THIRD.to_string(),
        terminal_result: FindingReplayTerminalResult::Completed,
        exit_code: match phase {
            FindingRecipePhaseKind::Baseline => 1,
            FindingRecipePhaseKind::Candidate => 0,
        },
        report_digest: match phase {
            FindingRecipePhaseKind::Baseline => HEX64.to_string(),
            FindingRecipePhaseKind::Candidate => HEX64_ALT.to_string(),
        },
        replay_run_id: run_id.to_string(),
    }
}

pub(crate) fn affected_delivery() -> FindingAffectedDelivery {
    FindingAffectedDelivery {
        receipt_id: "delivery-receipt-42".to_string(),
        receipt_sha256: HEX64.to_string(),
        checkpoint_ref: "checkpoints/venue-wedge/9001".to_string(),
        checkpoint_sha256: HEX64_ALT.to_string(),
    }
}

pub(crate) fn receipt_ref(receipt_id: &str) -> FindingReceiptRef {
    FindingReceiptRef {
        receipt_id: receipt_id.to_string(),
        receipt_sha256: HEX64.to_string(),
    }
}

pub(crate) fn checkpoint_ref() -> FindingCheckpointRef {
    FindingCheckpointRef {
        checkpoint_ref: "checkpoints/venue-wedge/9001".to_string(),
        checkpoint_sha256: HEX64_ALT.to_string(),
    }
}

pub(crate) fn buyer_authorization(
    challenger: &Keypair,
    standing: FindingChallengeStanding,
) -> FindingChallengeAuthorization {
    FindingChallengeAuthorization::BuyerSubmission(Box::new(FindingBuyerSubmission {
        challenger: challenger.public_key(),
        dispute_fee_terminal: FindingDisputeFeeTerminal {
            fee_schedule_envelope_sha256: HEX64.to_string(),
            event: FindingDisputeFeeEvent::ChallengeFiling,
            payer: challenger.public_key(),
            amount: usd(2_500),
            beneficiary_pool_principal_id: "pool:challenge-administration".to_string(),
            rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
        },
        dispute_lock_ref: FindingDisputeLockRef {
            lock_id: "dispute-lock-42".to_string(),
            class: FindingDisputeBondClass::Dispute,
            fee_schedule_envelope_sha256: HEX64.to_string(),
            amount: usd(10_000),
            expiry: 1_760_000_000,
        },
        standing,
    }))
}

pub(crate) fn venue_authorization() -> FindingChallengeAuthorization {
    FindingChallengeAuthorization::VenueAudit(FindingVenueAuditAuthorization {
        audit_epoch_envelope_sha256: HEX64.to_string(),
        selection_digest: HEX64_ALT.to_string(),
        authorization_digest: HEX64_THIRD.to_string(),
    })
}

pub(crate) fn digest_mismatch_evidence() -> FindingChallengeEvidence {
    FindingChallengeEvidence::DigestMismatch {
        failed_delivery_envelope_sha256: HEX64_THIRD.to_string(),
        deny_receipt_ref: receipt_ref("deny-receipt-42"),
        deny_checkpoint_ref: checkpoint_ref(),
    }
}

pub(crate) fn evidence_invalid_evidence() -> FindingChallengeEvidence {
    FindingChallengeEvidence::EvidenceInvalid {
        challenged_evidence_receipt_refs: vec![receipt_ref("evidence-receipt-1")],
        challenged_checkpoint_ref: checkpoint_ref(),
        purchase_record_envelope_sha256: HEX64_ALT.to_string(),
    }
}

pub(crate) fn replay_evidence(
    profile_envelope_sha256: &str,
) -> Result<FindingChallengeEvidence, Box<dyn Error>> {
    let recipe = recipe_body(profile_envelope_sha256);
    let recipe_preimage = canonical_json_string(&recipe)?;
    let recipe_digest = recipe.canonical_sha256()?;
    let reproduction = vec![
        FindingReplayReproduction {
            receipt_ref: receipt_ref("replay-receipt-baseline"),
            checkpoint_ref: checkpoint_ref(),
            observation_bytes: canonical_json_string(&observation_body(
                &recipe_digest,
                profile_envelope_sha256,
                FindingRecipePhaseKind::Baseline,
                "replay-run-42",
            ))?,
        },
        FindingReplayReproduction {
            receipt_ref: receipt_ref("replay-receipt-candidate"),
            checkpoint_ref: checkpoint_ref(),
            observation_bytes: canonical_json_string(&observation_body(
                &recipe_digest,
                profile_envelope_sha256,
                FindingRecipePhaseKind::Candidate,
                "replay-run-42",
            ))?,
        },
    ];
    Ok(FindingChallengeEvidence::ReplayContradiction {
        reproduction,
        recipe_preimage,
        purchase_record_envelope_sha256: HEX64_ALT.to_string(),
    })
}

pub(crate) fn challenge_body(
    authorization: FindingChallengeAuthorization,
    evidence: FindingChallengeEvidence,
) -> Result<FindingChallenge, FindingError> {
    let mut challenge = FindingChallenge {
        schema: FINDING_CHALLENGE_SCHEMA_V1.to_string(),
        challenge_id: String::new(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64_ALT.to_string(),
        listing_id: "finding-listing-01".to_string(),
        terms_envelope_sha256: HEX64.to_string(),
        profile_envelope_sha256: HEX64_THIRD.to_string(),
        venue_admission_envelope_sha256: HEX64.to_string(),
        backing_envelope_sha256: HEX64_ALT.to_string(),
        filed_at: 1_750_000_000,
        affected_deliveries: vec![affected_delivery()],
        authorization,
        evidence,
    };
    challenge.challenge_id = compute_challenge_id(&challenge)?;
    Ok(challenge)
}

pub(crate) fn failed_delivery_standing() -> FindingChallengeStanding {
    FindingChallengeStanding::FailedDelivery {
        failed_delivery_id: HEX64.to_string(),
        failed_delivery_envelope_sha256: HEX64_THIRD.to_string(),
    }
}

pub(crate) fn purchase_standing() -> FindingChallengeStanding {
    FindingChallengeStanding::FinalizedPurchase {
        purchase_key: HEX64.to_string(),
        purchase_record_envelope_sha256: HEX64_ALT.to_string(),
    }
}

pub(crate) fn buyer_digest_mismatch_challenge(
    challenger: &Keypair,
) -> Result<FindingChallenge, FindingError> {
    challenge_body(
        buyer_authorization(challenger, failed_delivery_standing()),
        digest_mismatch_evidence(),
    )
}

pub(crate) fn venue_replay_challenge() -> Result<FindingChallenge, Box<dyn Error>> {
    let evidence = replay_evidence(HEX64_THIRD)?;
    Ok(challenge_body(venue_authorization(), evidence)?)
}

pub(crate) fn outcome_body(
    challenge_envelope_sha256: &str,
    verdict: FindingChallengeVerdict,
    facet: FindingChallengeFacet,
) -> Result<FindingChallengeOutcome, FindingError> {
    let evidence_kind = facet.kind();
    let penalty_calculation = match verdict {
        FindingChallengeVerdict::Upheld => Some(FindingPenaltyCalculation {
            base_finding_stake_units: 100_000,
            open_per_sale_encumbrance_units: 20_000,
            computed_exposure_units: 120_000,
            listing_required_amount_units: 150_000,
            live_allocated_collateral_units: 130_000,
            penalty_amount: usd(120_000),
        }),
        _ => None,
    };
    let mut outcome = FindingChallengeOutcome {
        schema: FINDING_CHALLENGE_OUTCOME_SCHEMA_V1.to_string(),
        outcome_id: String::new(),
        challenge_envelope_sha256: challenge_envelope_sha256.to_string(),
        finding_id: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        backing_allocation_id: HEX64_ALT.to_string(),
        authorization: FindingChallengeAuthorizationKind::BuyerSubmission,
        audit_epoch_envelope_sha256: None,
        evidence_kind,
        verifier_profile_envelope_sha256: HEX64_THIRD.to_string(),
        evidence_bundle_digest: HEX64.to_string(),
        verdict,
        facet,
        reason: "committed payload digest does not match the delivered output".to_string(),
        trigger_digest: HEX64_ALT.to_string(),
        retry_deadline: None,
        penalty_calculation,
        evaluator_authority_id: "challenge-evaluator".to_string(),
        evaluator_key: keypair(43).public_key(),
        evaluator_key_epoch: 7,
        evaluator_valid_from: 1_700_000_000,
        evaluator_valid_until: 1_800_000_000,
        evaluator_revocation_status_ref: "revocations/challenge-evaluator".to_string(),
        evaluated_at: 1_750_000_500,
    };
    outcome.outcome_id = derive_outcome_id(&outcome)?;
    Ok(outcome)
}

pub(crate) fn upheld_outcome_with_penalty(
    penalty_calculation: FindingPenaltyCalculation,
) -> Result<FindingChallengeOutcome, FindingError> {
    let mut outcome = outcome_body(
        HEX64,
        FindingChallengeVerdict::Upheld,
        digest_mismatch_facet(),
    )?;
    outcome.penalty_calculation = Some(penalty_calculation);
    outcome.outcome_id = derive_outcome_id(&outcome)?;
    Ok(outcome)
}

pub(crate) fn digest_mismatch_facet() -> FindingChallengeFacet {
    FindingChallengeFacet::DigestMismatch(FindingDigestMismatchFacet {
        committed_payload_sha256: HEX64.to_string(),
        delivered_output_sha256: HEX64_ALT.to_string(),
        transform_profile: "identity".to_string(),
        realized_spend_units: 0,
    })
}

pub(crate) fn replay_facet(result: FindingReplayPredicateResult) -> FindingChallengeFacet {
    FindingChallengeFacet::ReplayContradiction(FindingReplayContradictionFacet {
        replay_run_id: "replay-run-42".to_string(),
        recipe_sha256: HEX64.to_string(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        predicate_result: result,
        observation_digests: vec![HEX64.to_string(), HEX64_ALT.to_string()],
    })
}

pub(crate) fn enforcement_body() -> Result<FindingChallengeEnforcement, FindingError> {
    let mut enforcement = FindingChallengeEnforcement {
        schema: FINDING_CHALLENGE_ENFORCEMENT_SCHEMA_V1.to_string(),
        enforcement_id: String::new(),
        liability_key: HEX64.to_string(),
        finding_id: HEX64_ALT.to_string(),
        listing_id: "finding-listing-01".to_string(),
        outcome_id: HEX64_THIRD.to_string(),
        outcome_envelope_sha256: HEX64.to_string(),
        penalty_envelope_sha256: HEX64_ALT.to_string(),
        bond_snapshot_envelope_sha256: HEX64_THIRD.to_string(),
        purchase_snapshot_digest: HEX64.to_string(),
        deterministic_allocation_digest: HEX64_ALT.to_string(),
        seller_allocation_id: HEX64_THIRD.to_string(),
        vault: FindingVaultReference {
            chain_id: "eip155:8453".to_string(),
            vault_contract: "0x00000000000000000000000000000000000000bd".to_string(),
            vault_id: "vault-42".to_string(),
        },
        amount: usd(120_000),
        destinations: vec![
            FindingEnforcementDestination {
                destination: "rail:venue-ledger:buyer-1".to_string(),
                amount: usd(90_000),
            },
            FindingEnforcementDestination {
                destination: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                amount: usd(30_000),
            },
        ],
        effect_intents: vec![
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::SellerImpair,
                intent_id: HEX64.to_string(),
            },
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::RootIntent,
                intent_id: HEX64_ALT.to_string(),
            },
            FindingEffectIntentBinding {
                kind: FindingEffectIntentKind::Retraction,
                intent_id: HEX64_THIRD.to_string(),
            },
        ],
        penalty_authority_id: "market-penalty".to_owned(),
        penalty_key: keypair(45).public_key(),
        penalty_key_epoch: 1,
        penalty_valid_from: 1,
        penalty_valid_until: 1_800_000_000,
        penalty_revocation_status_ref: "revocations/market-penalty".to_owned(),
        finalization_authority_id: "venue-finalization".to_owned(),
        finalization_key: keypair(44).public_key(),
        finalization_key_epoch: 1,
        finalization_valid_from: 1,
        finalization_valid_until: 1_800_000_000,
        finalization_revocation_status_ref: "revocations/venue-finalization".to_owned(),
        finalized_at: 1_750_100_000,
    };
    enforcement.enforcement_id = compute_enforcement_id(&enforcement)?;
    Ok(enforcement)
}

pub(crate) fn bond_snapshot_body(
    seller: &Keypair,
) -> Result<FindingFinalizedBondSnapshot, FindingError> {
    let mut snapshot = FindingFinalizedBondSnapshot {
        schema: FINDING_FINALIZED_BOND_SNAPSHOT_SCHEMA_V1.to_string(),
        snapshot_id: String::new(),
        chain_id: "eip155:8453".to_string(),
        vault_contract: "0x00000000000000000000000000000000000000bd".to_string(),
        vault_id: "vault-42".to_string(),
        seller: seller.public_key(),
        allocation_id: HEX64.to_string(),
        locked_amount: 500_000,
        held_amount: 120_000,
        slashed_amount: 0,
        currency: "USD".to_string(),
        block_number: 21_000_000,
        block_hash: format!("0x{HEX64}"),
        finality_policy: "confirmations>=64".to_string(),
        observed_finality: FindingObservedFinality::Confirmations { depth: 96 },
        identity_registry_record: "registry/operators/venue-42".to_string(),
        operator_key_hash: HEX64_ALT.to_string(),
        operator_key_epoch: 3,
        observed_at: 1_750_090_000,
    };
    snapshot.snapshot_id = compute_snapshot_id(&snapshot)?;
    Ok(snapshot)
}

pub(crate) fn audit_epoch_body() -> Result<FindingAuditEpoch, FindingError> {
    let audit_authority = keypair(42);
    let seed_witness = keypair(43);
    let eligible_snapshot_at = 1_749_999_000;
    let seed_witnessed_at = 1_749_999_500;
    let seed_commitment = derive_audit_seed_commitment(SEED);
    let mut epoch = FindingAuditEpoch {
        schema: FINDING_AUDIT_EPOCH_SCHEMA_V1.to_string(),
        audit_epoch_id: String::new(),
        epoch_index: 4,
        audit_authority: audit_authority.public_key(),
        seed_witnessed_at,
        eligible_snapshot_at,
        seed_witness: seed_witness.public_key(),
        seed_witness_signature: sign_audit_seed_witness(
            &seed_witness,
            &audit_authority.public_key(),
            4,
            HEX64,
            &seed_commitment,
            eligible_snapshot_at,
            seed_witnessed_at,
        )?,
        eligible_snapshot_digest: HEX64.to_string(),
        eligible_listing_count: 128,
        fee_schedule_envelope_sha256: HEX64_ALT.to_string(),
        seed_commitment,
        selection_algorithm_id: "weighted-reservoir-v1".to_string(),
        published_rate_bps: 250,
        available_budget: usd(750_000),
        authorization_digest: HEX64_THIRD.to_string(),
        committed_at: 1_750_000_000,
    };
    epoch.audit_epoch_id = compute_audit_epoch_id(&epoch)?;
    Ok(epoch)
}

pub(crate) fn audit_report_body(
    epoch_envelope_sha256: &str,
) -> Result<FindingAuditReport, FindingError> {
    let mut report = FindingAuditReport {
        schema: FINDING_AUDIT_REPORT_SCHEMA_V1.to_string(),
        audit_report_id: String::new(),
        audit_epoch_envelope_sha256: epoch_envelope_sha256.to_string(),
        revealed_seed: SEED.to_string(),
        selected_finding_ids: vec![HEX64.to_string(), HEX64_ALT.to_string()],
        attempt_envelope_sha256s: vec![HEX64.to_string()],
        missed_attempts: vec![FindingMissedAudit {
            finding_id: HEX64_ALT.to_string(),
            reason: "retained replay inputs expired before the attempt".to_string(),
        }],
        outcome_envelope_digests: vec![HEX64_THIRD.to_string()],
        reported_at: 1_750_050_000,
    };
    report.audit_report_id = compute_audit_report_id(&report)?;
    Ok(report)
}

pub(crate) fn market_penalty_envelope() -> Result<Value, Box<dyn Error>> {
    let authority = keypair(31);
    let body = json!({
        "schema": "chio.registry.market-penalty.v1",
        "penaltyId": "market-penalty-42",
        "feeScheduleId": "fee-schedule-1",
        "charterId": "charter-1",
        "caseId": "case-1",
        "governingOperatorId": "venue-operator",
        "namespace": "findings",
        "listingId": "finding-listing-01",
        "abuseClass": "fraudulent_listing",
        "bondClass": "listing",
        "action": "hold_bond",
        "state": "enforced",
        "penaltyAmount": { "units": 120_000, "currency": "USD" },
        "openedAt": 1_750_000_000_u64,
        "updatedAt": 1_750_000_000_u64,
        "evidenceRefs": [
            {
                "kind": "external",
                "referenceId": HEX64,
                "sha256": HEX64_ALT,
            }
        ],
        "issuedBy": "venue-operator",
    });
    let envelope = SignedExportEnvelope::sign(body, &authority)?;
    Ok(serde_json::to_value(&envelope)?)
}
