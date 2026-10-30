use super::*;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_finding::{
    compute_admission_id, compute_allocation_id, compute_authorization_id, compute_finding_id,
    compute_profile_id, compute_report_id, compute_terms_id, finding_checkpoint_log_id,
    sign_finding, Finding, FindingAdmission, FindingAuthorityKeyPolicy, FindingBackingRequirement,
    FindingBbsIssuerPolicy, FindingBondBacking, FindingBondClass, FindingChallengeBondLimit,
    FindingChallengeVerifierProfile, FindingCheckpointLogPolicy, FindingClaimedVerdict,
    FindingCollateralVault, FindingDescriptor, FindingEvidenceClass, FindingFacetKind,
    FindingFacetOutcome, FindingFacetResult, FindingFeeEvent, FindingFeeTerminalBinding,
    FindingGuaranteeClass, FindingMarketTerms, FindingOutcomeClass, FindingPayee,
    FindingPoolBinding, FindingPredicate, FindingReceiptRole, FindingReceiptSignerRole,
    FindingRecipeEnvironment, FindingRecipePhase, FindingRecipePhaseKind, FindingReplayRecipeInput,
    FindingResourceCaps, FindingSellerAuthorization, FindingVerifierReport,
    FINDING_ADMISSION_SCHEMA_V1, FINDING_BOND_BACKING_SCHEMA_V1,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_MARKET_TERMS_SCHEMA_V1,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1,
    FINDING_SELLER_AUTHORIZATION_SCHEMA_V1, FINDING_VERIFIER_REPORT_SCHEMA_V1,
};

pub(super) const FINDING_FIXTURE_KIND: &str = "finding-golden";

const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const VERIFIED_FIX_ISSUER_SEED: [u8; 32] = [9; 32];
const FIXTURE_README: &str = "README.md";
const FINDING_FIXTURE_DIR: &str = "finding";

/// A committed finding-family fixture directory. `generate` writes every
/// member except `README.md`, which is carried over from the committed
/// directory unchanged.
struct FindingFixture {
    id: &'static str,
    path: &'static str,
    description: &'static str,
    generate: fn(&Path) -> Result<(), CliError>,
}

const FINDING_FIXTURES: &[FindingFixture] = &[
    FindingFixture {
        id: "finding-verified-fix-basic",
        path: "fixtures/proof-room/finding/verified-fix-basic",
        description: "Issuer-signed chio.finding.v1 verified-fix golden",
        generate: generate_verified_fix,
    },
    FindingFixture {
        id: "finding-verifier-profile-basic",
        path: "fixtures/proof-room/finding/verifier-profile-basic",
        description: "Governance-signed challenge verifier profile golden",
        generate: generate_verifier_profile,
    },
    FindingFixture {
        id: "finding-market-terms-basic",
        path: "fixtures/proof-room/finding/market-terms-basic",
        description: "Seller-signed finding market terms golden",
        generate: generate_market_terms,
    },
    FindingFixture {
        id: "finding-seller-authorization-basic",
        path: "fixtures/proof-room/finding/seller-authorization-basic",
        description: "Issuer-signed seller authorization golden",
        generate: generate_seller_authorization,
    },
    FindingFixture {
        id: "finding-bond-backing-basic",
        path: "fixtures/proof-room/finding/bond-backing-basic",
        description: "Collateral-authority-signed bond backing golden",
        generate: generate_bond_backing,
    },
    FindingFixture {
        id: "finding-verifier-report-basic",
        path: "fixtures/proof-room/finding/verifier-report-basic",
        description: "Verifier-signed finding verifier report golden",
        generate: generate_verifier_report,
    },
    FindingFixture {
        id: "finding-venue-admission-basic",
        path: "fixtures/proof-room/finding/venue-admission-basic",
        description: "Venue-signed finding admission golden",
        generate: generate_venue_admission,
    },
    FindingFixture {
        id: "finding-replay-recipe-basic",
        path: "fixtures/proof-room/finding/replay-recipe-basic",
        description: "Unsigned finding replay recipe input golden",
        generate: generate_replay_recipe,
    },
    FindingFixture {
        id: "finding-cognition-market-qualified-profile",
        path: "fixtures/proof-room/finding/cognition-market-qualified-profile",
        description: "Cognition-market qualified profile Transaction Passport golden",
        generate: super::fixture_finding_cognition::generate_cognition_market_qualified_profile,
    },
];

/// Descriptors for the finding-family directories of `root`. They are
/// regeneration targets only and stay out of the published fixture catalog.
/// A root without a `finding` directory does not own these families.
pub(super) fn finding_fixture_descriptors(root: &Path) -> Vec<ProofFixtureDescriptor> {
    if !root.join(FINDING_FIXTURE_DIR).is_dir() {
        return Vec::new();
    }
    FINDING_FIXTURES
        .iter()
        .map(|fixture| ProofFixtureDescriptor {
            id: fixture.id.to_string(),
            kind: FINDING_FIXTURE_KIND.to_string(),
            path: fixture.path.to_string(),
            description: fixture.description.to_string(),
        })
        .collect()
}

/// Writes the finding-family fixture named by `descriptor` into the new
/// directory `out`, carrying `README.md` over from `committed`.
pub(super) fn materialize_finding_fixture(
    descriptor: &ProofFixtureDescriptor,
    committed: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let fixture = FINDING_FIXTURES
        .iter()
        .find(|fixture| fixture.id == descriptor.id)
        .ok_or_else(|| {
            CliError::cli_other_error(format!("unknown finding fixture id: {}", descriptor.id))
        })?;
    fs::create_dir_all(out)?;
    (fixture.generate)(out)?;
    let readme = committed.join(FIXTURE_README);
    if readme.is_file() {
        fs::write(out.join(FIXTURE_README), crate::input::read(readme)?)?;
    }
    Ok(())
}

pub(super) fn fixture_error(error: impl std::fmt::Display) -> CliError {
    CliError::cli_other_error(format!("finding fixture generation failed: {error}"))
}

fn write_pretty_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let mut json = serde_json::to_string_pretty(value)?;
    json.push('\n');
    fs::write(path, json)?;
    Ok(())
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

/// Unsigned verified-fix finding issued by the `[9; 32]` fixture key, with an
/// empty `finding_id` and signature.
pub(super) fn verified_fix_finding_draft() -> Finding {
    Finding {
        schema: FINDING_SCHEMA_V1.to_string(),
        finding_id: String::new(),
        descriptor: FindingDescriptor {
            topic: "repo:backbay/chio#test-failure".to_string(),
            context_sha256: "a".repeat(64),
            outcome_class: FindingOutcomeClass::VerifiedFix,
        },
        guarantee_class: FindingGuaranteeClass::DeterministicReplay,
        payload_sha256: "b".repeat(64),
        payload_media_type: "text/x-diff".to_string(),
        evidence_receipt_ids: vec!["r-1".to_string()],
        evidence_checkpoint_ref: "ckpt-1".to_string(),
        evidence_cost: MonetaryAmount {
            units: 4_200,
            currency: "USD".to_string(),
        },
        runtime_assurance_tier: None,
        evidence_class: FindingEvidenceClass::Verified,
        replay_recipe_sha256: Some("c".repeat(64)),
        intent_commitment_receipt_id: None,
        bond_ref: "bond-req-1".to_string(),
        status_feed_ref: "finding-status/test".to_string(),
        license_ref: None,
        price_hint_ref: None,
        issuer: verified_fix_issuer().public_key(),
        issued_at: 1_784_880_000,
        expires_at: 1_792_656_000,
        signature: String::new(),
    }
}

/// Content-addresses and signs `finding` with the verified-fix issuer key.
pub(super) fn sign_verified_fix_finding(mut finding: Finding) -> Result<Finding, CliError> {
    finding.finding_id = compute_finding_id(&finding).map_err(fixture_error)?;
    sign_finding(finding, &verified_fix_issuer()).map_err(fixture_error)
}

fn verified_fix_issuer() -> Keypair {
    Keypair::from_seed(&VERIFIED_FIX_ISSUER_SEED)
}

fn generate_verified_fix(out: &Path) -> Result<(), CliError> {
    let finding = sign_verified_fix_finding(verified_fix_finding_draft())?;
    write_pretty_json(&out.join("finding.json"), &finding)
}

fn generate_verifier_profile(out: &Path) -> Result<(), CliError> {
    let signed = SignedExportEnvelope::sign(profile_body()?, &keypair(1)).map_err(fixture_error)?;
    write_pretty_json(&out.join("profile.json"), &signed)
}

fn generate_market_terms(out: &Path) -> Result<(), CliError> {
    let seller = keypair(2);
    let signed =
        SignedExportEnvelope::sign(terms_body(&seller)?, &seller).map_err(fixture_error)?;
    write_pretty_json(&out.join("terms.json"), &signed)
}

fn generate_seller_authorization(out: &Path) -> Result<(), CliError> {
    let issuer = keypair(3);
    let seller = keypair(2);
    let signed = SignedExportEnvelope::sign(authorization_body(&issuer, &seller)?, &issuer)
        .map_err(fixture_error)?;
    write_pretty_json(&out.join("authorization.json"), &signed)
}

fn generate_bond_backing(out: &Path) -> Result<(), CliError> {
    let collateral = keypair(4);
    let seller = keypair(2);
    let signed = SignedExportEnvelope::sign(backing_body(&collateral, &seller)?, &collateral)
        .map_err(fixture_error)?;
    write_pretty_json(&out.join("backing.json"), &signed)
}

fn generate_verifier_report(out: &Path) -> Result<(), CliError> {
    let verifier = keypair(15);
    let signed =
        SignedExportEnvelope::sign(report_body(&verifier)?, &verifier).map_err(fixture_error)?;
    write_pretty_json(&out.join("report.json"), &signed)
}

fn generate_venue_admission(out: &Path) -> Result<(), CliError> {
    let venue = keypair(6);
    let signed =
        SignedExportEnvelope::sign(admission_body(&venue)?, &venue).map_err(fixture_error)?;
    write_pretty_json(&out.join("admission.json"), &signed)
}

fn generate_replay_recipe(out: &Path) -> Result<(), CliError> {
    write_pretty_json(&out.join("recipe.json"), &recipe_body())
}

fn key_policy(seed: u8, label: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: format!("authority-{label}"),
        key: keypair(seed).public_key(),
        key_epoch: 1,
        valid_from: 1_700_000_000,
        valid_until: 1_900_000_000,
        rotation_policy_ref: "rotation-policy-v1".to_string(),
        revocation_status_ref: "revocations/finding-market".to_string(),
    }
}

fn resource_caps() -> FindingResourceCaps {
    FindingResourceCaps {
        max_recipe_bytes: 262_144,
        max_evidence_receipts: 64,
        max_runtime_secs: 900,
        max_memory_bytes: 2_147_483_648,
    }
}

fn usd(units: u64) -> MonetaryAmount {
    MonetaryAmount {
        units,
        currency: "USD".to_string(),
    }
}

fn profile_body() -> Result<FindingChallengeVerifierProfile, CliError> {
    let mut profile = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_string(),
        profile_id: String::new(),
        governance_authority: keypair(1).public_key(),
        operator: "venue-operator".to_string(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: key_policy(11, "production"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: key_policy(12, "delivery"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: key_policy(13, "replay"),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id: finding_checkpoint_log_id(&keypair(14).public_key()).map_err(fixture_error)?,
            signer: key_policy(14, "checkpoint"),
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "bbs-issuer-fp".to_string(),
            key_hex: HEX64.to_string(),
            registry_ref: "registry/bbs-issuers".to_string(),
            key_epoch: 1,
            valid_from: 1_700_000_000,
            valid_until: 1_900_000_000,
            revocation_status_ref: "revocations/bbs".to_string(),
        },
        allowed_runner_manifests: vec![HEX64.to_string()],
        required_receipt_semantics: "chio.mediated_spend.v1".to_string(),
        resolver_policy_ref: "resolver-policy-v1".to_string(),
        retention_policy_ref: "retention-forever-v1".to_string(),
        resource_caps: resource_caps(),
        predicate_engine: "chio-replay-v1".to_string(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: vec![
            FindingFacetKind::ArtifactIntegrity,
            FindingFacetKind::ReceiptAuthenticity,
            FindingFacetKind::CheckpointMembership,
            FindingFacetKind::BondBacking,
            FindingFacetKind::GuaranteeConsistency,
        ],
        verifier_report_signer: key_policy(15, "verifier-report"),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    profile.profile_id = compute_profile_id(&profile).map_err(fixture_error)?;
    Ok(profile)
}

fn terms_body(seller: &Keypair) -> Result<FindingMarketTerms, CliError> {
    let mut terms = FindingMarketTerms {
        schema: FINDING_MARKET_TERMS_SCHEMA_V1.to_string(),
        terms_id: String::new(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        seller: seller.public_key(),
        backing_requirement: FindingBackingRequirement {
            base_finding_stake: usd(50),
            maximum_sale_exposure: usd(450),
            collateral_policy: "venue_ledger_exclusive_v1".to_string(),
        },
        filing_window_secs: 86_400,
        claim_window_secs: 604_800,
        appeal_window_secs: 259_200,
        audit_epoch_length_secs: 2_592_000,
        audit_eligible: true,
        decision_rule_refs: vec!["decision/replay-v1".to_string()],
        verifier_profile_envelope_sha256: HEX64.to_string(),
        challenge_bond_limits: vec![FindingChallengeBondLimit {
            guarantee_class: FindingGuaranteeClass::DeterministicReplay,
            min_bond: usd(10),
            max_bond: usd(100),
        }],
        payout_policy: "pro_rata_capped_v1".to_string(),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    terms.terms_id = compute_terms_id(&terms).map_err(fixture_error)?;
    Ok(terms)
}

fn authorization_body(
    issuer: &Keypair,
    seller: &Keypair,
) -> Result<FindingSellerAuthorization, CliError> {
    let mut authorization = FindingSellerAuthorization {
        schema: FINDING_SELLER_AUTHORIZATION_SCHEMA_V1.to_string(),
        authorization_id: String::new(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        issuer: issuer.public_key(),
        seller: seller.public_key(),
        provider_server_id: "finding-server".to_string(),
        provider_tool: "finding.reveal".to_string(),
        payee: FindingPayee::Beneficiary {
            destination: "rail:venue-ledger:seller-42".to_string(),
            currency: "USD".to_string(),
        },
        revocation_status_ref: "revocations/seller-auth".to_string(),
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    authorization.authorization_id =
        compute_authorization_id(&authorization).map_err(fixture_error)?;
    Ok(authorization)
}

fn backing_body(authority: &Keypair, seller: &Keypair) -> Result<FindingBondBacking, CliError> {
    let mut backing = FindingBondBacking {
        schema: FINDING_BOND_BACKING_SCHEMA_V1.to_string(),
        allocation_id: String::new(),
        collateral_authority: authority.public_key(),
        seller: seller.public_key(),
        authorization_envelope_sha256: HEX64.to_string(),
        finding_id: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        terms_envelope_sha256: HEX64.to_string(),
        profile_envelope_sha256: HEX64.to_string(),
        fee_requirement_sha256: HEX64.to_string(),
        fee_schedule_envelope_sha256: HEX64.to_string(),
        bond_class: FindingBondClass::Listing,
        locked_amount: usd(500),
        maximum_sale_exposure: usd(450),
        claim_horizon_secs: 604_800,
        audit_horizon_secs: 2_592_000,
        appeal_horizon_secs: 259_200,
        settlement_buffer_secs: 86_400,
        vault: FindingCollateralVault::VenueLedger {
            ledger_account: "vault:finding-collateral".to_string(),
            operator_epoch: 1,
        },
        issued_at: 1_700_000_000,
        expires_at: 1_900_000_000,
    };
    backing.allocation_id = compute_allocation_id(&backing).map_err(fixture_error)?;
    Ok(backing)
}

fn verified_facets() -> Vec<FindingFacetResult> {
    FindingFacetKind::ALL
        .into_iter()
        .map(|facet| {
            let outcome = match facet {
                FindingFacetKind::StatusLiveness => FindingFacetOutcome::Unavailable,
                _ => FindingFacetOutcome::Verified,
            };
            FindingFacetResult {
                facet,
                outcome,
                reason: "evaluated under the pinned verifier profile".to_string(),
                evidence_refs: Vec::new(),
            }
        })
        .collect()
}

fn report_body(verifier: &Keypair) -> Result<FindingVerifierReport, CliError> {
    let mut report = FindingVerifierReport {
        schema: FINDING_VERIFIER_REPORT_SCHEMA_V1.to_string(),
        report_id: String::new(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        verifier_profile_id: HEX64.to_string(),
        verifier_profile_envelope_sha256: HEX64.to_string(),
        verifier_implementation_id: "chio-finding-verifier/0.1".to_string(),
        resolved_evidence_bundle_sha256: HEX64.to_string(),
        replay_recipe_input_sha256: None,
        status_proof_input_sha256: None,
        finding_delivery_receipt_id: None,
        finding_delivery: None,
        trust_root_snapshot_sha256: HEX64.to_string(),
        resolver_policy_sha256: HEX64.to_string(),
        trusted_time_input_sha256: HEX64.to_string(),
        facets: verified_facets(),
        backing_allocation_id: Some(HEX64.to_string()),
        verifier_authority: verifier.public_key(),
        verifier_key_epoch: 1,
        evaluation_time: 1_750_000_000,
    };
    report.report_id = compute_report_id(&report).map_err(fixture_error)?;
    Ok(report)
}

fn fee_terminal(event: FindingFeeEvent, units: u64) -> FindingFeeTerminalBinding {
    FindingFeeTerminalBinding {
        fee_schedule_envelope_sha256: HEX64.to_string(),
        event,
        payer: "seller-42".to_string(),
        amount: usd(units),
        pool_principal_id: "pool:audit".to_string(),
        rail_destination: "rail:venue-ledger:audit-pool".to_string(),
        instruction_sha256: HEX64.to_string(),
        observation_sha256: HEX64.to_string(),
    }
}

fn admission_body(venue: &Keypair) -> Result<FindingAdmission, CliError> {
    let mut admission = FindingAdmission {
        schema: FINDING_ADMISSION_SCHEMA_V1.to_string(),
        admission_id: String::new(),
        venue: venue.public_key(),
        venue_id: "venue-wedge".to_string(),
        finding_id: HEX64.to_string(),
        finding_artifact_sha256: HEX64.to_string(),
        seller_authorization_envelope_sha256: HEX64.to_string(),
        listing_id: "finding-listing-01".to_string(),
        listing_envelope_sha256: HEX64.to_string(),
        server_id: "finding-server".to_string(),
        metadata_url: format!("https://venue.example/v1/findings/{HEX64}"),
        pricing_hint_envelope_sha256: HEX64.to_string(),
        capability_scope: format!("finding:{HEX64}"),
        publisher_operator_id: "venue-operator".to_string(),
        payee_destination: "rail:venue-ledger:seller-42".to_string(),
        fee_schedule_envelope_sha256: HEX64.to_string(),
        verifier_report_id: HEX64.to_string(),
        verifier_report_envelope_sha256: HEX64.to_string(),
        terms_envelope_sha256: HEX64.to_string(),
        profile_envelope_sha256: HEX64.to_string(),
        fee_terminals: vec![
            fee_terminal(FindingFeeEvent::Publication, 5),
            fee_terminal(FindingFeeEvent::ParticipationEpoch { epoch_index: 0 }, 3),
        ],
        backing_allocation_id: HEX64.to_string(),
        backing_envelope_sha256: HEX64.to_string(),
        audit_pool: FindingPoolBinding {
            principal_id: "pool:audit".to_string(),
            rail_destination: "rail:venue-ledger:audit-pool".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolBinding {
            principal_id: "pool:challenge-admin".to_string(),
            rail_destination: "rail:venue-ledger:challenge-admin".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        community_fund_destination: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
        status_feed_operator_ref: "status-feed/venue-wedge".to_string(),
        purchase_authority: key_policy(16, "purchase"),
        failed_delivery_authority: key_policy(17, "failed-delivery"),
        issued_at: 1_700_000_000,
        expires_at: 1_800_000_000,
    };
    admission.admission_id = compute_admission_id(&admission).map_err(fixture_error)?;
    Ok(admission)
}

fn recipe_body() -> FindingReplayRecipeInput {
    FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/replay-v1".to_string(),
        verifier_profile_envelope_sha256: HEX64.to_string(),
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
                input_bundle_sha256: HEX64.to_string(),
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
        resource_bounds: resource_caps(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: HEX64.to_string(),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    }
}
