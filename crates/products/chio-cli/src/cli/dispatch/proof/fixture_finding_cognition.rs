use super::fixture_finding::{
    fixture_error, sign_verified_fix_finding, verified_fix_finding_draft,
};
use super::*;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::metadata::{
    DeliveryResult, FindingDelivery, FindingDeliverySettlementMode, FindingMediaTypeCheck,
    FindingTransformProfile, FINDING_DELIVERY_SCHEMA,
};
use chio_finding::{
    build_status_non_inclusion_proof_input, compute_profile_id, compute_report_id,
    compute_status_epoch_id, derive_purchase_key, finding_checkpoint_log_id,
    signed_envelope_sha256, FindingAuthorityKeyPolicy, FindingBbsIssuerPolicy,
    FindingChallengeVerifierProfile, FindingCheckpointLogPolicy, FindingClaimedVerdict,
    FindingFacetKind, FindingFacetOutcome, FindingFacetResult, FindingPredicate,
    FindingPurchaseRecord, FindingReceiptRole, FindingReceiptSignerRole, FindingRecipeEnvironment,
    FindingRecipePhase, FindingRecipePhaseKind, FindingReplayRecipeInput, FindingResourceCaps,
    FindingStatusEpoch, FindingVerifierReport, SignedFindingChallengeVerifierProfile,
    FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1, FINDING_PURCHASE_RECORD_SCHEMA_V1,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_SCHEMA_V1, FINDING_STATUS_EPOCH_SCHEMA_V1,
    FINDING_STATUS_PROOF_INPUT_SCHEMA_V1, FINDING_VERIFIER_REPORT_SCHEMA_V1,
};
use chio_open_market::purchase_verification::{
    derive_payment_operation_id, derive_purchase_intent_id,
};
use chio_revocation_oracle::{
    finding_status_empty_leaf_hash, FindingStatusSparseMap, FINDING_STATUS_BRANCH_DOMAIN,
    FINDING_STATUS_EMPTY_LEAF_DOMAIN, FINDING_STATUS_HASH_ALGORITHM,
    FINDING_STATUS_KEY_DOMAIN_NONCE, FINDING_STATUS_KEY_HASH_DOMAIN, FINDING_STATUS_MAP_VERSION,
    FINDING_STATUS_OCCUPIED_LEAF_DOMAIN, FINDING_STATUS_PROOF_SEMANTICS,
    FINDING_STATUS_SPARSE_DEPTH,
};
use chio_transaction_passport::{
    sign_transaction_passport, TransactionPassport, COGNITION_MARKET_CLAIMS,
};
use serde_json::{json, Value};

const STATUS_FEED_ID: &str = "finding-status/test";
const RETRACTED_FINDING_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RETRACTION_INTENT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const GENERATED_AT: u64 = 1_784_880_000;
const CHECKED_AT: u64 = 1_784_880_030;
const ISSUED_AT: &str = "2026-07-31T20:00:30Z";
const LISTING_ID: &str = "listing-qualified-transaction";
const RESERVATION_ID: &str = "reservation-qualified-transaction";

const PASSPORT_SIGNER_SEED: u8 = 7;
const PROFILE_GOVERNANCE_SEED: u8 = 8;
const VERIFIER_SEED: u8 = 9;
const PURCHASE_AUTHORITY_SEED: u8 = 11;
const BUYER_SEED: u8 = 12;
const PAYER_SEED: u8 = 13;
const STATUS_OPERATOR_SEED: u8 = 42;

const FINDING_PATH: &str = "finding.json";
const RECIPE_PATH: &str = "attachments/replay-recipe-input.json";
const STATUS_PATH: &str = "attachments/status-proof-input.json";
const REPORT_PATH: &str = "report.json";
const PURCHASE_RECORD_PATH: &str = "purchase-record.json";
const CLAIM_SET_PATH: &str = "claim-set.json";
const VERIFIER_POLICY_PATH: &str = "verifier-policy.json";
const EVIDENCE_GRAPH_PATH: &str = "evidence-graph.json";
const PASSPORT_PATH: &str = "transaction-passport.json";
const DEPLOYMENT_PROFILE_PATH: &str = "deployment/verifier-profile.json";

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn canonical<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CliError> {
    chio_core_types::canonical_json_bytes(value).map_err(fixture_error)
}

/// Writes the cognition-market qualified profile bundle. Every member is
/// RFC 8785 canonical JSON without a trailing newline, because the evidence
/// graph and passport bind the exact file bytes.
pub(super) fn generate_cognition_market_qualified_profile(out: &Path) -> Result<(), CliError> {
    let profile = verifier_profile()?;
    let profile_envelope_sha256 = signed_envelope_sha256(&profile).map_err(fixture_error)?;
    let recipe = recipe_bytes(&profile_envelope_sha256)?;
    let finding = finding_bytes(&recipe)?;
    let status = status_proof_bytes(&finding_id(&finding)?)?;
    let report = report_bytes(
        &finding,
        &recipe,
        &status,
        &profile.body.profile_id,
        &profile_envelope_sha256,
    )?;
    let purchase_record = purchase_record_bytes(&finding_id(&finding)?)?;
    let claim_set = claim_set_bytes(&finding)?;
    let verifier_policy = verifier_policy_bytes()?;

    let report_id = sha256_hex(&report);
    let purchase_record_id = sha256_hex(&purchase_record);
    let finding_node_id = sha256_hex(&finding);
    let recipe_id = sha256_hex(&recipe);
    let status_id = sha256_hex(&status);
    let claim_set_id = sha256_hex(&claim_set);
    let policy_id = sha256_hex(&verifier_policy);
    let binds = |from: &str, to: &str| {
        json!({
            "from": from,
            "to": to,
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        })
    };
    let graph = json!({
        "schema": "chio.transaction.evidence-graph.v1",
        "id": "evidence-graph-cognition-market-qualified-profile",
        "issued_at": ISSUED_AT,
        "nodes": [
            node(CLAIM_SET_PATH, "claim-set", "chio.transaction.claim-set.v1", &claim_set),
            node(VERIFIER_POLICY_PATH, "verifier-policy", "chio.transaction.verifier-policy.v1", &verifier_policy),
            node(FINDING_PATH, "external-subject", FINDING_SCHEMA_V1, &finding),
            node(REPORT_PATH, "report", FINDING_VERIFIER_REPORT_SCHEMA_V1, &report),
            node(PURCHASE_RECORD_PATH, "commerce-order-context", FINDING_PURCHASE_RECORD_SCHEMA_V1, &purchase_record),
            node(RECIPE_PATH, "advisory-observation", FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, &recipe),
            node(STATUS_PATH, "advisory-observation", FINDING_STATUS_PROOF_INPUT_SCHEMA_V1, &status)
        ],
        "edges": [
            binds(&claim_set_id, &policy_id),
            binds(&claim_set_id, &report_id),
            binds(&claim_set_id, &finding_node_id),
            binds(&report_id, &finding_node_id),
            binds(&claim_set_id, &purchase_record_id),
            binds(&report_id, &purchase_record_id),
            binds(&report_id, &recipe_id),
            binds(&report_id, &status_id)
        ]
    });
    let evidence_graph = canonical(&graph)?;
    let root = keypair(PASSPORT_SIGNER_SEED);
    let mut passport = TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-cognition-market-qualified-profile".to_string(),
        issued_at: ISSUED_AT.to_string(),
        not_before: None,
        expires_at: None,
        issuer: format!("did:chio:{}", root.public_key().to_hex()),
        evidence_graph_sha256: sha256_hex(&evidence_graph),
        evidence_graph_path: EVIDENCE_GRAPH_PATH.to_string(),
        claim_set_sha256: claim_set_id,
        claim_set_path: CLAIM_SET_PATH.to_string(),
        verifier_policy_sha256: policy_id,
        verifier_policy_path: VERIFIER_POLICY_PATH.to_string(),
        omission_policy: Vec::new(),
        signature: String::new(),
    };
    passport.signature = sign_transaction_passport(&passport, &root).map_err(fixture_error)?;

    let members: [(&str, Vec<u8>); 10] = [
        (DEPLOYMENT_PROFILE_PATH, canonical(&profile)?),
        (PASSPORT_PATH, canonical(&passport)?),
        (EVIDENCE_GRAPH_PATH, evidence_graph),
        (CLAIM_SET_PATH, claim_set),
        (VERIFIER_POLICY_PATH, verifier_policy),
        (FINDING_PATH, finding),
        (REPORT_PATH, report),
        (PURCHASE_RECORD_PATH, purchase_record),
        (RECIPE_PATH, recipe),
        (STATUS_PATH, status),
    ];
    for (path, bytes) in members {
        let target = out.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, bytes)?;
    }
    Ok(())
}

fn node(path: &str, role: &str, schema: &str, bytes: &[u8]) -> Value {
    let digest = sha256_hex(bytes);
    json!({
        "id": digest,
        "schema": schema,
        "path": path,
        "sha256": digest,
        "role": role
    })
}

fn finding_id(finding: &[u8]) -> Result<String, CliError> {
    let finding: chio_finding::Finding =
        chio_core::canonical::UntrustedJsonText::from_wire(finding, MAX_FINDING_BYTES)?
            .decode_canonical()?;
    Ok(finding.finding_id)
}

const MAX_FINDING_BYTES: usize = 1_048_576;

/// The verified-fix finding re-bound to the qualified replay recipe digest.
fn finding_bytes(recipe: &[u8]) -> Result<Vec<u8>, CliError> {
    let mut finding = verified_fix_finding_draft();
    finding.replay_recipe_sha256 = Some(sha256_hex(recipe));
    canonical(&sign_verified_fix_finding(finding)?)
}

fn profile_key_policy(seed: u8, authority_id: &str) -> FindingAuthorityKeyPolicy {
    FindingAuthorityKeyPolicy {
        authority_id: authority_id.to_owned(),
        key: keypair(seed).public_key(),
        key_epoch: 1,
        valid_from: GENERATED_AT - 60,
        valid_until: GENERATED_AT + 600,
        rotation_policy_ref: format!("rotation/{authority_id}-v1"),
        revocation_status_ref: format!("revocations/{authority_id}-v1"),
    }
}

fn verifier_profile() -> Result<SignedFindingChallengeVerifierProfile, CliError> {
    let checkpoint_log = profile_key_policy(21, "checkpoint-log");
    let mut profile = FindingChallengeVerifierProfile {
        schema: FINDING_CHALLENGE_VERIFIER_PROFILE_SCHEMA_V1.to_owned(),
        profile_id: String::new(),
        governance_authority: keypair(PROFILE_GOVERNANCE_SEED).public_key(),
        operator: "qualified-market-operator".to_owned(),
        receipt_signers: vec![
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Production,
                policy: profile_key_policy(18, "production-receipts"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Delivery,
                policy: profile_key_policy(19, "delivery-receipts"),
            },
            FindingReceiptSignerRole {
                role: FindingReceiptRole::Replay,
                policy: profile_key_policy(20, "replay-receipts"),
            },
        ],
        checkpoint_logs: vec![FindingCheckpointLogPolicy {
            log_id: finding_checkpoint_log_id(&checkpoint_log.key).map_err(fixture_error)?,
            signer: checkpoint_log,
        }],
        bbs_projection_issuer: FindingBbsIssuerPolicy {
            issuer_fingerprint: "qualified-bbs-issuer".to_owned(),
            key_hex: HEX64.to_owned(),
            registry_ref: "registry/qualified-bbs-issuers".to_owned(),
            key_epoch: 1,
            valid_from: GENERATED_AT - 60,
            valid_until: GENERATED_AT + 600,
            revocation_status_ref: "revocations/qualified-bbs-issuer-v1".to_owned(),
        },
        allowed_runner_manifests: vec!["66".repeat(32)],
        required_receipt_semantics: "chio.mediated_spend.v1".to_owned(),
        resolver_policy_ref: "resolver/qualified-finding-v1".to_owned(),
        retention_policy_ref: "retention/qualified-finding-v1".to_owned(),
        resource_caps: resource_caps(),
        predicate_engine: "chio-replay-v1".to_owned(),
        allowed_predicates: vec![FindingPredicate::BaselineFailsCandidatePassesV1],
        required_facets: Vec::new(),
        verifier_report_signer: FindingAuthorityKeyPolicy {
            authority_id: "qualified-finding-verifier".to_string(),
            key: keypair(VERIFIER_SEED).public_key(),
            key_epoch: 1,
            valid_from: GENERATED_AT - 60,
            valid_until: GENERATED_AT + 600,
            rotation_policy_ref: "rotation/qualified-finding-verifier-v1".to_string(),
            revocation_status_ref: "revocations/qualified-finding-verifier-v1".to_string(),
        },
        purchase_authority: profile_key_policy(PURCHASE_AUTHORITY_SEED, "purchase-authority"),
        failed_delivery_authority: profile_key_policy(23, "failed-delivery-authority"),
        issued_at: GENERATED_AT - 60,
        expires_at: GENERATED_AT + 600,
    };
    profile.profile_id = compute_profile_id(&profile).map_err(fixture_error)?;
    SignedExportEnvelope::sign(profile, &keypair(PROFILE_GOVERNANCE_SEED)).map_err(fixture_error)
}

fn resource_caps() -> FindingResourceCaps {
    FindingResourceCaps {
        max_recipe_bytes: 65_536,
        max_evidence_receipts: 8,
        max_runtime_secs: 600,
        max_memory_bytes: 1_073_741_824,
    }
}

/// Signed non-inclusion proof: the operator map holds only an unrelated
/// retraction, so `finding_id` is provably absent.
fn status_proof_bytes(finding_id: &str) -> Result<Vec<u8>, CliError> {
    let operator = keypair(STATUS_OPERATOR_SEED);
    let mut map = FindingStatusSparseMap::new();
    let root = map
        .insert(RETRACTED_FINDING_ID, RETRACTION_INTENT)
        .map_err(fixture_error)?;
    let sparse = map.proof(finding_id).map_err(fixture_error)?;
    let mut epoch = FindingStatusEpoch {
        schema: FINDING_STATUS_EPOCH_SCHEMA_V1.to_string(),
        status_epoch_id: String::new(),
        status_map_version: FINDING_STATUS_MAP_VERSION.to_string(),
        proof_semantics: FINDING_STATUS_PROOF_SEMANTICS.to_string(),
        feed_id: STATUS_FEED_ID.to_string(),
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        map_epoch: root.map_epoch,
        operator_id: "qualified-status-operator".to_string(),
        operator_key: operator.public_key(),
        operator_key_epoch: 1,
        root_hash: hex::encode(root.root_hash),
        tree_depth: FINDING_STATUS_SPARSE_DEPTH as u16,
        hash_algorithm: FINDING_STATUS_HASH_ALGORITHM.to_string(),
        key_hash_domain: FINDING_STATUS_KEY_HASH_DOMAIN.to_string(),
        empty_leaf_domain: FINDING_STATUS_EMPTY_LEAF_DOMAIN.to_string(),
        occupied_leaf_domain: FINDING_STATUS_OCCUPIED_LEAF_DOMAIN.to_string(),
        branch_domain: FINDING_STATUS_BRANCH_DOMAIN.to_string(),
        empty_leaf_hash: hex::encode(finding_status_empty_leaf_hash()),
        anchor_refs: vec!["anchor/qualified-finding-status/1".to_string()],
        generated_at: GENERATED_AT,
        valid_from: GENERATED_AT - 60,
        valid_until: GENERATED_AT + 600,
    };
    epoch.status_epoch_id = compute_status_epoch_id(&epoch).map_err(fixture_error)?;
    let signed = SignedExportEnvelope::sign(epoch, &operator).map_err(fixture_error)?;
    let proof = build_status_non_inclusion_proof_input(&signed, finding_id, &sparse, CHECKED_AT)
        .map_err(fixture_error)?;
    canonical(&proof)
}

fn recipe_bytes(verifier_profile_envelope_sha256: &str) -> Result<Vec<u8>, CliError> {
    let recipe = FindingReplayRecipeInput {
        schema: FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1.to_string(),
        decision_rule_ref: "decision/baseline-fails-candidate-passes-v1".to_string(),
        verifier_profile_envelope_sha256: verifier_profile_envelope_sha256.to_owned(),
        context_sha256: "aa".repeat(32),
        payload_sha256: "bb".repeat(32),
        runner_server: "qualified-replay-runner".to_string(),
        runner_tool: "replay_patch".to_string(),
        runner_manifest_sha256: "66".repeat(32),
        phases: vec![
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Baseline,
                input_bundle_sha256: "77".repeat(32),
                payload_application: "not_applied".to_string(),
            },
            FindingRecipePhase {
                phase: FindingRecipePhaseKind::Candidate,
                input_bundle_sha256: "88".repeat(32),
                payload_application: "apply_patch_v1".to_string(),
            },
        ],
        parameters_sha256: "99".repeat(32),
        environment: FindingRecipeEnvironment {
            runtime_image_sha256: "22".repeat(32),
            platform: "linux-amd64".to_string(),
            network_policy: "deny_all".to_string(),
            clock_policy: "fixed".to_string(),
            randomness_policy: "seeded".to_string(),
            locale: "C.UTF-8".to_string(),
            timezone: "UTC".to_string(),
        },
        resource_bounds: resource_caps(),
        predicate: FindingPredicate::BaselineFailsCandidatePassesV1,
        pre_run_template_sha256: "aa".repeat(32),
        claimed_verdict: FindingClaimedVerdict::PredicateHolds,
    };
    recipe.validate().map_err(fixture_error)?;
    canonical(&recipe)
}

fn finding_delivery(finding_id: &str) -> FindingDelivery {
    FindingDelivery {
        schema: FINDING_DELIVERY_SCHEMA.to_owned(),
        finding_id: finding_id.to_owned(),
        listing_id: LISTING_ID.to_owned(),
        transform_profile: FindingTransformProfile::Identity,
        digest_check: DeliveryResult::Matched,
        media_type_check: FindingMediaTypeCheck::Matched,
        settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
        accepted_bid_envelope_sha256: "ab".repeat(32),
        venue_admission_envelope_sha256: "cd".repeat(32),
        reservation_id: RESERVATION_ID.to_owned(),
        purchase_intent_id: derive_purchase_intent_id(RESERVATION_ID),
        authoritative_payment_operation_id: derive_payment_operation_id(RESERVATION_ID),
        status_proof: None,
    }
}

fn report_bytes(
    finding: &[u8],
    recipe: &[u8],
    status: &[u8],
    verifier_profile_id: &str,
    verifier_profile_envelope_sha256: &str,
) -> Result<Vec<u8>, CliError> {
    let verifier = keypair(VERIFIER_SEED);
    let finding_id = finding_id(finding)?;
    let facets = FindingFacetKind::ALL
        .into_iter()
        .map(|facet| FindingFacetResult {
            facet,
            outcome: FindingFacetOutcome::Verified,
            reason: "independently verified for the bounded cognition-market profile".to_string(),
            evidence_refs: Vec::new(),
        })
        .collect();
    let mut report = FindingVerifierReport {
        schema: FINDING_VERIFIER_REPORT_SCHEMA_V1.to_string(),
        report_id: String::new(),
        finding_id: finding_id.clone(),
        finding_artifact_sha256: sha256_hex(finding),
        verifier_profile_id: verifier_profile_id.to_owned(),
        verifier_profile_envelope_sha256: verifier_profile_envelope_sha256.to_owned(),
        verifier_implementation_id: "chio-finding-verifier/0.1-qualified".to_string(),
        resolved_evidence_bundle_sha256: "34".repeat(32),
        replay_recipe_input_sha256: Some(sha256_hex(recipe)),
        status_proof_input_sha256: Some(sha256_hex(status)),
        finding_delivery_receipt_id: Some("89".repeat(32)),
        finding_delivery: Some(finding_delivery(&finding_id)),
        trust_root_snapshot_sha256: "45".repeat(32),
        resolver_policy_sha256: "56".repeat(32),
        trusted_time_input_sha256: "67".repeat(32),
        facets,
        backing_allocation_id: Some("78".repeat(32)),
        verifier_authority: verifier.public_key(),
        verifier_key_epoch: 1,
        evaluation_time: CHECKED_AT,
    };
    report.report_id = compute_report_id(&report).map_err(fixture_error)?;
    report.validate().map_err(fixture_error)?;
    canonical(&SignedExportEnvelope::sign(report, &verifier).map_err(fixture_error)?)
}

fn purchase_record_bytes(finding_id: &str) -> Result<Vec<u8>, CliError> {
    let delivery = finding_delivery(finding_id);
    let usd = |units| MonetaryAmount {
        units,
        currency: "USD".to_owned(),
    };
    let purchase = FindingPurchaseRecord {
        schema: FINDING_PURCHASE_RECORD_SCHEMA_V1.to_owned(),
        purchase_key: derive_purchase_key(
            &delivery.accepted_bid_envelope_sha256,
            &delivery.authoritative_payment_operation_id,
        ),
        purchase_intent_id: delivery.purchase_intent_id.clone(),
        authoritative_payment_operation_id: delivery.authoritative_payment_operation_id.clone(),
        buyer: keypair(BUYER_SEED).public_key(),
        payer: keypair(PAYER_SEED).public_key(),
        finding_id: delivery.finding_id.clone(),
        listing_id: delivery.listing_id.clone(),
        accepted_bid_envelope_sha256: delivery.accepted_bid_envelope_sha256.clone(),
        venue_admission_envelope_sha256: delivery.venue_admission_envelope_sha256.clone(),
        accepted_price: usd(50),
        realized_spend: usd(50),
        seller_backing_envelope_sha256: "ef".repeat(32),
        encumbrance_id: "encumbrance-qualified-transaction".to_owned(),
        delivery_receipt_id: "89".repeat(32),
        payment_reference: delivery.authoritative_payment_operation_id.clone(),
        payout_destination: "0x1111111111111111111111111111111111111111".to_owned(),
        recorded_at: CHECKED_AT,
    };
    purchase.validate().map_err(fixture_error)?;
    canonical(
        &SignedExportEnvelope::sign(purchase, &keypair(PURCHASE_AUTHORITY_SEED))
            .map_err(fixture_error)?,
    )
}

fn claim_set_bytes(finding: &[u8]) -> Result<Vec<u8>, CliError> {
    let paths = [
        vec![REPORT_PATH, PURCHASE_RECORD_PATH],
        vec![REPORT_PATH, RECIPE_PATH],
        vec![REPORT_PATH, STATUS_PATH],
        vec![REPORT_PATH],
    ];
    let claims = COGNITION_MARKET_CLAIMS
        .iter()
        .zip(paths)
        .map(|(claim_id, evidence)| {
            json!({
                "claim_id": claim_id,
                "status": "verified",
                "required_evidence": evidence,
                "evidence_refs": evidence,
                "verifier_module": "chio-finding-verifier"
            })
        })
        .collect::<Vec<_>>();
    canonical(&json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": "claim-set-cognition-market-qualified-profile",
        "issued_at": ISSUED_AT,
        "subject": {
            "kind": "finding",
            "id": finding_id(finding)?,
            "artifact_sha256": sha256_hex(finding)
        },
        "claims": claims
    }))
}

fn verifier_policy_bytes() -> Result<Vec<u8>, CliError> {
    canonical(&json!({
        "schema": "chio.transaction.verifier-policy.v1",
        "id": "verifier-policy-cognition-market-qualified-profile",
        "issued_at": ISSUED_AT,
        "required_claims": COGNITION_MARKET_CLAIMS,
        "omitted_claims": [],
        "required_evidence_roles": ["report", "commerce-order-context", "advisory-observation"]
    }))
}
