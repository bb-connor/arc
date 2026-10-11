use super::*;
use std::fs;
use std::sync::Arc;

use chio_core::crypto::Keypair;
use chio_kernel::finding_purchase::{FindingStatusProofContextView, FindingStatusProofVerifier};
use chio_store_sqlite::SqliteAuthorityStore;
use chio_test_support::prelude::*;
use chio_transaction_passport::{
    CognitionMarketStatusObservation, CognitionMarketStatusTrustStore,
};

const FEED_ID: &str = "status-feed/test";
const NOW: u64 = 1_800_000_000;

fn operator_key() -> Keypair {
    Keypair::from_seed(&[81; 32])
}

fn authority_pin(seed: u8, authority_id: &str, now: u64) -> FindingAuthorityPin {
    FindingAuthorityPin {
        authority_id: authority_id.to_string(),
        key_hex: Keypair::from_seed(&[seed; 32]).public_key().to_hex(),
        key_epoch: 1,
        valid_from: now.saturating_sub(100),
        valid_until: now.saturating_add(10_000),
        revocation_status_ref: format!("revocations/{authority_id}"),
    }
}

fn config() -> (FindingStatusOperatorPin, FindingStatusServiceBond) {
    let operator = FindingStatusOperatorPin {
        feed_id: FEED_ID.to_string(),
        role: FINDING_STATUS_OPERATOR_ROLE.to_string(),
        authority: FindingAuthorityPin {
            authority_id: "status-operator".to_string(),
            key_hex: operator_key().public_key().to_hex(),
            key_epoch: 4,
            valid_from: NOW - 100,
            valid_until: NOW + 10_000,
            revocation_status_ref: "revocations/status".to_string(),
        },
        rotation_policy_ref: "rotation/status-v1".to_string(),
        authorization_sha256: sha256_hex(b"status-authorization"),
        revoked_from: None,
    };
    let bond = FindingStatusServiceBond {
        bond_id: "status-bond".to_string(),
        feed_id: FEED_ID.to_string(),
        operator_id: "status-operator".to_string(),
        locked_units: 1_000,
        currency: "USD".to_string(),
        valid_from: NOW - 100,
        valid_until: NOW + 10_000,
        inclusion_sla_secs: 600,
        missed_inclusion_slash_units: 100,
        equivocation_slash_units: 1_000,
        evidence_sha256: sha256_hex(b"bond"),
    };
    (operator, bond)
}

fn submission() -> FindingStatusIntentSubmission {
    let (operator, bond) = config();
    let seller = Keypair::from_seed(&[83; 32]);
    let source_authority_id = seller.public_key().to_hex();
    let finding_id = sha256_hex(b"finding");
    let source_receipt = SignedExportEnvelope::sign(
        FindingVoluntaryRetractionReceipt {
            schema: FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA.to_string(),
            feed_id: FEED_ID.to_string(),
            key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
            finding_id: finding_id.clone(),
            source_authority_id: source_authority_id.clone(),
            issued_at: NOW,
        },
        &seller,
    )
    .test_expect("seller-signed retraction receipt");
    let source_receipt_sha256 =
        chio_finding::signed_envelope_sha256(&source_receipt).test_expect("source receipt digest");
    let mut body = FindingStatusIntentSubmission {
        schema: FINDING_STATUS_INTENT_SCHEMA.to_string(),
        intent_id: String::new(),
        feed_id: FEED_ID.to_string(),
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        finding_id,
        source: FindingStatusIntentSource::Voluntary,
        source_authority_id,
        source_receipt_sha256,
        source_receipt,
        operator_id: operator.authority.authority_id,
        operator_key_epoch: operator.authority.key_epoch,
        issued_at: NOW,
        inclusion_deadline: NOW + bond.inclusion_sla_secs,
    };
    body.intent_id = compute_intent_id(&body).test_expect("canonical status intent id");
    body
}

fn live_market_config(now: u64) -> FindingMarketConfig {
    let status_operator = FindingStatusOperatorPin {
        feed_id: FEED_ID.to_string(),
        role: FINDING_STATUS_OPERATOR_ROLE.to_string(),
        authority: FindingAuthorityPin {
            authority_id: "status-operator".to_string(),
            key_hex: operator_key().public_key().to_hex(),
            key_epoch: 4,
            valid_from: now.saturating_sub(100),
            valid_until: now.saturating_add(10_000),
            revocation_status_ref: "revocations/status".to_string(),
        },
        rotation_policy_ref: "rotation/status-v1".to_string(),
        authorization_sha256: sha256_hex(b"status-authorization"),
        revoked_from: None,
    };
    FindingMarketConfig {
        venue_id: "status-test-venue".to_string(),
        venue: authority_pin(1, "venue", now),
        listing: authority_pin(12, "listing", now),
        governance_root: authority_pin(2, "governance", now),
        authority_status: authority_pin(13, "authority-status", now),
        verifier_report: authority_pin(3, "verifier", now),
        collateral: authority_pin(4, "collateral", now),
        purchase: authority_pin(5, "purchase", now),
        failed_delivery: authority_pin(6, "failed-delivery", now),
        challenge_evaluator: authority_pin(7, "challenge-evaluator", now),
        venue_finalization: authority_pin(8, "venue-finalization", now),
        market_penalty: authority_pin(9, "market-penalty", now),
        settlement_observer: authority_pin(10, "settlement-observer", now),
        anchor_publisher: authority_pin(15, "anchor-publisher", now),
        max_snapshot_age_secs: 3_600,
        settlement_finality_requirement: chio_settle::FindingFinalityRequirement::Confirmations {
            min_depth: 64,
        },
        audit_authority: authority_pin(11, "audit-authority", now),
        audit_randomness_witness: authority_pin(14, "audit-randomness-witness", now),
        audit_pool: FindingPoolPin {
            principal_id: "pool:audit".to_string(),
            rail_destination: "rail:test:audit".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        challenge_administration_pool: FindingPoolPin {
            principal_id: "pool:challenge".to_string(),
            rail_destination: "rail:test:challenge".to_string(),
            currency: "USD".to_string(),
            authority_epoch: 1,
        },
        community_fund_destination: "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
        status_feed_operator_ref: FEED_ID.to_string(),
        status_feed_operator: status_operator,
        status_feed_service_bond: FindingStatusServiceBond {
            bond_id: "status-bond".to_string(),
            feed_id: FEED_ID.to_string(),
            operator_id: "status-operator".to_string(),
            locked_units: 1_000,
            currency: "USD".to_string(),
            valid_from: now.saturating_sub(100),
            valid_until: now.saturating_add(10_000),
            inclusion_sla_secs: 600,
            missed_inclusion_slash_units: 100,
            equivocation_slash_units: 1_000,
            evidence_sha256: sha256_hex(b"status-bond"),
        },
        status_max_epoch_age_secs: 300,
        fee_schedule_operator_keys: vec![Keypair::from_seed(&[90; 32]).public_key().to_hex()],
    }
}

fn provision_authority(
) -> Result<(tempfile::TempDir, Arc<SqliteAuthorityStore>), Box<dyn std::error::Error>> {
    let temp = chio_test_support::private_tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    }
    let database = temp.path().join("authority.sqlite3");
    let lock_root = temp.path().join("locks");
    fs::create_dir(&lock_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700))?;
    }
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = Arc::new(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
    Ok((temp, authority))
}

#[test]
fn status_intent_id_binds_the_fixed_domain_and_source_receipt() {
    let body = submission();
    let id = compute_intent_id(&body).test_expect("status intent id");
    let mut substituted = body;
    substituted.source_receipt_sha256 = sha256_hex(b"other-source-receipt");
    let other = compute_intent_id(&substituted).test_expect("substituted intent id");
    assert_ne!(id, other);
}

#[test]
fn strict_ingress_rejects_noncanonical_signed_bytes() {
    let signed = SignedExportEnvelope::sign(submission(), &operator_key())
        .test_expect("signed status intent");
    let pretty = serde_json::to_string_pretty(&signed).test_expect("pretty status intent");
    assert!(strict_intent_ingress(&pretty).is_err());

    let canonical = canonical_json_bytes(&signed).test_expect("canonical status intent");
    let raw = String::from_utf8(canonical).test_expect("UTF-8 status intent");
    assert!(strict_intent_ingress(&raw).is_ok());
}

#[test]
fn intent_validation_rejects_unsigned_and_operator_substitution() {
    let (operator, bond) = config();
    let mut signed = SignedExportEnvelope::sign(submission(), &operator_key())
        .test_expect("signed status intent");
    signed.body.source_authority_id = "substituted-seller".to_string();
    signed.body.intent_id =
        compute_intent_id(&signed.body).test_expect("substituted status intent id");
    let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
        .test_expect_err("mutated unsigned body must reject");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let substitute = Keypair::from_seed(&[82; 32]);
    let signed = SignedExportEnvelope::sign(submission(), &substitute)
        .test_expect("substitute-signed status intent");
    let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
        .test_expect_err("operator substitution must reject");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn intent_validation_rejects_a_countersigned_forged_source_receipt() {
    let (operator, bond) = config();
    let mut body = submission();
    body.source_receipt.signature = Keypair::from_seed(&[84; 32]).sign(b"forged source");
    body.source_receipt_sha256 = chio_finding::signed_envelope_sha256(&body.source_receipt)
        .test_expect("forged source receipt digest");
    body.intent_id = compute_intent_id(&body).test_expect("forged status intent id");
    let signed = SignedExportEnvelope::sign(body, &operator_key())
        .test_expect("operator-countersigned forged source receipt");

    let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
        .test_expect_err("operator countersignature cannot replace source authentication");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn intent_validation_rejects_stale_intent_and_expired_bond() {
    let (operator, mut bond) = config();
    let mut stale = submission();
    stale.issued_at = NOW - bond.inclusion_sla_secs;
    stale.inclusion_deadline = NOW;
    stale.intent_id = compute_intent_id(&stale).test_expect("stale status intent id");
    let stale = SignedExportEnvelope::sign(stale, &operator_key())
        .test_expect("stale signed status intent");
    let response = validate_intent_submission(&stale, &operator, &bond, FEED_ID, NOW)
        .test_expect_err("stale status intent must reject");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    bond.valid_until = NOW;
    let signed = SignedExportEnvelope::sign(submission(), &operator_key())
        .test_expect("signed status intent");
    let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
        .test_expect_err("expired status bond must reject");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let (mut operator, mut bond) = config();
    operator.authority.valid_until = NOW + bond.inclusion_sla_secs;
    bond.valid_until = NOW + bond.inclusion_sla_secs;
    let signed = SignedExportEnvelope::sign(submission(), &operator_key())
        .test_expect("signed status intent at expiring SLA boundary");
    let response = validate_intent_submission(&signed, &operator, &bond, FEED_ID, NOW)
        .test_expect_err("operator and bond must cover the full inclusion SLA");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[test]
fn new_intent_refreshes_liveness_at_persistence() {
    let (operator, bond) = config();
    let signed = SignedExportEnvelope::sign(submission(), &operator_key())
        .test_expect("signed status intent");
    let response = intent_persistence_time(&signed, &operator, &bond, FEED_ID, || {
        Ok(signed.body.inclusion_deadline)
    })
    .test_expect_err("intent expiring during validation must not be persisted");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn retained_exact_replay_recovers_without_current_liveness() {
    let (_temp, authority) = provision_authority().test_expect("durable authority store");
    let store = authority.finding_status_store();
    let signed = SignedExportEnvelope::sign(submission(), &operator_key())
        .test_expect("signed status intent");
    let raw = canonical_json_bytes(&signed).test_expect("canonical signed intent");
    store
        .issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &signed.body.intent_id,
            feed_id: &signed.body.feed_id,
            operator_id: &signed.body.operator_id,
            finding_id: &signed.body.finding_id,
            source: FindingRetractionIntentSource::Voluntary,
            intent_bytes: &raw,
            issued_at: signed.body.issued_at,
            inclusion_deadline: signed.body.inclusion_deadline,
            created_at: signed.body.issued_at,
        })
        .test_expect("persist exact status intent");

    let response = recover_exact_intent_replay(&store, &signed.body.intent_id, &raw)
        .test_expect("read retained intent")
        .test_expect("exact replay returns its retained decision");
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn retained_finding_rejects_a_self_authorized_voluntary_source(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let raw = include_str!(
        "../../../../../../fixtures/proof-room/finding/verified-fix-basic/finding.json"
    );
    let finding: chio_finding::Finding = serde_json::from_str(raw)?;
    chio_finding::verify_finding(&finding)?;
    authority.finding_market_store().put_finding(
        &chio_store_sqlite::FindingRecordInput {
            finding_id: &finding.finding_id,
            artifact_json: raw,
            topic: &finding.descriptor.topic,
            context_sha256: &finding.descriptor.context_sha256,
            issued_at: finding.issued_at,
            expires_at: finding.expires_at,
        },
        NOW,
    )?;

    let seller = Keypair::from_seed(&[83; 32]);
    let mut body = submission();
    body.finding_id.clone_from(&finding.finding_id);
    body.feed_id.clone_from(&finding.status_feed_ref);
    body.source_receipt = SignedExportEnvelope::sign(
        FindingVoluntaryRetractionReceipt {
            schema: FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA.to_string(),
            feed_id: body.feed_id.clone(),
            key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
            finding_id: body.finding_id.clone(),
            source_authority_id: seller.public_key().to_hex(),
            issued_at: NOW,
        },
        &seller,
    )?;
    body.source_authority_id = seller.public_key().to_hex();
    body.source_receipt_sha256 = chio_finding::signed_envelope_sha256(&body.source_receipt)?;
    body.intent_id = compute_intent_id(&body).test_expect("self-authorized intent id");
    let signed = SignedExportEnvelope::sign(body, &operator_key())?;
    let state = service_state(authority, live_market_config(NOW));

    let response = require_authorized_voluntary_source(&state, &signed)
        .test_expect_err("an arbitrary source key must not authorize its own retraction");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[test]
fn verifier_and_publisher_reject_malformed_service_bond() -> Result<(), Box<dyn std::error::Error>>
{
    let (operator, mut bond) = config();
    let (_temp, authority) = provision_authority()?;
    bond.locked_units = 0;

    assert!(
        super::super::finding_status_verifier::MarketFindingStatusVerifier::new(
            operator.clone(),
            bond.clone(),
            300,
            authority.finding_status_store(),
        )
        .is_err()
    );
    assert!(
        super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            authority.finding_status_store(),
            operator,
            bond,
            operator_key(),
            300,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn imported_point_proof_cannot_advance_the_publisher_floor(
) -> Result<(), Box<dyn std::error::Error>> {
    let (operator, bond) = config();
    let (_local_temp, local_authority) = provision_authority()?;
    let local_store = local_authority.finding_status_store();
    let local_publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        local_store.clone(),
        operator.clone(),
        bond.clone(),
        operator_key(),
        300,
    )?;
    let finding_id = sha256_hex(b"local-live-finding");
    let local = local_publisher.publish_non_inclusion(&finding_id, &[], NOW)?;
    assert_eq!(local.map_epoch, 1);

    let (_remote_temp, remote_authority) = provision_authority()?;
    let remote_store = remote_authority.finding_status_store();
    let remote_publisher =
        super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            remote_store.clone(),
            operator.clone(),
            bond.clone(),
            operator_key(),
            300,
        )?;
    remote_publisher.publish_non_inclusion(&finding_id, &[], NOW)?;
    let retracted_id = sha256_hex(b"remote-retracted-finding");
    let intent_id = sha256_hex(b"remote-retraction-intent");
    let intent_bytes = canonical_json_bytes(&serde_json::json!({
        "finding_id": retracted_id,
        "schema": "chio.finding.test-retraction.v1",
    }))?;
    remote_store.issue_retraction_intent(&FindingRetractionIntentInput {
        intent_id: &intent_id,
        feed_id: FEED_ID,
        operator_id: &operator.authority.authority_id,
        finding_id: &retracted_id,
        source: FindingRetractionIntentSource::Voluntary,
        intent_bytes: &intent_bytes,
        issued_at: NOW,
        inclusion_deadline: NOW + bond.inclusion_sla_secs,
        created_at: NOW,
    })?;
    let retracted = remote_publisher.publish_retraction(&intent_id, &[], NOW + 1)?;
    let retracted_epoch = chio_finding::parse_signed_status_epoch(&retracted.signed_epoch_bytes)?;
    let retracted_proof = chio_finding::parse_status_proof_input(&retracted.proof_bytes)?;
    let retracted_error = remote_store
        .admit_verified_status(&CognitionMarketStatusObservation {
            signed_epoch: &retracted_epoch,
            signed_epoch_bytes: &retracted.signed_epoch_bytes,
            proof: &retracted_proof,
            proof_bytes: &retracted.proof_bytes,
            operator_authorization_sha256: &operator.authorization_sha256,
            max_epoch_age_secs: 300,
            recorded_at: NOW + 1,
        })
        .test_expect_err("an imported inclusion must preserve the raw v1 leaf encoding");
    assert_eq!(retracted_error, "finding is retracted");
    assert_eq!(
        remote_store
            .get_leaf(FEED_ID, &retracted_id)?
            .ok_or_else(|| std::io::Error::other("retracted leaf"))?
            .status_value_bytes,
        b"retracted"
    );
    let imported = remote_publisher.publish_non_inclusion(&finding_id, &[], NOW + 1)?;
    assert_eq!(imported.map_epoch, 2);

    let imported_epoch = chio_finding::parse_signed_status_epoch(&imported.signed_epoch_bytes)?;
    let imported_proof = chio_finding::parse_status_proof_input(&imported.proof_bytes)?;
    let import_error = local_store
        .admit_verified_status(&CognitionMarketStatusObservation {
            signed_epoch: &imported_epoch,
            signed_epoch_bytes: &imported.signed_epoch_bytes,
            proof: &imported_proof,
            proof_bytes: &imported.proof_bytes,
            operator_authorization_sha256: &operator.authorization_sha256,
            max_epoch_age_secs: 300,
            recorded_at: NOW + 1,
        })
        .test_expect_err("one imported point proof must not advance the durable feed floor");
    assert!(import_error.contains("exact durable feed floor"));
    assert_eq!(local_store.get_feed_floor(FEED_ID)?.map_epoch, 1);

    let verifier = super::super::finding_status_verifier::MarketFindingStatusVerifier::new(
        operator,
        bond,
        300,
        local_store.clone(),
    )?;
    let imported_b64 = STANDARD.encode(&imported.proof_bytes);
    let view = FindingStatusProofContextView {
        proof_b64: &imported_b64,
        expected_finding_id: &finding_id,
        expected_feed_id: FEED_ID,
    };
    let verified = verifier.verify_status_proof(&view)?;
    let error = verifier
        .verify_status_admission(&view, &verified, NOW + 1)
        .test_expect_err("an imported future point proof must not advance publisher state");
    assert!(error.detail().contains("authoritative publisher floor"));
    assert_eq!(local_store.get_feed_floor(FEED_ID)?.map_epoch, 1);
    assert_eq!(
        local_publisher
            .publish_non_inclusion(&sha256_hex(b"another-local-live-finding"), &[], NOW + 1)?
            .map_epoch,
        1
    );
    Ok(())
}

#[test]
fn portable_proof_is_bound_to_the_authenticated_finding_feed(
) -> Result<(), Box<dyn std::error::Error>> {
    let (operator, bond) = config();
    let (_temp, authority) = provision_authority()?;
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        operator.clone(),
        bond.clone(),
        operator_key(),
        300,
    )?;
    let finding_id = sha256_hex(b"feed-bound-finding");
    let published = publisher.publish_non_inclusion(&finding_id, &[], NOW)?;
    let verifier = super::super::finding_status_verifier::MarketFindingStatusVerifier::new(
        operator, bond, 300, store,
    )?;
    let proof_b64 = STANDARD.encode(&published.proof_bytes);
    let error = verifier
        .verify_status_proof(&FindingStatusProofContextView {
            proof_b64: &proof_b64,
            expected_finding_id: &finding_id,
            expected_feed_id: "status-feed/other",
        })
        .test_expect_err("a proof from another feed must not establish live status");
    assert_eq!(
        error.detail(),
        "finding status proof binds a different feed"
    );
    Ok(())
}

#[test]
fn portable_proof_survives_a_valid_replacement_bond_window(
) -> Result<(), Box<dyn std::error::Error>> {
    struct FixedAdmissionClock(u64);

    impl chio_security_types::clock::Clock for FixedAdmissionClock {
        fn read(
            &self,
        ) -> core::result::Result<
            chio_security_types::clock::ClockReading,
            chio_security_types::clock::ClockError,
        > {
            let value = self.0;
            chio_security_types::clock::Clock::read(&chio_security_types::clock::FixedClock::new(
                value,
            ))
        }
    }

    let (operator, bond) = config();
    let (_temp, authority) = provision_authority()?;
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        operator.clone(),
        bond.clone(),
        operator_key(),
        300,
    )?;
    let finding_id = sha256_hex(b"replacement-bond-finding");
    let published = publisher.publish_non_inclusion(&finding_id, &[], NOW)?;
    let mut replacement_bond = bond;
    replacement_bond.valid_from = NOW + 1;
    replacement_bond.evidence_sha256 = sha256_hex(b"replacement-status-bond");
    let verifier =
        super::super::finding_status_verifier::MarketFindingStatusVerifier::new_with_clock(
            operator,
            replacement_bond,
            300,
            store,
            Arc::new(FixedAdmissionClock(NOW + 1)),
        )?;
    let proof_b64 = STANDARD.encode(&published.proof_bytes);
    let view = FindingStatusProofContextView {
        proof_b64: &proof_b64,
        expected_finding_id: &finding_id,
        expected_feed_id: FEED_ID,
    };

    let verified = verifier.verify_status_proof(&view)?;
    verifier.verify_status_admission(&view, &verified, NOW + 1)?;
    Ok(())
}

#[test]
fn root_projection_rejects_stale_or_substituted_epoch_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let (operator, bond) = config();
    let (_temp, authority) = provision_authority()?;
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        operator.clone(),
        bond.clone(),
        operator_key(),
        300,
    )?;
    publisher.publish_non_inclusion(&sha256_hex(b"root-test-finding"), &[], NOW)?;
    let mut epoch = store.get_current_epoch(FEED_ID)?;
    require_current_epoch(&operator, &bond, 300, &epoch, NOW)
        .test_expect("authorized current epoch");

    epoch.operator_key = Keypair::from_seed(&[83; 32]).public_key().to_hex();
    let response = require_current_epoch(&operator, &bond, 300, &epoch, NOW)
        .test_expect_err("substitute epoch operator must reject");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    epoch.operator_key = operator.authority.key_hex.clone();
    epoch.valid_until = NOW;
    let response = require_current_epoch(&operator, &bond, 300, &epoch, NOW)
        .test_expect_err("stale epoch must reject");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[tokio::test]
async fn root_and_proof_handlers_return_the_exact_verified_bytes(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let now = unix_timestamp_now().unwrap_or_else(|error| panic!("trusted fixture clock: {error}"));
    let market = live_market_config(now);
    market.validate()?;
    let store = authority.finding_status_store();
    let finding_id = sha256_hex(b"proof-finding");
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store,
        market.status_feed_operator.clone(),
        market.status_feed_service_bond.clone(),
        operator_key(),
        market.status_max_epoch_age_secs,
    )?;
    let published = publisher.publish_non_inclusion(&finding_id, &[], now)?;
    let epoch_bytes = published.signed_epoch_bytes.clone();
    let proof_bytes = published.proof_bytes.clone();
    let state = service_state(authority, market);

    let root =
        handle_get_finding_status_root(State(state.clone()), AxumPath(FEED_ID.to_string())).await;
    assert_eq!(root.status(), StatusCode::OK);
    let root_body = axum::body::to_bytes(root.into_body(), usize::MAX).await?;
    let root_json: serde_json::Value = serde_json::from_slice(&root_body)?;
    assert_eq!(
        root_json["signed_epoch_b64"],
        serde_json::Value::String(STANDARD.encode(&epoch_bytes))
    );

    let proof =
        handle_get_finding_status_proof(State(state), AxumPath((FEED_ID.to_string(), finding_id)))
            .await;
    assert_eq!(proof.status(), StatusCode::OK);
    let proof_body = axum::body::to_bytes(proof.into_body(), usize::MAX).await?;
    let proof_json: serde_json::Value = serde_json::from_slice(&proof_body)?;
    assert_eq!(
        proof_json["signed_epoch_b64"],
        serde_json::Value::String(STANDARD.encode(&epoch_bytes))
    );
    assert_eq!(
        proof_json["proof_input_b64"],
        serde_json::Value::String(STANDARD.encode(&proof_bytes))
    );
    Ok(())
}

#[test]
fn status_routes_reject_a_clock_below_the_durable_feed_floor(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let market = live_market_config(NOW);
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        market.status_feed_operator,
        market.status_feed_service_bond,
        operator_key(),
        market.status_max_epoch_age_secs,
    )?;
    publisher.publish_non_inclusion(&sha256_hex(b"clock-fenced-route"), &[], NOW)?;
    store.observe_trusted_time(FEED_ID, NOW + 100)?;

    let response = observe_status_route_time(&store, FEED_ID, || Ok(NOW + 50))
        .test_expect_err("route time below the durable floor must reject");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    Ok(())
}

#[test]
fn changed_anchor_references_advance_an_unchanged_status_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let (operator, bond) = config();
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        operator,
        bond,
        operator_key(),
        300,
    )?;
    let first = publisher.publish_non_inclusion(&sha256_hex(b"first"), &[], NOW)?;
    let anchors = vec!["anchor/status-feed/1".to_string()];
    let second = publisher.publish_non_inclusion(&sha256_hex(b"second"), &anchors, NOW + 1)?;
    assert_eq!(second.map_epoch, first.map_epoch + 1);
    let current = store.get_current_epoch(FEED_ID)?;
    let signed = chio_finding::parse_signed_status_epoch(&current.signed_epoch_bytes)?;
    assert_eq!(signed.body.anchor_refs, anchors);
    Ok(())
}

#[test]
fn reordered_or_duplicate_anchor_references_reuse_the_current_status_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let (operator, bond) = config();
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        operator,
        bond,
        operator_key(),
        300,
    )?;
    let first_anchors = vec![
        "anchor/status-feed/2".to_string(),
        "anchor/status-feed/1".to_string(),
        "anchor/status-feed/2".to_string(),
    ];
    let first = publisher.publish_non_inclusion(
        &sha256_hex(b"first-canonical-anchor-finding"),
        &first_anchors,
        NOW,
    )?;
    let reordered = vec![
        "anchor/status-feed/1".to_string(),
        "anchor/status-feed/2".to_string(),
    ];
    let second = publisher.publish_non_inclusion(
        &sha256_hex(b"second-canonical-anchor-finding"),
        &reordered,
        NOW + 1,
    )?;
    assert_eq!(second.map_epoch, first.map_epoch);
    let current = store.get_current_epoch(FEED_ID)?;
    let signed = chio_finding::parse_signed_status_epoch(&current.signed_epoch_bytes)?;
    assert_eq!(signed.body.anchor_refs, reordered);
    Ok(())
}

#[test]
fn changed_operator_authorization_advances_an_unchanged_status_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let (operator, bond) = config();
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        operator.clone(),
        bond.clone(),
        operator_key(),
        300,
    )?;
    let first = publisher.publish_non_inclusion(&sha256_hex(b"first"), &[], NOW)?;

    let mut refreshed_operator = operator;
    let rotated_key = Keypair::from_seed(&[82; 32]);
    refreshed_operator.authority.key_hex = rotated_key.public_key().to_hex();
    refreshed_operator.authority.key_epoch += 1;
    refreshed_operator.revoked_from = Some(NOW + 1_000);
    refreshed_operator.authorization_sha256 = sha256_hex(b"refreshed-status-authorization");
    let refreshed = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        refreshed_operator.clone(),
        bond,
        rotated_key,
        300,
    )?;
    let second = refreshed.publish_non_inclusion(&sha256_hex(b"second"), &[], NOW + 1)?;

    assert_eq!(second.map_epoch, first.map_epoch + 1);
    assert_eq!(
        store
            .get_current_epoch(FEED_ID)?
            .operator_authorization_sha256,
        refreshed_operator.authorization_sha256
    );
    Ok(())
}

#[test]
fn publisher_rejects_epoch_reuse_after_operator_revocation(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let (operator, bond) = config();
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        operator.clone(),
        bond.clone(),
        operator_key(),
        1_000,
    )?;
    let finding_id = sha256_hex(b"pre-revocation-finding");
    publisher.publish_non_inclusion(&finding_id, &[], NOW)?;

    let mut revoked_operator = operator;
    revoked_operator.revoked_from = Some(NOW + 700);
    let revoked_publisher =
        super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store,
            revoked_operator,
            bond,
            operator_key(),
            1_000,
        )?;
    let error = revoked_publisher
        .publish_non_inclusion(&finding_id, &[], NOW + 701)
        .test_expect_err("revoked operator must not reuse a prior signed epoch");
    assert!(
        error.contains("outside its validity window"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn publisher_rejects_epoch_reuse_after_service_bond_expiry(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let (operator, bond) = config();
    let store = authority.finding_status_store();
    let publisher = super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
        store.clone(),
        operator.clone(),
        bond,
        operator_key(),
        1_000,
    )?;
    publisher.publish_non_inclusion(&sha256_hex(b"bonded-finding"), &[], NOW)?;

    let mut replacement_operator = operator;
    replacement_operator.authority.valid_from = NOW - 2_000;
    let mut expired_bond = config().1;
    expired_bond.valid_from = NOW - 1_000;
    expired_bond.valid_until = NOW - 200;
    let expired_publisher =
        super::super::finding_status_publisher::FindingStatusEpochPublisher::new(
            store,
            replacement_operator,
            expired_bond,
            operator_key(),
            1_000,
        )?;
    let error = expired_publisher
        .publish_non_inclusion(&sha256_hex(b"another-bonded-finding"), &[], NOW + 1)
        .test_expect_err("expired service bond must not reuse a prior signed epoch");
    assert_eq!(error, "finding status publisher service bond is expired");
    Ok(())
}

#[tokio::test]
async fn status_handlers_fail_closed_without_live_bond_or_authentication(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let now = unix_timestamp_now().unwrap_or_else(|error| panic!("trusted fixture clock: {error}"));
    let mut market = live_market_config(now);
    market.status_feed_service_bond.valid_until = now;
    let state = service_state(Arc::clone(&authority), market);
    let response =
        handle_get_finding_status_root(State(state), AxumPath(FEED_ID.to_string())).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let market = live_market_config(now);
    let state = service_state(authority, market);
    let signed = SignedExportEnvelope::sign(submission(), &operator_key())?;
    let raw = String::from_utf8(canonical_json_bytes(&signed)?)?;
    let response = handle_submit_finding_status_intent(
        State(state),
        AxumPath(FEED_ID.to_string()),
        HeaderMap::new(),
        raw,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn exact_status_intent_replay_recovers_after_deadline_but_new_stale_intent_rejects(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, authority) = provision_authority()?;
    let now = unix_timestamp_now().unwrap_or_else(|error| panic!("trusted fixture clock: {error}"));
    let market = live_market_config(now);
    let seller = Keypair::from_seed(&[83; 32]);
    let issued_at = now.saturating_sub(
        market
            .status_feed_service_bond
            .inclusion_sla_secs
            .saturating_add(1),
    );
    let mut body = submission();
    body.issued_at = issued_at;
    body.inclusion_deadline = issued_at
        .checked_add(market.status_feed_service_bond.inclusion_sla_secs)
        .ok_or("test status deadline overflowed")?;
    body.source_receipt = SignedExportEnvelope::sign(
        FindingVoluntaryRetractionReceipt {
            schema: FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA.to_string(),
            feed_id: body.feed_id.clone(),
            key_domain_nonce: body.key_domain_nonce,
            finding_id: body.finding_id.clone(),
            source_authority_id: seller.public_key().to_hex(),
            issued_at,
        },
        &seller,
    )?;
    body.source_authority_id = seller.public_key().to_hex();
    body.source_receipt_sha256 = chio_finding::signed_envelope_sha256(&body.source_receipt)?;
    body.intent_id = compute_intent_id(&body).test_expect("expired status intent id");
    let signed = SignedExportEnvelope::sign(body, &operator_key())?;
    let raw = String::from_utf8(canonical_json_bytes(&signed)?)?;
    let store = authority.finding_status_store();
    assert_eq!(
        store.issue_retraction_intent(&FindingRetractionIntentInput {
            intent_id: &signed.body.intent_id,
            feed_id: &signed.body.feed_id,
            operator_id: &signed.body.operator_id,
            finding_id: &signed.body.finding_id,
            source: FindingRetractionIntentSource::Voluntary,
            intent_bytes: raw.as_bytes(),
            issued_at: signed.body.issued_at,
            inclusion_deadline: signed.body.inclusion_deadline,
            created_at: issued_at,
        })?,
        FindingStatusWriteOutcome::Inserted
    );
    let live_state = service_state(Arc::clone(&authority), market.clone());
    let mut expired_market = market;
    expired_market.status_feed_operator.authority.valid_until = now;
    expired_market.status_feed_service_bond.valid_until = now;
    let expired_state = service_state(Arc::clone(&authority), expired_market);
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer service-secret"),
    );

    let response = handle_submit_finding_status_intent(
        State(expired_state),
        AxumPath(FEED_ID.to_string()),
        headers.clone(),
        raw.clone(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let response_json: serde_json::Value = serde_json::from_slice(&response_body)?;
    assert_eq!(response_json["exact_replay"], true);
    assert_eq!(response_json["status"], "dispatch_eligible");

    let other_feed = "status-feed/other-venue";
    let mut other_market = live_market_config(now);
    other_market.status_feed_operator_ref = other_feed.to_string();
    other_market.status_feed_operator.feed_id = other_feed.to_string();
    other_market.status_feed_service_bond.feed_id = other_feed.to_string();
    let other_state = service_state(Arc::clone(&authority), other_market);
    let response = handle_submit_finding_status_intent(
        State(other_state),
        AxumPath(other_feed.to_string()),
        headers.clone(),
        raw,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut stale_new = signed.body;
    stale_new.finding_id = sha256_hex(b"another stale finding");
    stale_new.source_receipt.body.finding_id = stale_new.finding_id.clone();
    stale_new.source_receipt = SignedExportEnvelope::sign(stale_new.source_receipt.body, &seller)?;
    stale_new.source_receipt_sha256 =
        chio_finding::signed_envelope_sha256(&stale_new.source_receipt)?;
    stale_new.intent_id = compute_intent_id(&stale_new).test_expect("new stale intent id");
    let stale_new = SignedExportEnvelope::sign(stale_new, &operator_key())?;
    let stale_raw = String::from_utf8(canonical_json_bytes(&stale_new)?)?;
    let response = handle_submit_finding_status_intent(
        State(live_state),
        AxumPath(FEED_ID.to_string()),
        headers,
        stale_raw,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}
