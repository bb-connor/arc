//! Every passport door refuses a passport its revocation partner has revoked:
//! OID4VP direct post, federated issue, and the service and public challenge
//! verification routes.
use super::oid4vp_issuer_fetch_tests::{
    config_with, register_request, response_parts, state_with, BASE_UNIX_SECS,
};
use super::*;

use axum::extract::{Form, State};
use axum::http::HeaderValue;
use chio_credentials::{
    build_agent_passport, create_passport_presentation_challenge_with_reference,
    issue_chio_passport_sd_jwt_vc, issue_reputation_credential, passport_artifact_id,
    respond_to_oid4vp_request, respond_to_passport_presentation_challenge, AttestationWindow,
    ChioCredentialEvidence, PassportPresentationChallengeArgs, PassportPresentationOptions,
    PassportVerifierPolicy,
};
use chio_revocation_oracle::{passport_revocation_key, SqliteRevocationOracle};
use chio_security_types::clock::FixedClock;
use chio_test_support::prelude::*;

use crate::passport_revocation::passport_revocation_oracle_path;
use crate::passport_revocation_feed::{
    passport_revocation_leaves_page, sign_passport_revocation_root,
};
use crate::passport_revocation_mirror::{
    partner_revocation_mirror_path, PartnerRevocationError, PartnerRevocationMirror,
};
use crate::revocation_partner::{RevocationPartner, REVOCATION_PARTNER_REGISTRY_SCHEMA};

const ADVERTISE_URL: &str = "https://verifier.example";
const PARTNER: &str = "acme";
const NOW_MS: u64 = BASE_UNIX_SECS * 1_000;
const VALID_FROM: u64 = 1_700_000_000;
const VALID_UNTIL: u64 = 2_100_000_000;
const PRESENTED_AT: u64 = 1_750_000_000;

/// A verifier whose revocation partner is its own advertised issuer, so every
/// door can present a passport the partner has signed and revoked.
struct Door {
    _dir: tempfile::TempDir,
    config: TrustServiceConfig,
    authority: Keypair,
    holder: Keypair,
    passport: chio_credentials::AgentPassport,
}

impl Door {
    fn state(&self) -> TrustServiceState {
        state_with(
            self.config.clone(),
            Arc::new(FixedClock::from_millis(NOW_MS)),
        )
    }

    fn expected_refusal(&self) -> serde_json::Value {
        let revoked = PartnerRevocationError::Revoked {
            partner_id: PARTNER.to_owned(),
            passport_id: passport_artifact_id(&self.passport).test_unwrap(),
        };
        serde_json::json!({ "error": CliError::policy_error(revoked.to_string()).to_string() })
    }

    fn challenge(&self, challenge_id: Option<&str>) -> PassportPresentationChallenge {
        create_passport_presentation_challenge_with_reference(PassportPresentationChallengeArgs {
            verifier: ADVERTISE_URL.to_owned(),
            challenge_id: challenge_id.map(str::to_owned),
            nonce: "partner-door-nonce".to_owned(),
            issued_at: VALID_FROM,
            expires_at: VALID_UNTIL,
            options: PassportPresentationOptions::default(),
            policy_ref: None,
            policy: Some(PassportVerifierPolicy::default()),
        })
        .test_unwrap()
    }

    fn presentation(
        &self,
        challenge: &PassportPresentationChallenge,
    ) -> chio_credentials::PassportPresentationResponse {
        respond_to_passport_presentation_challenge(
            &self.holder,
            &self.passport,
            challenge,
            PRESENTED_AT,
        )
        .test_unwrap()
    }
}

/// Builds the door, with the partner's revocation of the passport already
/// mirrored and fresh at [`NOW_MS`].
fn door() -> Door {
    let dir = tempfile::tempdir().test_unwrap();
    let mut config = config_with(
        ADVERTISE_URL,
        &dir.path().join("authority.seed"),
        &dir.path().join("verifier.sqlite3"),
    );
    let authority = resolve_oid4vp_verifier_signing_key(&config).test_unwrap();
    let holder = Keypair::generate();
    let passport = issued_passport(&authority, &holder);

    let registry = dir.path().join("revocation-partners.json");
    std::fs::write(
        &registry,
        serde_json::to_vec(&serde_json::json!({
            "schema": REVOCATION_PARTNER_REGISTRY_SCHEMA,
            "partners": { PARTNER: {
                "partnerId": PARTNER,
                "issuer": ADVERTISE_URL,
                "authorityPublicKey": authority.public_key().to_hex(),
                "revocationFreshnessTtlSeconds": 60,
            }},
        }))
        .test_unwrap(),
    )
    .test_unwrap();
    config.revocation_partners_file = Some(registry.clone());

    let partner_registry = dir.path().join("partner-passport-statuses.json");
    SqliteRevocationOracle::open(&passport_revocation_oracle_path(&partner_registry).test_unwrap())
        .test_unwrap()
        .revoke(
            passport_revocation_key(&passport_artifact_id(&passport).test_unwrap()),
            NOW_MS - 1_000,
        )
        .test_unwrap();
    let signed =
        sign_passport_revocation_root(&partner_registry, authority.clone(), NOW_MS).test_unwrap();
    let leaves = passport_revocation_leaves_page(&partner_registry, 0).test_unwrap();
    let partner = RevocationPartner {
        partner_id: PARTNER.to_owned(),
        issuer: ADVERTISE_URL.to_owned(),
        authority_public_key: authority.public_key(),
        revocation_freshness_ttl_seconds: 60,
    };
    PartnerRevocationMirror::open(
        &partner_revocation_mirror_path(&registry, PARTNER).test_unwrap(),
        PARTNER,
    )
    .test_unwrap()
    .apply(&partner, &signed, &leaves.leaves, NOW_MS)
    .test_unwrap();

    Door {
        _dir: dir,
        config,
        authority,
        holder,
        passport,
    }
}

fn issued_passport(authority: &Keypair, holder: &Keypair) -> chio_credentials::AgentPassport {
    let holder_did = chio_did::DidChio::from_public_key(holder.public_key())
        .test_unwrap()
        .to_string();
    let credential = issue_reputation_credential(
        authority,
        chio_reputation::compute_local_scorecard(
            &holder.public_key().to_hex(),
            VALID_FROM,
            &chio_reputation::LocalReputationCorpus::default(),
            &chio_reputation::ReputationConfig::default(),
        ),
        ChioCredentialEvidence {
            query: AttestationWindow {
                since: None,
                until: VALID_FROM,
            },
            receipt_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_roots: Vec::new(),
            receipt_log_urls: Vec::new(),
            lineage_records: 0,
            uncheckpointed_receipts: 0,
            runtime_attestation: None,
        },
        VALID_FROM,
        VALID_UNTIL,
    )
    .test_unwrap();
    build_agent_passport(&holder_did, vec![credential]).test_unwrap()
}

fn service_headers(door: &Door) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", door.config.service_token)).test_unwrap(),
    );
    headers
}

async fn assert_partner_refusal(door: &Door, response: Response) {
    let (status, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).test_unwrap(),
        door.expected_refusal()
    );
}

#[tokio::test]
async fn the_oid4vp_door_refuses_a_partner_revoked_passport() {
    let door = door();
    let envelope = issue_chio_passport_sd_jwt_vc(
        &door.passport,
        ADVERTISE_URL,
        &door.authority,
        BASE_UNIX_SECS,
        None,
    )
    .test_unwrap();
    let request = register_request(&door.config, Vec::new(), BASE_UNIX_SECS);
    let response_jwt =
        respond_to_oid4vp_request(&door.holder, &envelope.compact, &request, BASE_UNIX_SECS)
            .test_unwrap();
    let response = handle_public_submit_oid4vp_response(
        State(door.state()),
        Form(Oid4vpDirectPostForm {
            response: response_jwt,
        }),
    )
    .await;
    assert_partner_refusal(&door, response).await;
}

#[tokio::test]
async fn the_federated_issue_door_refuses_a_partner_revoked_passport() {
    let door = door();
    let challenge = door.challenge(None);
    let request = FederatedIssueRequest {
        presentation: door.presentation(&challenge),
        expected_challenge: challenge,
        capability: crate::policy::DefaultCapability {
            scope: chio_core::capability::scope::ChioScope::default(),
            ttl: 60,
        },
        admission_policy: None,
        enterprise_identity: None,
        delegation_policy: None,
        upstream_capability_id: None,
    };
    let response =
        handle_federated_issue(State(door.state()), service_headers(&door), Json(request)).await;
    assert_partner_refusal(&door, response).await;
}

#[tokio::test]
async fn the_service_challenge_door_refuses_a_partner_revoked_passport() {
    let door = door();
    let challenge = door.challenge(None);
    let request = VerifyPassportChallengeRequest {
        presentation: door.presentation(&challenge),
        expected_challenge: Some(challenge),
    };
    let response = handle_verify_passport_challenge(
        State(door.state()),
        service_headers(&door),
        Json(request),
    )
    .await;
    assert_partner_refusal(&door, response).await;
}

#[tokio::test]
async fn the_public_challenge_door_refuses_a_partner_revoked_passport() {
    let door = door();
    let challenge = door.challenge(Some("partner-door-challenge"));
    PassportVerifierChallengeStore::open(
        configured_verifier_challenge_db_path(&door.config).test_unwrap(),
    )
    .test_unwrap()
    .register(&challenge)
    .test_unwrap();
    let request = VerifyPassportChallengeRequest {
        presentation: door.presentation(&challenge),
        expected_challenge: None,
    };
    let response =
        handle_public_verify_passport_challenge(State(door.state()), Json(request)).await;
    assert_partner_refusal(&door, response).await;
}
