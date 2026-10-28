use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::oid4vp_issuer_fetch_tests::{
    config_with, register_request, response_parts, state_with, BASE_UNIX_SECS,
};
use super::*;

use axum::extract::{Form, State};
use axum::http::HeaderValue;
use chio_credentials::{
    build_agent_passport, create_passport_presentation_challenge_with_reference, credential_digest,
    issue_chio_passport_sd_jwt_vc, issue_reputation_credential, passport_artifact_id,
    present_agent_passport, respond_to_oid4vp_request, respond_to_passport_presentation_challenge,
    AgentPassport, AttestationWindow, ChioCredentialEvidence, PassportPresentationChallengeArgs,
    PassportPresentationOptions, PassportVerifierPolicy,
};
use chio_revocation_oracle::{
    credential_revocation_key, passport_revocation_key, EpochRoot, RevocationKey, SignedEpochRoot,
    SqliteRevocationOracle,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use chio_test_support::prelude::*;

use crate::passport_revocation::passport_revocation_oracle_path;
use crate::passport_revocation_feed::{
    passport_revocation_leaves_page, sign_passport_revocation_root, PassportRevocationLeavesPage,
};
use crate::passport_revocation_mirror::{
    partner_revocation_mirror_path, PartnerRevocationError, PartnerRevocationMirror,
};
use crate::revocation_partner::{RevocationPartner, REVOCATION_PARTNER_REGISTRY_SCHEMA};

const ADVERTISE_URL: &str = "https://verifier.example";
const PARTNER: &str = "acme";
const OTHER_PARTNER: &str = "globex";
const OTHER_ISSUER: &str = "https://trust.globex.example";
const NOW_MS: u64 = BASE_UNIX_SECS * 1_000;
const VALID_FROM: u64 = 1_700_000_000;
const VALID_UNTIL: u64 = 2_100_000_000;
const PRESENTED_AT: u64 = 1_750_000_000;
const TTL_SECONDS: u64 = 60;

/// A clock the tests and the sync seam move by hand.
struct StepClock(AtomicU64);

impl StepClock {
    fn at(unix_ms: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(unix_ms)))
    }

    fn set(&self, unix_ms: u64) {
        self.0.store(unix_ms, Ordering::SeqCst);
    }

    fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl Clock for StepClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        Ok(ClockReading::new(
            UnixMillis::new(self.now_ms()),
            MonotonicInstant::from_nanos(0),
        ))
    }
}

/// A partner's published feed: its own lifecycle registry and oracle.
struct PartnerFeed {
    registry: std::path::PathBuf,
    oracle: SqliteRevocationOracle,
    authority: Keypair,
}

impl PartnerFeed {
    fn new(dir: &std::path::Path, name: &str, authority: Keypair) -> Self {
        let registry = dir.join(format!("{name}-passport-statuses.json"));
        let oracle =
            SqliteRevocationOracle::open(&passport_revocation_oracle_path(&registry).test_unwrap())
                .test_unwrap();
        Self {
            registry,
            oracle,
            authority,
        }
    }

    fn revoke(&self, key: RevocationKey, at_ms: u64) {
        self.oracle.revoke(key, at_ms).test_unwrap();
    }

    fn publish(&self, at_ms: u64) -> (SignedEpochRoot, PassportRevocationLeavesPage) {
        let signed = sign_passport_revocation_root(
            &self.oracle,
            &self.registry,
            self.authority.clone(),
            at_ms,
        )
        .test_unwrap();
        let page = passport_revocation_leaves_page(&self.oracle, &self.registry, 0).test_unwrap();
        (signed, page)
    }
}

/// A sync seam that moves the door's clock as a slow network would, then
/// applies whatever the partner has published, or fails like an unreachable
/// partner.
struct ScriptedSync {
    clock: Arc<StepClock>,
    advance_ms: u64,
    published: Mutex<BTreeMap<String, (SignedEpochRoot, PassportRevocationLeavesPage)>>,
    calls: AtomicUsize,
}

impl ScriptedSync {
    fn new(clock: Arc<StepClock>, advance_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            clock,
            advance_ms,
            published: Mutex::new(BTreeMap::new()),
            calls: AtomicUsize::new(0),
        })
    }

    fn publish(&self, partner_id: &str, feed: (SignedEpochRoot, PassportRevocationLeavesPage)) {
        self.published
            .lock()
            .test_unwrap()
            .insert(partner_id.to_owned(), feed);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl PartnerMirrorSync for ScriptedSync {
    fn sync(
        &self,
        mirror: Arc<PartnerRevocationMirror>,
        partner: &RevocationPartner,
        _clock: Arc<dyn Clock>,
    ) -> Result<EpochRoot, PartnerRevocationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.clock.advance(self.advance_ms);
        let published = self
            .published
            .lock()
            .test_unwrap()
            .get(&partner.partner_id)
            .cloned();
        let Some((signed, page)) = published else {
            return Err(PartnerRevocationError::Fetch(
                partner.partner_id.clone(),
                "partner unreachable".to_owned(),
            ));
        };
        mirror.apply(partner, &signed, &page.leaves, self.clock.now_ms())
    }
}

/// A verifier whose first revocation partner is its own advertised issuer,
/// so every door can present a passport that partner signed.
struct Door {
    dir: tempfile::TempDir,
    config: TrustServiceConfig,
    clock: Arc<StepClock>,
    sync: Arc<ScriptedSync>,
    authority: Keypair,
    holder: Keypair,
    partners: Vec<serde_json::Value>,
    feed: PartnerFeed,
}

impl Door {
    fn new(sync_advance_ms: u64) -> Self {
        let dir = tempfile::tempdir().test_unwrap();
        let mut config = config_with(
            ADVERTISE_URL,
            &dir.path().join("authority.seed"),
            &dir.path().join("verifier.sqlite3"),
        );
        let authority = resolve_oid4vp_verifier_signing_key(&config).test_unwrap();
        let registry = dir.path().join("revocation-partners.json");
        config.revocation_partners_file = Some(registry);
        let clock = StepClock::at(NOW_MS);
        let sync = ScriptedSync::new(Arc::clone(&clock), sync_advance_ms);
        let feed = PartnerFeed::new(dir.path(), PARTNER, authority.clone());
        let mut door = Self {
            dir,
            config,
            clock,
            sync,
            authority: authority.clone(),
            holder: Keypair::generate(),
            partners: Vec::new(),
            feed,
        };
        door.add_partner(
            PARTNER,
            ADVERTISE_URL,
            &authority,
            &[&authority],
            TTL_SECONDS,
        );
        door
    }

    fn registry(&self) -> std::path::PathBuf {
        self.config.revocation_partners_file.clone().test_unwrap()
    }

    fn add_partner(
        &mut self,
        partner_id: &str,
        issuer: &str,
        authority: &Keypair,
        issuer_keys: &[&Keypair],
        ttl_seconds: u64,
    ) {
        self.partners.push(serde_json::json!({
            "partnerId": partner_id,
            "issuer": issuer,
            "authorityPublicKey": authority.public_key().to_hex(),
            "issuerPublicKeys": issuer_keys
                .iter()
                .map(|key| key.public_key().to_hex())
                .collect::<Vec<_>>(),
            "revocationFreshnessTtlSeconds": ttl_seconds,
        }));
        let partners: serde_json::Map<String, serde_json::Value> = self
            .partners
            .iter()
            .map(|partner| {
                (
                    partner["partnerId"].as_str().test_unwrap().to_owned(),
                    partner.clone(),
                )
            })
            .collect();
        std::fs::write(
            self.registry(),
            serde_json::to_vec(&serde_json::json!({
                "schema": REVOCATION_PARTNER_REGISTRY_SCHEMA,
                "partners": partners,
            }))
            .test_unwrap(),
        )
        .test_unwrap();
    }

    fn partner(&self, partner_id: &str) -> RevocationPartner {
        let entry = self
            .partners
            .iter()
            .find(|partner| partner["partnerId"] == partner_id)
            .test_unwrap();
        serde_json::from_value(entry.clone()).test_unwrap()
    }

    /// Commits `feed` into the door's mirror of `partner_id` at `at_ms`.
    fn mirror(
        &self,
        partner_id: &str,
        feed: &(SignedEpochRoot, PassportRevocationLeavesPage),
        at_ms: u64,
    ) {
        PartnerRevocationMirror::open(
            &partner_revocation_mirror_path(&self.registry(), partner_id).test_unwrap(),
            partner_id,
        )
        .test_unwrap()
        .apply(&self.partner(partner_id), &feed.0, &feed.1.leaves, at_ms)
        .test_unwrap();
    }

    fn state(&self) -> TrustServiceState {
        let mut state = state_with(self.config.clone(), self.clock.clone());
        state.partner_revocation_door = Arc::new(PartnerRevocationDoor::with_sync(Arc::clone(
            &self.sync,
        )
            as Arc<dyn PartnerMirrorSync>));
        state
    }

    fn passport(&self, issuers: &[&Keypair]) -> AgentPassport {
        let holder_did = chio_did::DidChio::from_public_key(self.holder.public_key())
            .test_unwrap()
            .to_string();
        let credentials = issuers
            .iter()
            .map(|issuer| issued_credential(issuer, &self.holder))
            .collect();
        build_agent_passport(&holder_did, credentials).test_unwrap()
    }

    fn challenge(
        &self,
        challenge_id: Option<&str>,
        issued_at: u64,
        expires_at: u64,
    ) -> PassportPresentationChallenge {
        create_passport_presentation_challenge_with_reference(PassportPresentationChallengeArgs {
            verifier: ADVERTISE_URL.to_owned(),
            challenge_id: challenge_id.map(str::to_owned),
            nonce: "partner-door-nonce".to_owned(),
            issued_at,
            expires_at,
            options: PassportPresentationOptions::default(),
            policy_ref: None,
            policy: Some(PassportVerifierPolicy::default()),
        })
        .test_unwrap()
    }

    fn service_request(
        &self,
        passport: &AgentPassport,
        challenge: &PassportPresentationChallenge,
    ) -> VerifyPassportChallengeRequest {
        VerifyPassportChallengeRequest {
            presentation: respond_to_passport_presentation_challenge(
                &self.holder,
                passport,
                challenge,
                PRESENTED_AT,
            )
            .test_unwrap(),
            expected_challenge: Some(challenge.clone()),
        }
    }

    async fn service_door(&self, request: VerifyPassportChallengeRequest) -> Response {
        handle_verify_passport_challenge(State(self.state()), service_headers(self), Json(request))
            .await
    }

    async fn public_door(
        &self,
        passport: &AgentPassport,
        challenge: &PassportPresentationChallenge,
    ) -> Response {
        let request = VerifyPassportChallengeRequest {
            presentation: respond_to_passport_presentation_challenge(
                &self.holder,
                passport,
                challenge,
                PRESENTED_AT,
            )
            .test_unwrap(),
            expected_challenge: None,
        };
        handle_public_verify_passport_challenge(State(self.state()), Json(request)).await
    }

    fn register_public_challenge(&self, challenge: &PassportPresentationChallenge) {
        PassportVerifierChallengeStore::open(
            configured_verifier_challenge_db_path(&self.config).test_unwrap(),
        )
        .test_unwrap()
        .register(challenge)
        .test_unwrap();
    }
}

fn issued_credential(issuer: &Keypair, holder: &Keypair) -> chio_credentials::ReputationCredential {
    issue_reputation_credential(
        issuer,
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
    .test_unwrap()
}

fn service_headers(door: &Door) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", door.config.service_token)).test_unwrap(),
    );
    headers
}

fn refusal(error: PartnerRevocationError) -> serde_json::Value {
    serde_json::json!({ "error": CliError::policy_error(error.to_string()).to_string() })
}

fn revoked(partner_id: &str, subject: &str) -> serde_json::Value {
    refusal(PartnerRevocationError::Revoked {
        partner_id: partner_id.to_owned(),
        subject: subject.to_owned(),
    })
}

async fn assert_refused(response: Response, expected: serde_json::Value) {
    let (status, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).test_unwrap(),
        expected
    );
}

async fn assert_admitted(response: Response) {
    let (status, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A door whose partner has revoked `passport` by passport id, mirrored and
/// fresh at [`NOW_MS`].
fn door_with_revoked_passport() -> (Door, AgentPassport) {
    let door = Door::new(0);
    let passport = door.passport(&[&door.authority]);
    door.feed.revoke(
        passport_revocation_key(&passport_artifact_id(&passport).test_unwrap()),
        NOW_MS - 1_000,
    );
    door.mirror(PARTNER, &door.feed.publish(NOW_MS), NOW_MS);
    (door, passport)
}

#[tokio::test]
async fn the_service_challenge_door_refuses_a_partner_revoked_passport() {
    let (door, passport) = door_with_revoked_passport();
    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    let response = door
        .service_door(door.service_request(&passport, &challenge))
        .await;
    let passport_id = passport_artifact_id(&passport).test_unwrap();
    assert_refused(response, revoked(PARTNER, &passport_id)).await;
}

#[tokio::test]
async fn the_public_challenge_door_refuses_a_partner_revoked_passport() {
    let (door, passport) = door_with_revoked_passport();
    let challenge = door.challenge(Some("partner-door-challenge"), VALID_FROM, VALID_UNTIL);
    door.register_public_challenge(&challenge);
    let response = door.public_door(&passport, &challenge).await;
    let passport_id = passport_artifact_id(&passport).test_unwrap();
    assert_refused(response, revoked(PARTNER, &passport_id)).await;
}

#[tokio::test]
async fn the_oid4vp_door_refuses_a_partner_revoked_passport() {
    let (door, passport) = door_with_revoked_passport();
    let envelope = issue_chio_passport_sd_jwt_vc(
        &passport,
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
    let passport_id = passport_artifact_id(&passport).test_unwrap();
    assert_refused(response, revoked(PARTNER, &passport_id)).await;
}

#[tokio::test]
async fn the_federated_issue_door_refuses_a_partner_revoked_passport() {
    let (door, passport) = door_with_revoked_passport();
    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    let request = FederatedIssueRequest {
        presentation: respond_to_passport_presentation_challenge(
            &door.holder,
            &passport,
            &challenge,
            PRESENTED_AT,
        )
        .test_unwrap(),
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
    let passport_id = passport_artifact_id(&passport).test_unwrap();
    assert_refused(response, revoked(PARTNER, &passport_id)).await;
}

#[tokio::test]
async fn the_native_door_refuses_a_filtered_view_of_a_partner_revoked_passport() {
    let door = Door::new(0);
    let outsider = Keypair::generate();
    let passport = door.passport(&[&door.authority, &outsider]);
    let partner_credential = passport
        .credentials
        .iter()
        .find(|credential| {
            credential.unsigned.issuer
                == chio_did::DidChio::from_public_key(door.authority.public_key())
                    .test_unwrap()
                    .to_string()
        })
        .test_unwrap();
    let digest = credential_digest(partner_credential).test_unwrap();
    door.feed
        .revoke(credential_revocation_key(&digest), NOW_MS - 1_000);
    door.mirror(PARTNER, &door.feed.publish(NOW_MS), NOW_MS);

    let filtered = present_agent_passport(
        &passport,
        &PassportPresentationOptions {
            issuer_allowlist: [partner_credential.unsigned.issuer.clone()]
                .into_iter()
                .collect(),
            max_credentials: None,
        },
    )
    .test_unwrap();
    assert_ne!(
        passport_artifact_id(&filtered).test_unwrap(),
        passport_artifact_id(&passport).test_unwrap()
    );
    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    let response = door
        .service_door(door.service_request(&filtered, &challenge))
        .await;
    assert_refused(response, revoked(PARTNER, &digest)).await;
}

#[tokio::test]
async fn the_native_door_matches_a_passport_issued_under_a_rotated_partner_key() {
    let mut door = Door::new(0);
    let retired = Keypair::generate();
    door.partners.clear();
    let authority = door.authority.clone();
    door.add_partner(
        PARTNER,
        ADVERTISE_URL,
        &authority,
        &[&authority, &retired],
        TTL_SECONDS,
    );
    let passport = door.passport(&[&retired]);
    let digest = credential_digest(&passport.credentials[0]).test_unwrap();
    door.feed
        .revoke(credential_revocation_key(&digest), NOW_MS - 1_000);
    door.mirror(PARTNER, &door.feed.publish(NOW_MS), NOW_MS);

    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    let response = door
        .service_door(door.service_request(&passport, &challenge))
        .await;
    assert_refused(response, revoked(PARTNER, &digest)).await;
}

#[tokio::test]
async fn a_challenge_that_expires_during_the_partner_sync_is_refused_and_not_consumed() {
    let mut door = Door::new(30_000);
    door.partners.clear();
    let authority = door.authority.clone();
    door.add_partner(PARTNER, ADVERTISE_URL, &authority, &[&authority], 120);
    door.sync.publish(PARTNER, door.feed.publish(NOW_MS));
    let passport = door.passport(&[&door.authority]);
    let challenge = door.challenge(None, BASE_UNIX_SECS - 10, BASE_UNIX_SECS + 10);

    let response = door
        .service_door(door.service_request(&passport, &challenge))
        .await;
    let (status, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(door.sync.calls(), 1);

    door.clock.set(NOW_MS);
    let retry = door
        .service_door(door.service_request(&passport, &challenge))
        .await;
    assert_admitted(retry).await;
    assert_eq!(
        door.sync.calls(),
        1,
        "the synced mirror is fresh at the retry"
    );
}

#[tokio::test]
async fn a_public_challenge_that_expires_during_the_partner_sync_is_refused_and_not_consumed() {
    let mut door = Door::new(30_000);
    door.partners.clear();
    let authority = door.authority.clone();
    door.add_partner(PARTNER, ADVERTISE_URL, &authority, &[&authority], 120);
    door.sync.publish(PARTNER, door.feed.publish(NOW_MS));
    let passport = door.passport(&[&door.authority]);
    let challenge = door.challenge(
        Some("expiring-public-challenge"),
        BASE_UNIX_SECS - 10,
        BASE_UNIX_SECS + 10,
    );
    door.register_public_challenge(&challenge);

    let response = door.public_door(&passport, &challenge).await;
    let (status, body) = response_parts(response).await;
    assert!(status.is_client_error(), "{status} {body}");
    assert_eq!(door.sync.calls(), 1);

    door.clock.set(NOW_MS);
    assert_admitted(door.public_door(&passport, &challenge).await).await;
}

#[tokio::test]
async fn every_matched_mirror_is_rechecked_at_the_acceptance_instant() {
    let mut door = Door::new(61_000);
    let other = Keypair::generate();
    door.add_partner(OTHER_PARTNER, OTHER_ISSUER, &other, &[&other], TTL_SECONDS);
    door.mirror(PARTNER, &door.feed.publish(NOW_MS), NOW_MS);
    let other_feed = PartnerFeed::new(door.dir.path(), OTHER_PARTNER, other.clone());
    door.sync
        .publish(OTHER_PARTNER, other_feed.publish(NOW_MS + 61_000));
    let passport = door.passport(&[&door.authority, &other]);

    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    let response = door
        .service_door(door.service_request(&passport, &challenge))
        .await;
    assert_eq!(door.sync.calls(), 1);
    assert_refused(
        response,
        refusal(PartnerRevocationError::StaleRoot {
            partner_id: PARTNER.to_owned(),
            issued_at_unix_ms: NOW_MS,
            now_unix_ms: NOW_MS + 61_000,
            ttl_ms: TTL_SECONDS * 1_000,
        }),
    )
    .await;
}

#[tokio::test]
async fn the_door_denies_a_partner_revocation_once_the_mirror_window_lapses() {
    let door = Door::new(0);
    door.mirror(PARTNER, &door.feed.publish(NOW_MS), NOW_MS);
    door.clock.set(NOW_MS + TTL_SECONDS * 1_000 + 1);
    let passport = door.passport(&[&door.authority]);
    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    let response = door
        .service_door(door.service_request(&passport, &challenge))
        .await;
    assert_eq!(door.sync.calls(), 1);
    assert_refused(
        response,
        refusal(PartnerRevocationError::Fetch(
            PARTNER.to_owned(),
            "partner unreachable".to_owned(),
        )),
    )
    .await;
}

#[tokio::test]
async fn the_door_fails_closed_when_a_stale_partner_cannot_sync() {
    let door = Door::new(0);
    let passport = door.passport(&[&door.authority]);
    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    let response = door
        .service_door(door.service_request(&passport, &challenge))
        .await;
    assert_refused(
        response,
        refusal(PartnerRevocationError::Fetch(
            PARTNER.to_owned(),
            "partner unreachable".to_owned(),
        )),
    )
    .await;
}

#[tokio::test]
async fn the_door_passes_issuers_outside_the_registry_and_services_without_one() {
    let door = Door::new(0);
    let outsider = Keypair::generate();
    let passport = door.passport(&[&outsider]);
    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    assert_admitted(
        door.service_door(door.service_request(&passport, &challenge))
            .await,
    )
    .await;
    assert_eq!(door.sync.calls(), 0);

    let mut unconfigured = Door::new(0);
    unconfigured.config.revocation_partners_file = None;
    let passport = unconfigured.passport(&[&unconfigured.authority]);
    let challenge = unconfigured.challenge(None, VALID_FROM, VALID_UNTIL);
    assert_admitted(
        unconfigured
            .service_door(unconfigured.service_request(&passport, &challenge))
            .await,
    )
    .await;
    assert_eq!(unconfigured.sync.calls(), 0);
}

#[tokio::test]
async fn the_door_rereads_the_registry_and_refuses_an_invalid_or_missing_one() {
    let door = Door::new(0);
    door.mirror(PARTNER, &door.feed.publish(NOW_MS), NOW_MS);
    let passport = door.passport(&[&door.authority]);
    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);

    std::fs::write(
        door.registry(),
        b"{\"schema\":\"chio.revocation-partner-registry.v0\"}",
    )
    .test_unwrap();
    let (status, body) = response_parts(
        door.service_door(door.service_request(&passport, &challenge))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("revocation partner registry"), "{body}");

    std::fs::remove_file(door.registry()).test_unwrap();
    let (status, body) = response_parts(
        door.service_door(door.service_request(&passport, &challenge))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("revocation partner registry"), "{body}");
    assert_eq!(door.sync.calls(), 0);
}

#[tokio::test]
async fn the_production_door_syncs_only_over_the_strict_transport() {
    let door = Door::new(0);
    let passport = door.passport(&[&door.authority]);
    let challenge = door.challenge(None, VALID_FROM, VALID_UNTIL);
    let state = state_with(door.config.clone(), door.clock.clone());
    let response = handle_verify_passport_challenge(
        State(state),
        service_headers(&door),
        Json(door.service_request(&passport, &challenge)),
    )
    .await;
    let (status, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.contains(&format!("partner `{PARTNER}` revocation feed fetch failed")),
        "{body}"
    );
}
