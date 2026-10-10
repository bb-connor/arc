//! Offer creation, pre-authorized code redemption and credential redemption
//! each read the whole offers file, change it and write it back. One that
//! starts while another sits between its read and its write must read what
//! that write left, so a code or access token is consumed once and no change
//! is lost.

use super::*;
use crate::passport_verifier::{
    PassportIssuanceOfferRecord, PassportIssuanceOfferRegistry, PassportIssuanceOfferState,
    RegistryUpdateError,
};

const HANG_GUARD: Duration = Duration::from_secs(30);
const PAUSE_BOUND: Duration = HANG_GUARD;
use chio_credentials::{
    CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_OID4VCI_FORMAT,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading};
use futures_util::FutureExt;
use std::future::Future;
use std::sync::mpsc;

/// An issuer clock whose first reading waits until the test releases it.
/// Code redemption reads it while resolving the issuer metadata, after it has
/// read the offers file and before it writes the file back. Every later
/// reading passes straight through.
struct PausedFirstReading {
    inner: Arc<dyn Clock>,
    pause: std::sync::Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl Clock for PausedFirstReading {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let pause = self
            .pause
            .lock()
            .map_err(|_| ClockError::Unavailable)?
            .take();
        if let Some((arrived, release)) = pause {
            let _ = arrived.send(());
            let _ = release.recv_timeout(PAUSE_BOUND);
        }
        self.inner.read()
    }
}

fn paused_clock(
    state: &TrustServiceState,
) -> (TrustServiceState, mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (arrived_tx, arrived) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let mut state = state.clone();
    state.finding_challenge_clock = Arc::new(PausedFirstReading {
        inner: Arc::clone(&state.finding_challenge_clock),
        pause: std::sync::Mutex::new(Some((arrived_tx, release_rx))),
    });
    (state, arrived, release)
}

/// A code redemption held between its offers file read and its write.
struct PausedRedemption {
    release: mpsc::Sender<()>,
    redemption: tokio::task::JoinHandle<Response>,
}

impl PausedRedemption {
    /// Redeems `request` on the blocking pool, as the token route does, and
    /// returns once the redemption has read the offers file and waits on the
    /// issuer clock.
    fn start(
        state: &TrustServiceState,
        request: Oid4vciTokenRequest,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (state, arrived, release) = paused_clock(state);
        let runtime = tokio::runtime::Handle::current();
        let redemption = tokio::task::spawn_blocking(move || {
            runtime.block_on(handle_redeem_passport_issuance_token(
                State(state),
                Json(request),
            ))
        });
        arrived
            .recv_timeout(HANG_GUARD)
            .map_err(|_| "the code redemption ended before it read the issuer clock")?;
        Ok(Self {
            release,
            redemption,
        })
    }

    /// Lets the redemption write the offers file and returns its response.
    async fn finish(self) -> Result<Response, Box<dyn std::error::Error>> {
        self.release.send(())?;
        Ok(tokio::time::timeout(HANG_GUARD, self.redemption).await??)
    }
}

fn assert_registry_busy(path: &Path) {
    assert!(matches!(
        crate::signed_input::lock_registry(path),
        Err(RegistryUpdateError::Busy)
    ));
}

async fn assert_error(response: Response, status: StatusCode, error: &str) -> TestResult {
    let (actual_status, text) = status_and_text(response).await?;
    assert_eq!(actual_status, status, "{text}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text)?,
        serde_json::json!({"error": error})
    );
    Ok(())
}

async fn assert_busy(response: Response) -> TestResult {
    assert_error(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        &CliError::from(RegistryUpdateError::Busy).to_string(),
    )
    .await
}

/// Offers issued by the provisioned authority, written as the service's
/// offers file.
struct OffersFile {
    path: PathBuf,
    metadata: Oid4vciCredentialIssuerMetadata,
    registry: PassportIssuanceOfferRegistry,
    issued_at: u64,
}

impl OffersFile {
    fn new(fixture: &PublicAuthorityFixture) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            path: fixture
                .state
                .config
                .passport_issuance_offers_file
                .clone()
                .ok_or("offers file not configured")?,
            metadata: configured_passport_credential_issuer(&fixture.state.config)?,
            registry: PassportIssuanceOfferRegistry::default(),
            issued_at: chio_test_support::clock::unix_seconds(),
        })
    }

    /// Issues one offer and returns it with the wallet's request to redeem
    /// its pre-authorized code.
    fn offer(
        &mut self,
    ) -> Result<(PassportIssuanceOfferRecord, Oid4vciTokenRequest), Box<dyn std::error::Error>>
    {
        let record = self.registry.issue_offer(
            &self.metadata,
            issuable_passport(self.issued_at)?,
            None,
            3_600,
            self.issued_at,
        )?;
        let request = Oid4vciTokenRequest {
            grant_type: chio_credentials::OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
            pre_authorized_code: record.offer.pre_authorized_code()?.to_string(),
        };
        Ok((record, request))
    }

    /// Redeems a code in place and returns its access token.
    fn redeem(
        &mut self,
        request: &Oid4vciTokenRequest,
    ) -> Result<String, Box<dyn std::error::Error>> {
        Ok(self
            .registry
            .redeem_pre_authorized_code(&self.metadata, request, self.issued_at, 300)?
            .access_token)
    }

    fn write(&self) -> TestResult {
        std::fs::write(&self.path, canonical_json_bytes(&self.registry)?)?;
        Ok(())
    }
}

fn credential_request(record: &PassportIssuanceOfferRecord) -> Oid4vciCredentialRequest {
    Oid4vciCredentialRequest {
        credential_configuration_id: Some(
            CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.to_string(),
        ),
        format: Some(CHIO_PASSPORT_OID4VCI_FORMAT.to_string()),
        subject: record.offer.chio_offer_context.as_ref().map_or_else(
            || record.passport.subject.clone(),
            |context| context.subject.clone(),
        ),
    }
}

fn bearer(token: &str) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))?,
    );
    Ok(headers)
}

fn redeem_credential(
    state: &TrustServiceState,
    access_token: &str,
    record: &PassportIssuanceOfferRecord,
) -> Result<impl Future<Output = Response>, Box<dyn std::error::Error>> {
    Ok(handle_redeem_passport_issuance_credential(
        State(state.clone()),
        bearer(access_token)?,
        Json(credential_request(record)),
    ))
}

async fn status_and_text(
    response: Response,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn persisted_offers(
    path: &Path,
) -> Result<PassportIssuanceOfferRegistry, Box<dyn std::error::Error>> {
    Ok(PassportIssuanceOfferRegistry::load(path)?)
}

#[tokio::test(flavor = "current_thread")]
async fn one_pre_authorized_code_redeemed_during_a_paused_redemption_issues_one_credential(
) -> TestResult {
    let (fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    let mut offers = OffersFile::new(&fixture)?;
    let (record, request) = offers.offer()?;
    offers.write()?;
    let before = std::fs::read(&offers.path)?;

    let paused = PausedRedemption::start(&fixture.state, request.clone())?;
    assert_registry_busy(&offers.path);
    assert_busy(
        handle_redeem_passport_issuance_token(State(fixture.state.clone()), Json(request.clone()))
            .await,
    )
    .await?;
    assert_eq!(std::fs::read(&offers.path)?, before);
    let token = issued_token(paused.finish().await?).await?;
    let persisted = persisted_offers(&offers.path)?;
    let winner = persisted
        .offers
        .get(&record.offer_id)
        .ok_or("winner disappeared")?;
    assert_eq!(winner.state, PassportIssuanceOfferState::TokenIssued);
    assert_eq!(
        winner.access_token.as_deref(),
        Some(token.access_token.as_str())
    );
    assert_error(
        handle_redeem_passport_issuance_token(State(fixture.state.clone()), Json(request)).await,
        StatusCode::BAD_REQUEST,
        &CliError::cli_other_error("pre-authorized code has already been redeemed").to_string(),
    )
    .await?;
    let response = redeem_credential(&fixture.state, &token.access_token, &record)?.await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!persisted_offers(&offers.path)?
        .offers
        .contains_key(&record.offer_id));
    assert_error(
        redeem_credential(&fixture.state, &token.access_token, &record)?.await,
        StatusCode::UNAUTHORIZED,
        &CliError::cli_other_error("access token is not present in the issuance registry")
            .to_string(),
    )
    .await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_credential_redeemed_during_a_paused_code_redemption_is_issued_once() -> TestResult {
    let (fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    let mut offers = OffersFile::new(&fixture)?;
    let (entitled, entitled_code) = offers.offer()?;
    let access_token = offers.redeem(&entitled_code)?;
    let (waiting, waiting_code) = offers.offer()?;
    offers.write()?;

    let paused = PausedRedemption::start(&fixture.state, waiting_code)?;
    assert_registry_busy(&offers.path);
    let before = std::fs::read(&offers.path)?;
    assert_busy(redeem_credential(&fixture.state, &access_token, &entitled)?.await).await?;
    assert_eq!(std::fs::read(&offers.path)?, before);
    let token = issued_token(paused.finish().await?).await?;
    let credential = redeem_credential(&fixture.state, &access_token, &entitled)?.await;
    let (status, body) = status_and_text(credential).await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_error(
        redeem_credential(&fixture.state, &access_token, &entitled)?.await,
        StatusCode::UNAUTHORIZED,
        &CliError::cli_other_error("access token is not present in the issuance registry")
            .to_string(),
    )
    .await?;
    let persisted = persisted_offers(&offers.path)?;
    assert!(!persisted.offers.contains_key(&entitled.offer_id));
    let waiting = persisted
        .offers
        .get(&waiting.offer_id)
        .ok_or("the redeemed offer is missing from the offers file")?;
    assert_eq!(waiting.state, PassportIssuanceOfferState::TokenIssued);
    assert_eq!(
        waiting.access_token.as_deref(),
        Some(token.access_token.as_str())
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_offer_created_during_a_paused_code_redemption_is_kept() -> TestResult {
    let (fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    let mut offers = OffersFile::new(&fixture)?;
    let (waiting, waiting_code) = offers.offer()?;
    offers.write()?;

    let paused = PausedRedemption::start(&fixture.state, waiting_code)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer service-secret"),
    );
    let created = handle_create_passport_issuance_offer(
        State(fixture.state.clone()),
        headers,
        Json(CreatePassportIssuanceOfferRequest {
            passport: issuable_passport(offers.issued_at)?,
            ttl_seconds: 3_600,
            credential_configuration_id: None,
        }),
    );
    assert_registry_busy(&offers.path);
    let before = std::fs::read(&offers.path)?;
    assert_busy(created.await).await?;
    assert_eq!(std::fs::read(&offers.path)?, before);
    let token = issued_token(paused.finish().await?).await?;
    let created = handle_create_passport_issuance_offer(
        State(fixture.state.clone()),
        bearer("service-secret")?,
        Json(CreatePassportIssuanceOfferRequest {
            passport: issuable_passport(offers.issued_at)?,
            ttl_seconds: 3_600,
            credential_configuration_id: None,
        }),
    )
    .await;
    let (status, body) = status_and_text(created).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let created: PassportIssuanceOfferRecord = serde_json::from_str(&body)?;

    let persisted = persisted_offers(&offers.path)?;
    assert!(
        persisted.offers.contains_key(&created.offer_id),
        "the offer created while a code redemption was in flight was lost"
    );
    let waiting = persisted
        .offers
        .get(&waiting.offer_id)
        .ok_or("the redeemed offer is missing from the offers file")?;
    assert_eq!(waiting.state, PassportIssuanceOfferState::TokenIssued);
    assert_eq!(
        waiting.access_token.as_deref(),
        Some(token.access_token.as_str())
    );
    Ok(())
}

async fn issued_token(
    response: Response,
) -> Result<chio_credentials::Oid4vciTokenResponse, Box<dyn std::error::Error>> {
    let (status, body) = status_and_text(response).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    Ok(serde_json::from_str(&body)?)
}

fn policy(policy_id: &str) -> Result<SignedPassportVerifierPolicy, Box<dyn std::error::Error>> {
    let now = chio_test_support::clock::unix_seconds();
    Ok(chio_credentials::create_signed_passport_verifier_policy(
        &Keypair::from_seed(&[41; 32]),
        policy_id,
        "verifier",
        now,
        now + 3_600,
        chio_credentials::PassportVerifierPolicy::default(),
    )?)
}

/// A FIFO is only a deterministic read pause in this witness, never the
/// supported registry storage format. The bytes and mutation handlers are real.
#[tokio::test(flavor = "current_thread")]
async fn an_unrelated_policy_upsert_cannot_restore_a_deleted_policy() -> TestResult {
    use std::io::Write;
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("policies.json");
    let removed = policy("removed")?;
    let added = policy("unrelated")?;
    let mut initial = VerifierPolicyRegistry::default();
    initial.upsert(removed)?;
    let bytes = canonical_json_bytes(&initial)?;
    let mut state = metrics_state("service-secret");
    state.config.verifier_policies_file = Some(path.clone());
    let result = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&path)
        .status()?;
    assert!(
        result.success(),
        "could not create deterministic read pause"
    );
    let (opened_tx, opened_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let fifo = path.clone();
    let supplied = bytes.clone();
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().write(true).open(fifo)?;
        file.write_all(&supplied)?;
        let _ = opened_tx.send(());
        let _ = release_rx.recv_timeout(HANG_GUARD);
        Ok(())
    });
    let upsert = tokio::task::spawn_blocking({
        let state = state.clone();
        let added = added.clone();
        let runtime = tokio::runtime::Handle::current();
        move || {
            runtime.block_on(handle_upsert_verifier_policy(
                State(state),
                AxumPath("unrelated".to_string()),
                bearer("service-secret").test_unwrap(),
                Json(added),
            ))
        }
    });
    tokio::task::spawn_blocking(move || opened_rx.recv_timeout(HANG_GUARD)).await??;
    std::fs::remove_file(&path)?;
    std::fs::write(&path, &bytes)?;
    let deletion = handle_delete_verifier_policy(
        State(state.clone()),
        AxumPath("removed".to_string()),
        bearer("service-secret")?,
    )
    .await;
    assert_registry_busy(&path);
    assert_busy(deletion).await?;
    assert_eq!(std::fs::read(&path)?, bytes);
    release_tx.send(())?;
    let response = tokio::time::timeout(HANG_GUARD, upsert).await??;
    assert_eq!(response.status(), StatusCode::OK);
    writer.join().map_err(|_| "FIFO writer panicked")??;
    let response = handle_delete_verifier_policy(
        State(state),
        AxumPath("removed".to_string()),
        bearer("service-secret")?,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let reopened = VerifierPolicyRegistry::load(&path)?;
    assert!(
        reopened.get("removed").is_none(),
        "an unrelated update restored a committed policy deletion"
    );
    assert_eq!(reopened.get("unrelated"), Some(&added));
    Ok(())
}

#[tokio::test]
async fn invalid_entitlement_preserves_401_body_and_reads_before_creating_a_signer() -> TestResult {
    let (mut fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    let mut offers = OffersFile::new(&fixture)?;
    let (record, _) = offers.offer()?;
    offers.write()?;
    let missing_seed = fixture.directory.path().join("not-created.seed");
    fixture.state.config.authority_db_path = None;
    fixture.state.config.authority_seed_path = Some(missing_seed.clone());
    let before = std::fs::read(&offers.path)?;
    let response = redeem_credential(&fixture.state, "not-entitled", &record)?.await;
    let (status, text) = status_and_text(response).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let expected = offers
        .registry
        .validate_credential_entitlement(ADVERTISE_URL, "not-entitled", offers.issued_at)
        .err()
        .ok_or("fixture token unexpectedly entitled")?;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text)?,
        serde_json::json!({"error": expected.to_string()})
    );
    assert!(
        !missing_seed.exists(),
        "an unentitled request created signing material"
    );
    assert_eq!(std::fs::read(&offers.path)?, before);
    Ok(())
}

#[tokio::test]
async fn invalid_policy_preserves_the_original_400_body_and_leaves_bytes_unchanged() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("policies.json");
    let mut state = metrics_state("service-secret");
    state.config.verifier_policies_file = Some(path.clone());
    let mut registry = VerifierPolicyRegistry::default();
    registry.upsert(policy("kept")?)?;
    std::fs::write(&path, canonical_json_bytes(&registry)?)?;
    let before = std::fs::read(&path)?;
    let mut document = policy("invalid")?;
    document.body.verifier = "substituted-verifier".to_string();
    let expected = verify_signed_passport_verifier_policy(&document)
        .err()
        .ok_or("tampered policy was valid")?;
    let response = handle_upsert_verifier_policy(
        State(state.clone()),
        AxumPath("invalid".to_string()),
        bearer("service-secret")?,
        Json(document),
    )
    .await;
    let (status, text) = status_and_text(response).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text)?,
        serde_json::json!({"error": expected.to_string()})
    );
    assert_eq!(std::fs::read(&path)?, before);
    let response = handle_upsert_verifier_policy(
        State(state),
        AxumPath("next".to_string()),
        bearer("service-secret")?,
        Json(policy("next")?),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(VerifierPolicyRegistry::load(&path)?.get("next").is_some());
    Ok(())
}

/// Unrelated operator writes retain admission while two public token
/// operations hold the service's public issuance budget.
#[tokio::test(flavor = "current_thread")]
async fn public_token_work_cannot_starve_unrelated_operator_mutation() -> TestResult {
    let (first, _first_db) = PublicAuthorityFixture::provisioned()?;
    let (mut second, _second_db) = PublicAuthorityFixture::provisioned()?;
    // These two independently configured files share one service's public
    // budget; an operator clone shares only its own separate budget.
    second.state.public_passport_issuance_lane = first.state.public_passport_issuance_lane.clone();
    let mut first_offers = OffersFile::new(&first)?;
    let (_, first_code) = first_offers.offer()?;
    first_offers.write()?;
    let mut second_offers = OffersFile::new(&second)?;
    let (_, second_code) = second_offers.offer()?;
    second_offers.write()?;
    let first_paused = PausedRedemption::start(&first.state, first_code)?;
    let second_paused = PausedRedemption::start(&second.state, second_code)?;
    assert_eq!(
        first
            .state
            .public_passport_issuance_lane
            .available_permits(),
        0
    );
    assert_eq!(
        first.state.operator_registry_write_lane.available_permits(),
        2
    );
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("operator-policies.json");
    let mut operator = first.state.clone();
    operator.config.verifier_policies_file = Some(path.clone());
    let document = policy("operator")?;
    let response = handle_upsert_verifier_policy(
        State(operator.clone()),
        AxumPath("operator".to_string()),
        bearer("service-secret")?,
        Json(document.clone()),
    )
    .await;
    let (status, text) = status_and_text(response).await?;
    let statuses = directory.path().join("operator-passport-statuses.json");
    let passport = issuable_passport(first_offers.issued_at)?;
    let record = PassportStatusRegistry::update(&statuses, |registry| {
        registry.publish(&passport, first_offers.issued_at, Default::default())
    })?;
    operator.config.passport_statuses_file = Some(statuses.clone());
    let revoked = handle_revoke_passport_status(
        State(operator),
        AxumPath(record.passport_id.clone()),
        bearer("service-secret")?,
        Json(PassportStatusRevocationRequest {
            reason: Some("compromised".to_string()),
            revoked_at: Some(first_offers.issued_at + 1),
        }),
    )
    .await;
    let (revocation_status, revocation_text) = status_and_text(revoked).await?;
    issued_token(first_paused.finish().await?).await?;
    issued_token(second_paused.finish().await?).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "public token work denied an unrelated operator mutation: {text}"
    );
    assert_eq!(revocation_status, StatusCode::OK, "{revocation_text}");
    assert_eq!(
        PassportStatusRegistry::load(&statuses)?
            .get(&record.passport_id)
            .map(|record| record.status),
        Some(chio_credentials::PassportLifecycleState::Revoked)
    );
    assert_eq!(
        VerifierPolicyRegistry::load(&path)?.get("operator"),
        Some(&document)
    );
    Ok(())
}

/// Dropping the async handler cannot drop the blocking transaction's lock or
/// admission. The clock pause is inside the real fresh mutation callback.
#[tokio::test(flavor = "current_thread")]
async fn cancelled_token_redemption_keeps_its_permit_and_still_consumes_the_code() -> TestResult {
    let (mut fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    fixture.state.public_passport_issuance_lane = BlockingLane::new("public_passport_issuance", 1);
    let lane = fixture.state.public_passport_issuance_lane.clone();
    let mut offers = OffersFile::new(&fixture)?;
    let (record, request) = offers.offer()?;
    offers.write()?;
    let before = std::fs::read(&offers.path)?;
    let (paused, arrived, release) = paused_clock(&fixture.state);
    let redemption = tokio::spawn(handle_redeem_passport_issuance_token(
        State(paused),
        Json(request.clone()),
    ));
    tokio::task::spawn_blocking(move || arrived.recv_timeout(HANG_GUARD)).await??;
    assert_registry_busy(&offers.path);
    assert_eq!(std::fs::read(&offers.path)?, before);
    redemption.abort();
    let cancelled = tokio::time::timeout(HANG_GUARD, redemption)
        .await?
        .err()
        .ok_or("aborted token request still answered")?;
    assert!(cancelled.is_cancelled());
    assert_eq!(lane.available_permits(), 0);
    assert_registry_busy(&offers.path);
    let refused =
        handle_redeem_passport_issuance_token(State(fixture.state.clone()), Json(request.clone()))
            .now_or_never()
            .ok_or("saturated token request queued")?;
    assert_error(
        refused,
        StatusCode::SERVICE_UNAVAILABLE,
        "registry writes are at capacity; nothing was changed, retry",
    )
    .await?;
    // Malformed unauthenticated input retains its historical 400 even while
    // the public lane and this file's lock are occupied.
    let malformed = Oid4vciTokenRequest {
        grant_type: request.grant_type.clone(),
        pre_authorized_code: String::new(),
    };
    let expected =
        CliError::from(malformed.validate().err().ok_or("empty code was valid")?).to_string();
    assert_error(
        handle_redeem_passport_issuance_token(State(fixture.state.clone()), Json(malformed)).await,
        StatusCode::BAD_REQUEST,
        &expected,
    )
    .await?;
    assert_eq!(std::fs::read(&offers.path)?, before);

    release.send(())?;
    tokio::time::timeout(HANG_GUARD, lane.wait_for_free_permit()).await?;
    assert_eq!(lane.available_permits(), 1);
    drop(crate::signed_input::lock_registry(&offers.path).map_err(CliError::from)?);
    let reopened = persisted_offers(&offers.path)?;
    let consumed = reopened
        .offers
        .get(&record.offer_id)
        .ok_or("consumed code was lost")?;
    assert_eq!(consumed.state, PassportIssuanceOfferState::TokenIssued);
    let token = consumed
        .access_token
        .as_deref()
        .ok_or("cancelled redemption did not persist its token")?;
    assert_error(
        handle_redeem_passport_issuance_token(State(fixture.state.clone()), Json(request)).await,
        StatusCode::BAD_REQUEST,
        &CliError::cli_other_error("pre-authorized code has already been redeemed").to_string(),
    )
    .await?;
    let credential = redeem_credential(&fixture.state, token, &record)?.await;
    assert_eq!(credential.status(), StatusCode::OK);
    assert!(!persisted_offers(&offers.path)?
        .offers
        .contains_key(&record.offer_id));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_credential_redemption_keeps_its_permit_and_still_consumes_the_token(
) -> TestResult {
    let (mut fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    fixture.state.public_passport_issuance_lane = BlockingLane::new("public_passport_issuance", 1);
    let lane = fixture.state.public_passport_issuance_lane.clone();
    let mut offers = OffersFile::new(&fixture)?;
    let (record, code) = offers.offer()?;
    let token = offers.redeem(&code)?;
    let (next, next_code) = offers.offer()?;
    offers.write()?;
    let before = std::fs::read(&offers.path)?;
    let (paused, arrived, release) = paused_clock(&fixture.state);
    let redemption = tokio::spawn(handle_redeem_passport_issuance_credential(
        State(paused),
        bearer(&token)?,
        Json(credential_request(&record)),
    ));
    tokio::task::spawn_blocking(move || arrived.recv_timeout(HANG_GUARD)).await??;
    assert_registry_busy(&offers.path);
    assert_eq!(std::fs::read(&offers.path)?, before);
    redemption.abort();
    let cancelled = tokio::time::timeout(HANG_GUARD, redemption)
        .await?
        .err()
        .ok_or("aborted credential request still answered")?;
    assert!(cancelled.is_cancelled());
    assert_eq!(lane.available_permits(), 0);
    assert_registry_busy(&offers.path);
    let refused = redeem_credential(&fixture.state, &token, &record)?
        .now_or_never()
        .ok_or("saturated credential request queued")?;
    assert_error(
        refused,
        StatusCode::SERVICE_UNAVAILABLE,
        "registry writes are at capacity; nothing was changed, retry",
    )
    .await?;
    assert_eq!(std::fs::read(&offers.path)?, before);

    release.send(())?;
    tokio::time::timeout(HANG_GUARD, lane.wait_for_free_permit()).await?;
    assert_eq!(lane.available_permits(), 1);
    drop(crate::signed_input::lock_registry(&offers.path).map_err(CliError::from)?);
    assert!(!persisted_offers(&offers.path)?
        .offers
        .contains_key(&record.offer_id));
    assert_error(
        redeem_credential(&fixture.state, &token, &record)?.await,
        StatusCode::UNAUTHORIZED,
        &CliError::cli_other_error("access token is not present in the issuance registry")
            .to_string(),
    )
    .await?;
    let next_token = issued_token(
        handle_redeem_passport_issuance_token(State(fixture.state.clone()), Json(next_code)).await,
    )
    .await?;
    let reopened = persisted_offers(&offers.path)?;
    assert_eq!(
        reopened
            .offers
            .get(&next.offer_id)
            .and_then(|record| record.access_token.as_deref()),
        Some(next_token.access_token.as_str())
    );
    Ok(())
}
