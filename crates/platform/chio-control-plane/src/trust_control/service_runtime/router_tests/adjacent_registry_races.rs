//! Offer creation, pre-authorized code redemption and credential redemption
//! each read the whole offers file, change it and write it back. One that
//! starts while another sits between its read and its write must read what
//! that write left, so a code or access token is consumed once and no change
//! is lost.

use super::*;
use crate::passport_verifier::{
    PassportIssuanceOfferRecord, PassportIssuanceOfferRegistry, PassportIssuanceOfferState,
};

const HANG_GUARD: Duration = Duration::from_secs(30);
const PAUSE_BOUND: Duration = HANG_GUARD;
use chio_credentials::{
    CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_OID4VCI_FORMAT,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading};
use std::future::Future;
use std::sync::mpsc;
use std::task::Poll;

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
        let (arrived_tx, arrived) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let mut state = state.clone();
        state.finding_challenge_clock = Arc::new(PausedFirstReading {
            inner: Arc::clone(&state.finding_challenge_clock),
            pause: std::sync::Mutex::new(Some((arrived_tx, release_rx))),
        });
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

/// Polls `request` once while `paused` sits between its offers file read and
/// its write, then lets `paused` write. Returns the paused redemption's
/// response and then `request`'s.
async fn race(
    paused: PausedRedemption,
    request: impl Future<Output = Response>,
) -> Result<(Response, Response), Box<dyn std::error::Error>> {
    let mut request = std::pin::pin!(request);
    let first_poll = std::future::poll_fn(|cx| Poll::Ready(request.as_mut().poll(cx))).await;
    let redeemed = paused.finish().await?;
    let response = match first_poll {
        Poll::Ready(response) => response,
        Poll::Pending => tokio::time::timeout(HANG_GUARD, request).await?,
    };
    Ok((redeemed, response))
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

/// Redeems a credential with the access token `response` granted, if it
/// granted one, and returns how many tokens and credentials that issued.
async fn credentials_from(
    state: &TrustServiceState,
    record: &PassportIssuanceOfferRecord,
    response: Response,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let (status, body) = status_and_text(response).await?;
    if status != StatusCode::OK {
        return Ok((0, 0));
    }
    let token = serde_json::from_str::<Oid4vciTokenResponse>(&body)?.access_token;
    let (status, _) = status_and_text(redeem_credential(state, &token, record)?.await).await?;
    Ok((1, usize::from(status == StatusCode::OK)))
}

#[tokio::test(flavor = "current_thread")]
async fn one_pre_authorized_code_redeemed_during_a_paused_redemption_issues_one_credential(
) -> TestResult {
    let (fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    let mut offers = OffersFile::new(&fixture)?;
    let (record, request) = offers.offer()?;
    offers.write()?;

    let paused = PausedRedemption::start(&fixture.state, request.clone())?;
    let second = tokio::task::spawn_blocking({
        let state = fixture.state.clone();
        let runtime = tokio::runtime::Handle::current();
        move || {
            runtime.block_on(handle_redeem_passport_issuance_token(
                State(state),
                Json(request),
            ))
        }
    });
    let second = tokio::time::timeout(HANG_GUARD, second).await??;
    let (second_tokens, second_credentials) =
        credentials_from(&fixture.state, &record, second).await?;
    let (first_tokens, first_credentials) =
        credentials_from(&fixture.state, &record, paused.finish().await?).await?;
    let tokens = first_tokens + second_tokens;
    let credentials = first_credentials + second_credentials;
    assert_eq!(
        (tokens, credentials),
        (1, 1),
        "one pre-authorized code issued {tokens} access tokens and {credentials} credentials"
    );
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
    let credential = redeem_credential(&fixture.state, &access_token, &entitled)?;
    let (redeemed, credential) = race(paused, credential).await?;
    let credential = if credential.status() == StatusCode::SERVICE_UNAVAILABLE {
        redeem_credential(&fixture.state, &access_token, &entitled)?.await
    } else {
        credential
    };
    let token = issued_token(redeemed).await?;
    let (status, body) = status_and_text(credential).await?;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) =
        status_and_text(redeem_credential(&fixture.state, &access_token, &entitled)?.await).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "one access token issued a second credential: {body}"
    );
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
    let (redeemed, created) = race(paused, created).await?;
    let created = if created.status() == StatusCode::SERVICE_UNAVAILABLE {
        handle_create_passport_issuance_offer(
            State(fixture.state.clone()),
            bearer("service-secret")?,
            Json(CreatePassportIssuanceOfferRequest {
                passport: issuable_passport(offers.issued_at)?,
                ttl_seconds: 3_600,
                credential_configuration_id: None,
            }),
        )
        .await
    } else {
        created
    };
    let token = issued_token(redeemed).await?;
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
    std::fs::write(&path, bytes)?;
    let deletion = handle_delete_verifier_policy(
        State(state.clone()),
        AxumPath("removed".to_string()),
        bearer("service-secret")?,
    )
    .await;
    let refused = deletion.status() == StatusCode::SERVICE_UNAVAILABLE;
    if !refused {
        assert_eq!(deletion.status(), StatusCode::OK);
    }
    release_tx.send(())?;
    let response = tokio::time::timeout(HANG_GUARD, upsert).await??;
    assert_eq!(response.status(), StatusCode::OK);
    writer.join().map_err(|_| "FIFO writer panicked")??;
    if refused {
        let response = handle_delete_verifier_policy(
            State(state),
            AxumPath("removed".to_string()),
            bearer("service-secret")?,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
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
