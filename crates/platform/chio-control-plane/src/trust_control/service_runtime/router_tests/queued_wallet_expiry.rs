//! Time spent waiting for a blocking worker cannot extend wallet authority.
use super::*;
use axum::body::Body;
use axum::http::Request;
use chio_credentials::{
    AgentPassport, Oid4vciCredentialRequest, Oid4vciTokenRequest,
    CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_SD_JWT_VC_FORMAT,
    OID4VCI_PRE_AUTHORIZED_GRANT_TYPE,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const HANG_GUARD: Duration = Duration::from_secs(15);

struct Wallet {
    _directory: tempfile::TempDir,
    state: TrustServiceState,
    path: PathBuf,
    passport: AgentPassport,
    token: String,
    code: String,
    expires_at: u64,
}

fn passport(now: u64) -> TestResult<AgentPassport> {
    let subject = Keypair::from_seed(&[93; 32]);
    let scorecard = chio_reputation::compute_local_scorecard(
        &subject.public_key().to_hex(),
        now,
        &chio_reputation::LocalReputationCorpus::default(),
        &chio_reputation::ReputationConfig::default(),
    );
    let credential = chio_credentials::issue_reputation_credential(
        &Keypair::from_seed(&[94; 32]),
        scorecard,
        chio_credentials::ChioCredentialEvidence {
            query: chio_credentials::AttestationWindow {
                since: None,
                until: now,
            },
            receipt_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_roots: Vec::new(),
            receipt_log_urls: Vec::new(),
            lineage_records: 0,
            uncheckpointed_receipts: 0,
            runtime_attestation: None,
        },
        now,
        now.checked_add(7_200).ok_or("fixture clock overflow")?,
    )?;
    let did = credential.unsigned.credential_subject.id.clone();
    Ok(chio_credentials::build_agent_passport(
        &did,
        vec![credential],
    )?)
}

impl Wallet {
    fn new(ttl: u64) -> TestResult<Self> {
        Self::with_authority(ttl, false)
    }

    fn with_authority(ttl: u64, sqlite: bool) -> TestResult<Self> {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("offers.json");
        let seed = directory.path().join("authority.seed");
        crate::load_or_create_authority_keypair(&seed)?;
        let mut state = metrics_state("service-secret");
        state.finding_challenge_clock = chio_test_support::clock::clock();
        state.config.advertise_url = Some("https://wallet.example.test".to_string());
        if sqlite {
            let database = directory.path().join("authority.sqlite3");
            chio_store_sqlite::SqliteCapabilityAuthority::open_with_clock(
                &database,
                Arc::clone(&state.finding_challenge_clock),
            )?;
            state.config.authority_db_path = Some(database);
        } else {
            state.config.authority_seed_path = Some(seed);
        }
        state.config.passport_issuance_offers_file = Some(path.clone());
        let now = state.finding_challenge_clock.unix_millis()?.as_secs();
        let passport = passport(now)?;
        let metadata = configured_passport_credential_issuer(&state.config)?;
        let mut registry = PassportIssuanceOfferRegistry::default();
        let offered = registry.issue_offer(
            &metadata,
            passport.clone(),
            Some(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID),
            ttl,
            now,
        )?;
        let token = registry
            .redeem_pre_authorized_code(
                &metadata,
                &Oid4vciTokenRequest {
                    grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
                    pre_authorized_code: offered.offer.pre_authorized_code()?.to_string(),
                },
                now,
                ttl,
            )?
            .access_token;
        let waiting = registry.issue_offer(
            &metadata,
            passport.clone(),
            Some(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID),
            ttl,
            now,
        )?;
        let code = waiting.offer.pre_authorized_code()?.to_string();
        let expires_at = waiting.expires_at;
        registry.save_for_issuance(&path)?;
        Ok(Self {
            _directory: directory,
            state,
            path,
            passport,
            token,
            code,
            expires_at,
        })
    }

    fn headers(&self, token: &str) -> TestResult<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        Ok(headers)
    }

    fn request(&self) -> Oid4vciCredentialRequest {
        Oid4vciCredentialRequest {
            credential_configuration_id: Some(
                CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
            ),
            format: Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string()),
            subject: self.passport.subject.clone(),
        }
    }

    async fn expired(&self) -> TestResult<u64> {
        tokio::time::timeout(HANG_GUARD, async {
            loop {
                let now = self.state.finding_challenge_clock.unix_millis()?.as_secs();
                if now > self.expires_at {
                    return Ok(now);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await?
    }
}

/// Hold the sole blocking worker, then release it before any assertion can
/// unwind the runtime. A timeout also bounds an interrupted Original.
struct HeldPool {
    release: Option<std::sync::mpsc::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl HeldPool {
    async fn new() -> TestResult<Self> {
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _ = entered.send(());
            let _ = wait.recv_timeout(HANG_GUARD);
        });
        tokio::time::timeout(HANG_GUARD, observed).await??;
        Ok(Self {
            release: Some(release),
            task,
        })
    }

    async fn finish(&mut self) -> TestResult {
        if let Some(release) = self.release.take() {
            release.send(())?;
        }
        tokio::time::timeout(HANG_GUARD, &mut self.task).await??;
        Ok(())
    }
}

impl Drop for HeldPool {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

fn runtime() -> TestResult<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()?)
}

async fn refused(
    wallet: &Wallet,
    response: Response,
    expected: StatusCode,
    reason: &str,
    before: &[u8],
) -> TestResult {
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let value: Value = serde_json::from_slice(&body)?;
    let after = std::fs::read(&wallet.path)?;
    eprintln!(
        "expired wallet response={status}; credential_present={}; registry_changed={}",
        value.get("credential").is_some(),
        after != before
    );
    assert_eq!(status, expected, "expired wallet authority was accepted");
    assert_eq!(
        value,
        json!({"error": CliError::cli_other_error(reason.to_string()).to_string()})
    );
    assert_eq!(
        after, before,
        "refusal persisted or consumed wallet authority"
    );
    Ok(())
}

#[test]
fn final_wallet_queued_expiry_middleware_refuses_before_body_poll() -> TestResult {
    let runtime = runtime()?;
    runtime.block_on(async {
        let wallet = Wallet::new(3)?;
        let before = std::fs::read(&wallet.path)?;
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&polls);
        let stream = futures_util::stream::once(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(br#"{"duplicate":1,"duplicate":2}"#))
        });
        let request = Request::builder().method("POST").uri(PASSPORT_ISSUANCE_CREDENTIAL_PATH)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", wallet.token))
            .body(Body::from_stream(stream))?;
        let mut held = HeldPool::new().await?;
        let router = super::super::build_router(wallet.state.clone());
        let mut response = Box::pin(router.oneshot(request));
        assert!(matches!(futures_util::poll!(response.as_mut()), Poll::Pending));
        assert_eq!(wallet.state.wallet_entitlement_lane.blocking_lane().available_permits(), 3);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        wallet.expired().await?;
        held.finish().await?;
        let response = tokio::time::timeout(HANG_GUARD, response).await??;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        eprintln!("expired pre-body entitlement: status={status}; body_polls={}", polls.load(Ordering::SeqCst));
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(serde_json::from_slice::<Value>(&body)?, json!({"error":
            CliError::cli_other_error("access token entitlement has expired".to_string()).to_string()}));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read(&wallet.path)?, before);
        Ok(())
    })
}

#[test]
fn final_wallet_queued_expiry_credential_refuses_without_consuming_token() -> TestResult {
    let runtime = runtime()?;
    runtime.block_on(async {
        let wallet = Wallet::new(3)?;
        let before = std::fs::read(&wallet.path)?;
        let mut held = HeldPool::new().await?;
        let mut response = Box::pin(handle_redeem_passport_issuance_credential(
            State(wallet.state.clone()),
            wallet.headers(&wallet.token)?,
            Json(wallet.request()),
        ));
        assert!(matches!(
            futures_util::poll!(response.as_mut()),
            Poll::Pending
        ));
        assert_eq!(
            wallet
                .state
                .public_passport_issuance_lane
                .available_permits(),
            1
        );
        wallet.expired().await?;
        held.finish().await?;
        let response = tokio::time::timeout(HANG_GUARD, response).await?;
        refused(
            &wallet,
            response,
            StatusCode::UNAUTHORIZED,
            "access token entitlement has expired",
            &before,
        )
        .await
    })
}

#[test]
fn final_wallet_queued_expiry_code_refuses_without_minting_token() -> TestResult {
    let runtime = runtime()?;
    runtime.block_on(async {
        let wallet = Wallet::new(3)?;
        let before = std::fs::read(&wallet.path)?;
        let mut held = HeldPool::new().await?;
        let mut response = Box::pin(handle_redeem_passport_issuance_token(
            State(wallet.state.clone()),
            Json(Oid4vciTokenRequest {
                grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
                pre_authorized_code: wallet.code.clone(),
            }),
        ));
        assert!(matches!(
            futures_util::poll!(response.as_mut()),
            Poll::Pending
        ));
        assert_eq!(
            wallet
                .state
                .public_passport_issuance_lane
                .available_permits(),
            1
        );
        wallet.expired().await?;
        held.finish().await?;
        let response = tokio::time::timeout(HANG_GUARD, response).await?;
        refused(
            &wallet,
            response,
            StatusCode::BAD_REQUEST,
            "issuance offer has expired",
            &before,
        )
        .await
    })
}

#[test]
fn final_wallet_queued_expiry_new_offer_starts_after_worker_wait() -> TestResult {
    let runtime = runtime()?;
    runtime.block_on(async {
        let wallet = Wallet::new(3)?;
        let mut held = HeldPool::new().await?;
        let mut response = Box::pin(handle_create_passport_issuance_offer(
            State(wallet.state.clone()),
            wallet.headers("service-secret")?,
            Json(CreatePassportIssuanceOfferRequest {
                passport: wallet.passport.clone(),
                ttl_seconds: 60,
                credential_configuration_id: Some(
                    CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
                ),
            }),
        ));
        assert!(matches!(
            futures_util::poll!(response.as_mut()),
            Poll::Pending
        ));
        assert_eq!(
            wallet
                .state
                .operator_registry_write_lane
                .available_permits(),
            1
        );
        let released_at = wallet.expired().await?;
        held.finish().await?;
        let response = tokio::time::timeout(HANG_GUARD, response).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
        let offer: PassportIssuanceOfferRecord = serde_json::from_slice(&body)?;
        eprintln!(
            "queued offer issued_at={}, released_at={released_at}",
            offer.issued_at
        );
        assert!(
            offer.issued_at >= released_at,
            "offer used its pre-queue timestamp"
        );
        assert_eq!(offer.expires_at, offer.issued_at + 60);
        Ok(())
    })
}

#[test]
fn final_wallet_queued_expiry_healthy_token_and_signed_credential_progress() -> TestResult {
    let runtime = runtime()?;
    runtime.block_on(async {
        let wallet = Wallet::new(3_600)?;
        let response = handle_redeem_passport_issuance_token(
            State(wallet.state.clone()),
            Json(Oid4vciTokenRequest {
                grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
                pre_authorized_code: wallet.code.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = handle_redeem_passport_issuance_credential(
            State(wallet.state.clone()),
            wallet.headers(&wallet.token)?,
            Json(wallet.request()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
        let credential: chio_credentials::Oid4vciCredentialResponse =
            serde_json::from_slice(&body)?;
        assert_eq!(credential.format, CHIO_PASSPORT_SD_JWT_VC_FORMAT);
        assert!(serde_json::to_value(&credential)?
            .get("credential")
            .is_some());
        let registry = PassportIssuanceOfferRegistry::load(&wallet.path)?;
        let consumed = registry.validate_credential_entitlement(
            "https://wallet.example.test", &wallet.token,
            wallet.state.finding_challenge_clock.unix_millis()?.as_secs(),
        ).test_unwrap_err();
        assert!(matches!(&consumed, CliError::Chio(error) if error.to_string() ==
            CliError::cli_other_error("access token is not present in the issuance registry".to_string()).to_string()));
        Ok(())
    })
}

#[cfg(unix)]
struct PausedOffers {
    path: PathBuf,
    release: Option<std::sync::mpsc::Sender<()>>,
    writer: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

#[cfg(unix)]
impl PausedOffers {
    fn new(
        path: PathBuf,
        bytes: Vec<u8>,
    ) -> TestResult<(Self, tokio::sync::oneshot::Receiver<()>)> {
        use std::io::Write;
        let created = std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(&path)
            .status()?;
        assert!(created.success(), "could not create paused offers fixture");
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let read_path = path.clone();
        let writer = std::thread::spawn(move || {
            let mut file = std::fs::OpenOptions::new().write(true).open(read_path)?;
            let _ = entered.send(());
            let _ = wait.recv_timeout(HANG_GUARD);
            file.write_all(&bytes)
        });
        Ok((
            Self {
                path,
                release: Some(release),
                writer: Some(writer),
            },
            observed,
        ))
    }

    fn finish(&mut self) -> TestResult {
        if let Some(release) = self.release.take() {
            release.send(())?;
        }
        if let Some(writer) = self.writer.take() {
            writer.join().map_err(|_| "offers writer panicked")??;
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PausedOffers {
    fn drop(&mut self) {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(writer) = self.writer.take() {
            let reader = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&self.path);
            let _ = writer.join();
            drop(reader);
        }
    }
}

#[cfg(unix)]
#[test]
fn final_wallet_queued_expiry_middleware_rechecks_after_registry_read() -> TestResult {
    let runtime = runtime()?;
    runtime.block_on(async {
        let mut wallet = Wallet::new(3)?;
        let before = std::fs::read(&wallet.path)?;
        let paused_path = wallet.path.with_file_name("paused-offers.json");
        let (mut paused, entered) = PausedOffers::new(paused_path.clone(), before.clone())?;
        wallet.state.config.passport_issuance_offers_file = Some(paused_path);
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&polls);
        let stream = futures_util::stream::once(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(br#"{"duplicate":1,"duplicate":2}"#))
        });
        let request = Request::builder().method("POST").uri(PASSPORT_ISSUANCE_CREDENTIAL_PATH)
            .header(CONTENT_TYPE, "application/json").header(AUTHORIZATION, format!("Bearer {}", wallet.token))
            .body(Body::from_stream(stream))?;
        let router = super::super::build_router(wallet.state.clone());
        let response = tokio::spawn(async move { router.oneshot(request).await });
        tokio::time::timeout(HANG_GUARD, entered).await??;
        wallet.expired().await?;
        paused.finish()?;
        let response = tokio::time::timeout(HANG_GUARD, response).await???;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        assert_eq!(serde_json::from_slice::<Value>(&body)?, json!({"error":
            CliError::cli_other_error("access token entitlement has expired".to_string()).to_string()}));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read(&wallet.path)?, before);
        Ok(())
    })
}

/// With plain seeds authority admission reads no clock. With SQLite, the
/// second clock read is already inside the actual signing-key inspection on
/// the Original, and inside that loader after the repaired entitlement sample.
struct SignerWaitClock {
    clock: Arc<dyn chio_security_types::clock::Clock>,
    reads: AtomicUsize,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl chio_security_types::clock::Clock for SignerWaitClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
            if let Some(entered) = self
                .entered
                .lock()
                .map_err(|_| chio_security_types::clock::ClockError::Unavailable)?
                .take()
            {
                let _ = entered.send(());
            }
            self.release
                .lock()
                .map_err(|_| chio_security_types::clock::ClockError::Unavailable)?
                .recv_timeout(HANG_GUARD)
                .map_err(|_| chio_security_types::clock::ClockError::Unavailable)?;
        }
        self.clock.read()
    }
}

#[test]
fn final_wallet_queued_expiry_credential_rechecks_after_signer_inspection() -> TestResult {
    let runtime = runtime()?;
    runtime.block_on(async {
        let mut wallet = Wallet::with_authority(3, true)?;
        let before = std::fs::read(&wallet.path)?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        wallet.state.finding_challenge_clock = Arc::new(SignerWaitClock {
            clock: Arc::clone(&wallet.state.finding_challenge_clock),
            reads: AtomicUsize::new(0),
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(wait),
        });
        let headers = wallet.headers(&wallet.token)?;
        let state = wallet.state.clone();
        let payload = wallet.request();
        let response = tokio::spawn(async move {
            handle_redeem_passport_issuance_credential(State(state), headers, Json(payload)).await
        });
        tokio::time::timeout(HANG_GUARD, observed).await??;
        wallet.expired().await?;
        release.send(())?;
        let response = tokio::time::timeout(HANG_GUARD, response).await??;
        refused(
            &wallet,
            response,
            StatusCode::UNAUTHORIZED,
            "access token entitlement has expired",
            &before,
        )
        .await
    })
}

struct UnavailableClock;
impl chio_security_types::clock::Clock for UnavailableClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        Err(chio_security_types::clock::ClockError::Unavailable)
    }
}

#[test]
fn final_wallet_queued_expiry_clock_error_refuses_without_registry_mutation() -> TestResult {
    let runtime = runtime()?;
    runtime.block_on(async {
        let mut wallet = Wallet::new(3_600)?;
        let before = std::fs::read(&wallet.path)?;
        wallet.state.finding_challenge_clock = Arc::new(UnavailableClock);
        let responses = vec![
            handle_create_passport_issuance_offer(
                State(wallet.state.clone()),
                wallet.headers("service-secret")?,
                Json(CreatePassportIssuanceOfferRequest {
                    passport: wallet.passport.clone(),
                    ttl_seconds: 60,
                    credential_configuration_id: Some(
                        CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
                    ),
                }),
            )
            .await,
            handle_redeem_passport_issuance_token(
                State(wallet.state.clone()),
                Json(Oid4vciTokenRequest {
                    grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
                    pre_authorized_code: wallet.code.clone(),
                }),
            )
            .await,
            handle_redeem_passport_issuance_credential(
                State(wallet.state.clone()),
                wallet.headers(&wallet.token)?,
                Json(wallet.request()),
            )
            .await,
        ];
        for response in responses {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body = axum::body::to_bytes(response.into_body(), 4096).await?;
            assert_eq!(
                serde_json::from_slice::<Value>(&body)?,
                json!({"error":
                chio_security_types::clock::ClockError::Unavailable.code()})
            );
            assert_eq!(std::fs::read(&wallet.path)?, before);
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&polls);
        let body = Body::from_stream(futures_util::stream::once(async move {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{}"))
        }));
        let request = Request::builder()
            .method("POST")
            .uri(PASSPORT_ISSUANCE_CREDENTIAL_PATH)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", wallet.token))
            .body(body)?;
        let response = super::super::build_router(wallet.state.clone())
            .oneshot(request)
            .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read(&wallet.path)?, before);
        Ok(())
    })
}
