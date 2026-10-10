//! Issuer operations bind their actual private key to the admitted head and
//! live set before their surrounding file transaction persists any result.

use super::*;
use chio_credentials::{
    Oid4vciCredentialResponse, Oid4vciTokenResponse,
    CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_SD_JWT_VC_FORMAT,
    OID4VCI_PRE_AUTHORIZED_GRANT_TYPE,
};

struct IssuerFixture {
    _directory: tempfile::TempDir,
    state: TrustServiceState,
    offers: PathBuf,
    passport: chio_credentials::AgentPassport,
    credential_offer: PassportIssuanceOfferRecord,
    credential_token: String,
    waiting_code: String,
    actual: PublicKey,
    admitted: PublicKey,
}

impl IssuerFixture {
    fn new(recover: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let authority_path = directory.path().join("custodian.sqlite3");
        let offers = directory.path().join("offers.json");
        let mut state = metrics_state("service-secret");
        state.finding_challenge_clock = chio_test_support::clock::clock();
        state.config.advertise_url = Some(ADVERTISE_URL.to_string());
        state.config.authority_db_path = Some(authority_path.clone());
        state.config.passport_issuance_offers_file = Some(offers.clone());
        let custodian = SqliteCapabilityAuthority::open_with_clock(
            &authority_path,
            Arc::clone(&state.finding_challenge_clock),
        )?;
        let actual = custodian.local_keypair()?.public_key();
        let recovery_root = Keypair::from_seed(&[99; 32]);
        let anchor = custodian.initialize_replication_with_recovery(
            "issuer-binding",
            Some(&recovery_root.public_key()),
        )?;
        let metadata = configured_passport_credential_issuer(&state.config)?;
        let now = chio_test_support::clock::unix_seconds();
        let passport = issuable_passport(now)?;
        let mut registry = PassportIssuanceOfferRegistry::default();
        let credential_offer = registry.issue_offer(
            &metadata,
            passport.clone(),
            Some(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID),
            3_600,
            now,
        )?;
        let credential_token = registry
            .redeem_pre_authorized_code(
                &metadata,
                &Oid4vciTokenRequest {
                    grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
                    pre_authorized_code: credential_offer.offer.pre_authorized_code()?.to_string(),
                },
                now,
                3_600,
            )?
            .access_token;
        let waiting = registry.issue_offer(
            &metadata,
            passport.clone(),
            Some(CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID),
            3_600,
            now,
        )?;
        let waiting_code = waiting.offer.pre_authorized_code()?.to_string();
        registry.save_for_issuance(&offers)?;
        let admitted = if recover {
            let recovered = SqliteCapabilityAuthority::open_with_clock(
                directory.path().join("recovered.sqlite3"),
                Arc::clone(&state.finding_challenge_clock),
            )?;
            recovered.pin_replication_anchor(&anchor)?;
            recovered.apply_signed_snapshot(&custodian.signed_snapshot()?)?;
            recovered.recover_authority(&recovery_root)?;
            let admitted = recovered.status()?.public_key;
            custodian.apply_signed_snapshot(&recovered.signed_snapshot()?)?;
            admitted
        } else {
            actual.clone()
        };
        // Selection is asserted through the exact loaders used by unchanged
        // handlers. A fixture that naturally selects the head does not prove
        // this boundary and must not be labelled a signer-binding Original.
        assert_eq!(
            resolve_oid4vp_verifier_signing_key(&state.config)?.public_key(),
            actual
        );
        assert_eq!(
            crate::trust_control::config_and_public::resolve_public_registry_signing_key(
                &state.config,
                &state.finding_challenge_clock
            )?
            .public_key(),
            actual
        );
        let status =
            crate::trust_control::report_validation::load_authority_status_for_state(&state)
                .map_err(|response| {
                    format!("fixture admitted read refused: {}", response.status())
                })?;
        assert_eq!(
            status.public_key.as_deref(),
            Some(admitted.to_hex().as_str())
        );
        assert_eq!(status.trusted_public_keys, vec![admitted.to_hex()]);
        if recover {
            assert_ne!(actual, admitted);
        }
        Ok(Self {
            _directory: directory,
            state,
            offers,
            passport,
            credential_offer,
            credential_token,
            waiting_code,
            actual,
            admitted,
        })
    }

    fn headers(token: &str) -> Result<HeaderMap, Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        Ok(headers)
    }

    async fn create(&self) -> Response {
        handle_create_passport_issuance_offer(
            State(self.state.clone()),
            Self::headers("service-secret").test_unwrap(),
            Json(CreatePassportIssuanceOfferRequest {
                passport: self.passport.clone(),
                ttl_seconds: 3_600,
                credential_configuration_id: Some(
                    CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
                ),
            }),
        )
        .await
    }

    async fn token(&self) -> Response {
        handle_redeem_passport_issuance_token(
            State(self.state.clone()),
            Json(Oid4vciTokenRequest {
                grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
                pre_authorized_code: self.waiting_code.clone(),
            }),
        )
        .await
    }

    async fn credential(&self) -> Response {
        handle_redeem_passport_issuance_credential(
            State(self.state.clone()),
            Self::headers(&self.credential_token).test_unwrap(),
            Json(Oid4vciCredentialRequest {
                credential_configuration_id: Some(
                    CHIO_PASSPORT_SD_JWT_VC_CREDENTIAL_CONFIGURATION_ID.to_string(),
                ),
                format: Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string()),
                subject: self.credential_offer.passport.subject.clone(),
            }),
        )
        .await
    }

    async fn assert_refused(&self, response: Response, before: &[u8]) -> TestResult {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "admitted head {} excludes selected {}, but issuer returned {}: {}",
            self.admitted.to_hex(),
            self.actual.to_hex(),
            status,
            String::from_utf8_lossy(&body)
        );
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(value.get("error").is_some());
        assert!(value.get("credential").is_none());
        assert!(value.get("accessToken").is_none());
        assert!(value.get("offer").is_none());
        assert_eq!(std::fs::read(&self.offers)?, before);
        Ok(())
    }
}

#[tokio::test]
async fn an_unadmitted_actual_signer_cannot_create_a_portable_offer() -> TestResult {
    let fixture = IssuerFixture::new(true)?;
    let before = std::fs::read(&fixture.offers)?;
    fixture
        .assert_refused(fixture.create().await, &before)
        .await
}

#[tokio::test]
async fn an_unadmitted_actual_signer_cannot_redeem_a_code() -> TestResult {
    let fixture = IssuerFixture::new(true)?;
    let before = std::fs::read(&fixture.offers)?;
    fixture.assert_refused(fixture.token().await, &before).await
}

#[tokio::test]
async fn an_unadmitted_actual_signer_cannot_issue_a_portable_credential() -> TestResult {
    let fixture = IssuerFixture::new(true)?;
    let before = std::fs::read(&fixture.offers)?;
    fixture
        .assert_refused(fixture.credential().await, &before)
        .await
}

#[tokio::test]
async fn current_custodian_issuer_operations_progress_and_bind_the_credential_key() -> TestResult {
    let fixture = IssuerFixture::new(false)?;
    assert_eq!(fixture.create().await.status(), StatusCode::OK);
    let response = fixture.token().await;
    assert_eq!(response.status(), StatusCode::OK);
    let _: Oid4vciTokenResponse =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await?)?;
    let response = fixture.credential().await;
    assert_eq!(response.status(), StatusCode::OK);
    let response: Oid4vciCredentialResponse =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await?)?;
    response.validate(
        chio_test_support::clock::unix_seconds(),
        Some(CHIO_PASSPORT_SD_JWT_VC_FORMAT),
        Some(&fixture.passport.subject),
    )?;
    let key = response
        .chio_credential_context
        .as_ref()
        .and_then(|context| context.issuer_jwk.as_ref())
        .ok_or("portable response omitted issuer key")?
        .to_public_key()?;
    assert_eq!(key, fixture.admitted);
    Ok(())
}

#[tokio::test]
async fn unconfigured_unsigned_issuer_operations_keep_the_legacy_profile() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("unsigned-offers.json");
    let mut state = metrics_state("service-secret");
    state.config.advertise_url = Some(ADVERTISE_URL.to_string());
    state.config.passport_issuance_offers_file = Some(path.clone());
    let response = handle_create_passport_issuance_offer(
        State(state.clone()),
        IssuerFixture::headers("service-secret")?,
        Json(CreatePassportIssuanceOfferRequest {
            passport: issuable_passport(chio_test_support::clock::unix_seconds())?,
            ttl_seconds: 3_600,
            credential_configuration_id: None,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let offer: PassportIssuanceOfferRecord =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await?)?;
    let response = handle_redeem_passport_issuance_token(
        State(state.clone()),
        Json(Oid4vciTokenRequest {
            grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.to_string(),
            pre_authorized_code: offer.offer.pre_authorized_code()?.to_string(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let token: Oid4vciTokenResponse =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await?)?;
    let response = handle_redeem_passport_issuance_credential(
        State(state),
        IssuerFixture::headers(&token.access_token)?,
        Json(Oid4vciCredentialRequest {
            credential_configuration_id: Some(
                chio_credentials::CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.to_string(),
            ),
            format: Some(chio_credentials::CHIO_PASSPORT_OID4VCI_FORMAT.to_string()),
            subject: offer.passport.subject,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response: Oid4vciCredentialResponse =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1024 * 1024).await?)?;
    assert!(response
        .chio_credential_context
        .as_ref()
        .and_then(|context| context.issuer_jwk.as_ref())
        .is_none());
    assert!(PassportIssuanceOfferRegistry::load(&path)?
        .offers
        .is_empty());
    Ok(())
}

/// A source-specific fixture seam: each inspection constructor and its lookup
/// read the explicit authority clock. Key selection is reads 1-2, guard pre-view
/// 3-4, pre-binding 5-6, then post-binding starts at read 7 after the real
/// credential construction callback returns. Refusal completes at read 8.
/// This count describes this owning implementation, not a protocol guarantee.
struct PausePostSignerRead {
    inner: Arc<dyn chio_security_types::clock::Clock>,
    reads: std::sync::atomic::AtomicUsize,
    reached: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl chio_security_types::clock::Clock for PausePostSignerRead {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        use chio_security_types::clock::ClockError;
        let read = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if read == 7 {
            self.reached.send(()).map_err(|_| ClockError::Unavailable)?;
            self.release
                .lock()
                .map_err(|_| ClockError::Unavailable)?
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| ClockError::Unavailable)?;
        }
        self.inner.read()
    }
}

#[tokio::test]
async fn a_rotation_after_provisional_credential_construction_refuses_without_consuming_entitlement(
) -> TestResult {
    let mut fixture = IssuerFixture::new(false)?;
    let original = std::fs::read(&fixture.offers)?;
    let authority_path = fixture
        .state
        .config
        .authority_db_path
        .clone()
        .ok_or("missing authority path")?;
    let (reached, reached_rx) = std::sync::mpsc::channel();
    let (release_tx, release) = std::sync::mpsc::channel();
    let clock = Arc::new(PausePostSignerRead {
        inner: Arc::clone(&fixture.state.finding_challenge_clock),
        reads: std::sync::atomic::AtomicUsize::new(0),
        reached,
        release: std::sync::Mutex::new(release),
    });
    fixture.state.finding_challenge_clock = clock.clone();
    let offers = fixture.offers.clone();
    let token = fixture.credential_token.clone();
    let observed_clock = Arc::clone(&clock);
    let rotation = std::thread::spawn(move || {
        let outcome = (|| -> Result<(Vec<u8>, bool, PublicKey, PublicKey, usize), String> {
            reached_rx
                .recv_timeout(Duration::from_secs(30))
                .map_err(|error| error.to_string())?;
            let reads_at_pause = observed_clock
                .reads
                .load(std::sync::atomic::Ordering::SeqCst);
            let before = std::fs::read(&offers).map_err(|error| error.to_string())?;
            let registry =
                PassportIssuanceOfferRegistry::load(&offers).map_err(|error| error.to_string())?;
            let entitled = registry
                .validate_credential_entitlement(
                    ADVERTISE_URL,
                    &token,
                    chio_test_support::clock::unix_seconds(),
                )
                .is_ok();
            let authority = SqliteCapabilityAuthority::open(&authority_path)
                .map_err(|error| error.to_string())?;
            let selected = authority
                .local_keypair()
                .map_err(|error| error.to_string())?
                .public_key();
            let rotated = authority
                .rotate()
                .map_err(|error| error.to_string())?
                .public_key;
            Ok((before, entitled, selected, rotated, reads_at_pause))
        })();
        let _ = release_tx.send(());
        outcome
    });
    let response = tokio::time::timeout(Duration::from_secs(35), fixture.credential()).await?;
    let (paused_bytes, entitled_at_pause, selected_at_pause, rotated, reads_at_pause) =
        rotation.join().map_err(|_| "rotation worker panicked")??;
    assert_eq!(
        reads_at_pause, 7,
        "the real callback did not reach its post-construction inspection"
    );
    assert_eq!(
        clock.reads.load(std::sync::atomic::Ordering::SeqCst),
        8,
        "the refused post-binding lookup did not complete at the documented source boundary"
    );
    assert_eq!(selected_at_pause, fixture.actual);
    assert_ne!(rotated, fixture.actual);
    assert!(
        entitled_at_pause,
        "credential was consumed before the post-construction guard"
    );
    assert_eq!(
        paused_bytes, original,
        "provisional callback persisted before its authority post-check"
    );
    fixture.assert_refused(response, &original).await?;
    let status =
        crate::trust_control::report_validation::load_authority_status_for_state(&fixture.state)
            .map_err(|response| format!("rotated status refused: {}", response.status()))?;
    assert_eq!(
        status.public_key.as_deref(),
        Some(rotated.to_hex().as_str())
    );
    let reopened = PassportIssuanceOfferRegistry::load(&fixture.offers)?;
    assert!(reopened
        .validate_credential_entitlement(
            ADVERTISE_URL,
            &fixture.credential_token,
            chio_test_support::clock::unix_seconds()
        )
        .is_ok());
    Ok(())
}
