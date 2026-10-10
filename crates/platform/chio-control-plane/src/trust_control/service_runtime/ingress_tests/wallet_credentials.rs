//! Wallet access tokens must be entitled before the credential upload is polled.
use super::*;
use crate::passport_verifier::{PassportIssuanceOfferRegistry, PassportIssuanceOfferState};
use chio_credentials::{
    build_agent_passport, default_oid4vci_passport_issuer_metadata, issue_reputation_credential,
    AttestationWindow, ChioCredentialEvidence, Oid4vciCredentialRequest, Oid4vciTokenRequest,
    CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID, CHIO_PASSPORT_OID4VCI_FORMAT,
    OID4VCI_PRE_AUTHORIZED_GRANT_TYPE,
};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[cfg(unix)]
#[path = "wallet_ingress.rs"]
mod wallet_ingress;

struct WalletFixture {
    _directory: tempfile::TempDir,
    registry_path: std::path::PathBuf,
    seed_path: std::path::PathBuf,
    state: TrustServiceState,
    token: String,
}

impl WalletFixture {
    fn new(offer_age: u64, offer_ttl: u64, token_ttl: u64) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let registry_path = directory.path().join("wallet-offers.json");
        let seed_path = directory.path().join("unused-signing-seed");
        let now = unix_timestamp_now()?;
        let issued_at = now
            .checked_sub(offer_age)
            .ok_or("test clock before offer age")?;
        let subject = Keypair::from_seed(&[93; 32]);
        let scorecard = chio_reputation::compute_local_scorecard(
            &subject.public_key().to_hex(),
            issued_at,
            &chio_reputation::LocalReputationCorpus::default(),
            &chio_reputation::ReputationConfig::default(),
        );
        let credential = issue_reputation_credential(
            &Keypair::from_seed(&[94; 32]),
            scorecard,
            ChioCredentialEvidence {
                query: AttestationWindow {
                    since: None,
                    until: issued_at,
                },
                receipt_count: 0,
                receipt_ids: Vec::new(),
                checkpoint_roots: Vec::new(),
                receipt_log_urls: Vec::new(),
                lineage_records: 0,
                uncheckpointed_receipts: 0,
                runtime_attestation: None,
            },
            issued_at,
            now.checked_add(7_200).ok_or("test clock overflow")?,
        )?;
        let subject_did = credential.unsigned.credential_subject.id.clone();
        let passport = build_agent_passport(&subject_did, vec![credential])?;
        let metadata = default_oid4vci_passport_issuer_metadata("https://wallet.example.test")?;
        let mut registry = PassportIssuanceOfferRegistry::default();
        let offer = registry.issue_offer(&metadata, passport, None, offer_ttl, issued_at)?;
        let response = registry.redeem_pre_authorized_code(
            &metadata,
            &Oid4vciTokenRequest {
                grant_type: OID4VCI_PRE_AUTHORIZED_GRANT_TYPE.into(),
                pre_authorized_code: offer.offer.pre_authorized_code()?.into(),
            },
            issued_at,
            token_ttl,
        )?;
        std::fs::write(&registry_path, canonical_json_bytes(&registry)?)?;
        assert_eq!(
            PassportIssuanceOfferRegistry::load(&registry_path)?,
            registry
        );
        let mut state = metrics_state("service-secret");
        state.config.advertise_url = Some("https://wallet.example.test/".into());
        state.config.passport_issuance_offers_file = Some(registry_path.clone());
        // A duplicate must be rejected before the normal metadata/signing path
        // can create this configured seed. Entitlement has no signing dependency.
        state.config.authority_seed_path = Some(seed_path.clone());
        Ok(Self {
            _directory: directory,
            registry_path,
            seed_path,
            state,
            token: response.access_token,
        })
    }

    fn live() -> TestResult<Self> {
        Self::new(0, 3_600, 3_600)
    }

    fn rewrite_state(&self, state: PassportIssuanceOfferState) -> TestResult {
        let mut registry = PassportIssuanceOfferRegistry::load(&self.registry_path)?;
        let record = registry
            .offers
            .values_mut()
            .next()
            .ok_or("missing test offer")?;
        record.state = state;
        record.credential_issued_at = (state == PassportIssuanceOfferState::CredentialIssued)
            .then_some(unix_timestamp_now()?);
        std::fs::write(&self.registry_path, canonical_json_bytes(&registry)?)?;
        assert_eq!(
            PassportIssuanceOfferRegistry::load(&self.registry_path)?,
            registry
        );
        Ok(())
    }

    async fn submit(
        &self,
        credential: Option<&str>,
        expected: StatusCode,
        expected_polls: usize,
    ) -> TestResult {
        let before = std::fs::read(&self.registry_path)?;
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let stream = futures_util::stream::once(async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
                br#"{"ignored":1,"ignored":2}"#,
            ))
        });
        let mut request = Request::builder()
            .method("POST")
            .uri(PASSPORT_ISSUANCE_CREDENTIAL_PATH)
            .header(CONTENT_TYPE, "application/json");
        if let Some(credential) = credential {
            request = request.header(AUTHORIZATION, credential);
        }
        let response = super::super::super::build_router(self.state.clone())
            .oneshot(request.body(Body::from_stream(stream))?)
            .await?;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
        assert_eq!(polls.load(Ordering::SeqCst), expected_polls);
        assert_eq!(std::fs::read(&self.registry_path)?, before);
        assert!(
            !self.seed_path.exists(),
            "pre-body authorization created signing material"
        );
        Ok(())
    }
}

#[tokio::test]
async fn wallet_missing_or_malformed_bearer_never_polls_body() -> TestResult {
    let fixture = WalletFixture::live()?;
    for credential in [
        None,
        Some("Basic malformed"),
        Some("Bearer "),
        Some("bearer malformed"),
    ] {
        fixture
            .submit(credential, StatusCode::UNAUTHORIZED, 0)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn wallet_forged_or_service_bearer_never_polls_body() -> TestResult {
    let fixture = WalletFixture::live()?;
    for credential in [
        "Bearer forged-wallet-token",
        "Bearer service-secret",
        "Bearer workload-secret",
    ] {
        fixture
            .submit(Some(credential), StatusCode::UNAUTHORIZED, 0)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn wallet_expired_offer_or_token_never_polls_or_refreshes_registry() -> TestResult {
    for fixture in [
        WalletFixture::new(600, 3_600, 60)?,
        WalletFixture::new(600, 60, 60)?,
    ] {
        let credential = format!("Bearer {}", fixture.token);
        fixture
            .submit(Some(&credential), StatusCode::UNAUTHORIZED, 0)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn wallet_consumed_or_unissued_entitlement_never_polls_body() -> TestResult {
    for state in [
        PassportIssuanceOfferState::CredentialIssued,
        PassportIssuanceOfferState::Offered,
    ] {
        let fixture = WalletFixture::live()?;
        fixture.rewrite_state(state)?;
        let credential = format!("Bearer {}", fixture.token);
        fixture
            .submit(Some(&credential), StatusCode::UNAUTHORIZED, 0)
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn wallet_issuer_binding_is_checked_before_body_without_signing() -> TestResult {
    let mut fixture = WalletFixture::live()?;
    fixture.state.config.advertise_url = Some("https://another-issuer.example.test".into());
    let credential = format!("Bearer {}", fixture.token);
    fixture
        .submit(Some(&credential), StatusCode::UNAUTHORIZED, 0)
        .await?;
    Ok(())
}

#[tokio::test]
async fn wallet_live_opaque_token_keeps_duplicate_validation_and_storage() -> TestResult {
    let fixture = WalletFixture::live()?;
    let credential = format!("Bearer {}", fixture.token);
    fixture
        .submit(Some(&credential), StatusCode::BAD_REQUEST, 1)
        .await?;
    Ok(())
}

#[tokio::test]
async fn wallet_entitlement_is_rechecked_after_upload_without_consumption() -> TestResult {
    let mut fixture = WalletFixture::live()?;
    fixture.state.config.authority_seed_path = None;
    let mut consumed = PassportIssuanceOfferRegistry::load(&fixture.registry_path)?;
    let record = consumed
        .offers
        .values_mut()
        .next()
        .ok_or("missing test offer")?;
    let body = canonical_json_bytes(&Oid4vciCredentialRequest {
        credential_configuration_id: Some(CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.into()),
        format: Some(CHIO_PASSPORT_OID4VCI_FORMAT.into()),
        subject: record.passport.subject.clone(),
    })?;
    record.state = PassportIssuanceOfferState::CredentialIssued;
    record.credential_issued_at = Some(unix_timestamp_now()?);
    let consumed_bytes = canonical_json_bytes(&consumed)?;
    let upload_registry = fixture.registry_path.clone();
    let upload_bytes = consumed_bytes.clone();
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let stream = futures_util::stream::once(async move {
        observed.fetch_add(1, Ordering::SeqCst);
        // Another redemption wins after the early entitlement check but before
        // this request completes its upload. The handler must read fresh state.
        std::fs::write(upload_registry, upload_bytes)?;
        Ok::<_, std::io::Error>(axum::body::Bytes::from(body))
    });
    let request = Request::builder()
        .method("POST")
        .uri(PASSPORT_ISSUANCE_CREDENTIAL_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", fixture.token))
        .body(Body::from_stream(stream))?;
    let response = super::super::super::build_router(fixture.state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    let refusal = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(&fixture.registry_path)?, consumed_bytes);
    assert!(!fixture.seed_path.exists());
    Ok(())
}

#[tokio::test]
async fn wallet_consumed_during_upload_cannot_create_signing_seed() -> TestResult {
    let fixture = WalletFixture::live()?;
    let mut consumed = PassportIssuanceOfferRegistry::load(&fixture.registry_path)?;
    let record = consumed
        .offers
        .values_mut()
        .next()
        .ok_or("missing test offer")?;
    let body = canonical_json_bytes(&Oid4vciCredentialRequest {
        credential_configuration_id: Some(CHIO_PASSPORT_OID4VCI_CREDENTIAL_CONFIGURATION_ID.into()),
        format: Some(CHIO_PASSPORT_OID4VCI_FORMAT.into()),
        subject: record.passport.subject.clone(),
    })?;
    record.state = PassportIssuanceOfferState::CredentialIssued;
    record.credential_issued_at = Some(unix_timestamp_now()?);
    let consumed_bytes = canonical_json_bytes(&consumed)?;
    let upload_registry = fixture.registry_path.clone();
    let upload_bytes = consumed_bytes.clone();
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let stream = futures_util::stream::once(async move {
        observed.fetch_add(1, Ordering::SeqCst);
        // Another redemption wins after the early entitlement check but before
        // this request completes its upload. The handler must read fresh state.
        std::fs::write(upload_registry, upload_bytes)?;
        Ok::<_, std::io::Error>(axum::body::Bytes::from(body))
    });
    let request = Request::builder()
        .method("POST")
        .uri(PASSPORT_ISSUANCE_CREDENTIAL_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", fixture.token))
        .body(Body::from_stream(stream))?;
    let response = super::super::super::build_router(fixture.state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    let refusal = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "{}",
        String::from_utf8_lossy(&refusal)
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(&fixture.registry_path)?, consumed_bytes);
    assert!(
        !fixture.seed_path.exists(),
        "consumed upload created signing material before fresh entitlement denial"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[path = "wallet_entitlement_admission.rs"]
mod wallet_entitlement_admission;
