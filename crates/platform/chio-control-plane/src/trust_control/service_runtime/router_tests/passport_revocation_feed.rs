use std::io::Write as _;
use std::path::{Path, PathBuf};

use chio_credentials::{
    PassportLifecycleRecord, PassportLifecycleState, PassportStatusDistribution,
};
use chio_revocation_oracle::SignedEpochRoot;
use chio_security_types::clock::FixedClock;

use super::*;
use crate::partner_card::{PartnerCard, PartnerFederationPolicy};
use crate::passport_revocation::revoke_passport_status;
use crate::passport_revocation_feed::{
    passport_revocation_root_verifier, PassportRevocationLeavesPage,
    PASSPORT_REVOCATION_LEAVES_SCHEMA,
};
use crate::passport_revocation_mirror::{
    partner_revocation_mirror_path, PartnerRevocationError, PartnerRevocationMirror,
};
use crate::passport_verifier::PassportStatusRegistry;
use crate::trust_control::service_runtime::router::build_router;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PASSPORT: &str = "sha256:federated-passport";
const NOW_MS: u64 = 1_800_000_000_000;

struct Partner {
    _dir: tempfile::TempDir,
    registry: PathBuf,
    authority: Keypair,
    state: TrustServiceState,
}

fn write_seed(path: &Path, authority: &Keypair) -> TestResult {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(authority.seed_hex().as_bytes())?;
    Ok(())
}

fn did(seed: u8) -> Result<String, Box<dyn std::error::Error>> {
    Ok(
        chio_did::DidChio::from_public_key(Keypair::from_seed(&[seed; 32]).public_key())?
            .to_string(),
    )
}

fn partner() -> Result<Partner, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    let seed = dir.path().join("authority.seed");
    let authority = Keypair::from_seed(&[31; 32]);
    write_seed(&seed, &authority)?;
    let record = PassportLifecycleRecord {
        passport_id: PASSPORT.to_owned(),
        subject: did(3)?,
        issuers: vec![did(4)?],
        issuer_count: 1,
        published_at: 1_000,
        updated_at: 1_000,
        status: PassportLifecycleState::Active,
        superseded_by: None,
        revoked_at: None,
        revoked_reason: None,
        distribution: PassportStatusDistribution::default(),
        valid_until: "2099-01-01T00:00:00Z".to_owned(),
    };
    PassportStatusRegistry::update(&registry, |lifecycle| {
        lifecycle.passports.insert(PASSPORT.to_owned(), record);
        Ok(())
    })?;
    let mut state = metrics_state("service-secret");
    state.finding_challenge_clock = Arc::new(FixedClock::from_millis(NOW_MS));
    state.config.passport_statuses_file = Some(registry.clone());
    state.config.authority_seed_path = Some(seed);
    Ok(Partner {
        _dir: dir,
        registry,
        authority,
        state,
    })
}

fn card(authority: &Keypair) -> PartnerCard {
    PartnerCard {
        partner_id: "acme".to_owned(),
        trust_control_url: "https://trust.acme.example".to_owned(),
        authority_public_key: authority.public_key(),
        federation_policy: PartnerFederationPolicy {
            revocation_freshness_ttl_seconds: Some(60),
        },
    }
}

async fn get(
    state: &TrustServiceState,
    uri: &str,
) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error>> {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .body(axum::body::Body::empty())?;
    let response = build_router(state.clone()).oneshot(request).await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok((status, body.to_vec()))
}

async fn serve(
    state: TrustServiceState,
) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _served = axum::serve(listener, build_router(state)).await;
    });
    Ok(addr)
}

fn loopback_sync(
    addr: std::net::SocketAddr,
    mirror: &PartnerRevocationMirror,
    card: &PartnerCard,
) -> Result<chio_revocation_oracle::EpochRoot, PartnerRevocationError> {
    let deadline = PortableFetchDeadline::start()
        .map_err(|error| PartnerRevocationError::Fetch("acme".to_owned(), error.to_string()))?;
    let agent = build_portable_fetch_agent(vec![addr], false, &deadline)
        .map_err(|error| PartnerRevocationError::Fetch("acme".to_owned(), error.to_string()))?;
    let mut feed = PartnerRevocationFeed::new("acme", &format!("http://{addr}"), agent);
    mirror.sync(card, &mut feed, &FixedClock::from_millis(NOW_MS))
}

#[tokio::test]
async fn the_root_route_signs_the_oracle_root_with_the_authority_key() -> TestResult {
    let partner = partner()?;
    revoke_passport_status(
        &partner.registry,
        PASSPORT,
        Some("compromised"),
        Some(2_000),
    )?;
    let (status, body) = get(&partner.state, PUBLIC_PASSPORT_REVOCATION_ROOT_PATH).await?;
    assert_eq!(status, StatusCode::OK);
    let signed: SignedEpochRoot = serde_json::from_slice(&body)?;
    signed.verify(&passport_revocation_root_verifier(
        &partner.authority.public_key(),
    ))?;
    assert_eq!(signed.root.leaf_count, 1);
    Ok(())
}

#[tokio::test]
async fn the_leaves_route_pages_from_a_required_cursor() -> TestResult {
    let partner = partner()?;
    revoke_passport_status(&partner.registry, PASSPORT, None, Some(2_000))?;
    let (status, body) = get(
        &partner.state,
        &format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=0"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let page: PassportRevocationLeavesPage = serde_json::from_slice(&body)?;
    assert_eq!(page.schema, PASSPORT_REVOCATION_LEAVES_SCHEMA);
    assert_eq!(page.leaves.len(), 1);
    assert_eq!(page.leaves[0].subject, PASSPORT);

    for uri in [
        PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH.to_owned(),
        format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=-1"),
        format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=0&limit=5"),
    ] {
        let (status, _) = get(&partner.state, &uri).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn the_feed_refuses_without_a_lifecycle_registry() -> TestResult {
    let mut partner = partner()?;
    partner.state.config.passport_statuses_file = None;
    for uri in [
        PUBLIC_PASSPORT_REVOCATION_ROOT_PATH.to_owned(),
        format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=0"),
    ] {
        let (status, body) = get(&partner.state, &uri).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{uri}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?["error"],
            "passport revocation feed requires --passport-statuses-file"
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_root_route_refuses_without_an_authority() -> TestResult {
    let mut partner = partner()?;
    partner.state.config.authority_seed_path = None;
    let (status, body) = get(&partner.state, PUBLIC_PASSPORT_REVOCATION_ROOT_PATH).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body)?["error"],
        "passport revocation feed requires a configured trust-control authority"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_at_the_partner_reaches_the_mirror_over_http() -> TestResult {
    let partner = partner()?;
    let card = card(&partner.authority);
    let registry = partner.registry.clone();
    let addr = serve(partner.state.clone()).await?;
    let dir = tempfile::tempdir()?;
    let mirror_path =
        partner_revocation_mirror_path(&dir.path().join("b-passport-statuses.json"), "acme")?;

    let (first, second) = tokio::task::spawn_blocking(move || {
        let mirror = PartnerRevocationMirror::open(&mirror_path, "acme")?;
        loopback_sync(addr, &mirror, &card)?;
        let first = mirror.check_passport(&card, PASSPORT, NOW_MS);
        revoke_passport_status(&registry, PASSPORT, Some("compromised"), Some(2_000))
            .map_err(|error| PartnerRevocationError::Fetch("acme".to_owned(), error.to_string()))?;
        loopback_sync(addr, &mirror, &card)?;
        Ok::<_, PartnerRevocationError>((first, mirror.check_passport(&card, PASSPORT, NOW_MS)))
    })
    .await??;
    assert_eq!(first, Ok(()));
    assert_eq!(
        second,
        Err(PartnerRevocationError::Revoked {
            partner_id: "acme".to_owned(),
            passport_id: PASSPORT.to_owned(),
        })
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_strict_transport_refuses_a_loopback_partner_before_any_fetch() -> TestResult {
    let partner = partner()?;
    let addr = serve(partner.state.clone()).await?;
    let mut card = card(&partner.authority);
    card.trust_control_url = format!("https://{addr}");
    let dir = tempfile::tempdir()?;
    let mirror_path =
        partner_revocation_mirror_path(&dir.path().join("b-passport-statuses.json"), "acme")?;
    let clock: Arc<dyn chio_security_types::clock::Clock> =
        Arc::new(FixedClock::from_millis(NOW_MS));
    let synced = {
        let mirror_path = mirror_path.clone();
        tokio::task::spawn_blocking(move || {
            sync_partner_revocation_mirror(card, mirror_path, clock)
        })
        .await?
    };
    assert!(
        matches!(&synced, Err(PartnerRevocationError::Fetch(partner_id, reason))
            if partner_id == "acme" && reason.to_lowercase().contains("loopback")),
        "{synced:?}"
    );
    assert!(!mirror_path.exists());
    Ok(())
}
