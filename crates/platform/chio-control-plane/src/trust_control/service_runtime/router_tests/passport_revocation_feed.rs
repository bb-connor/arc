use std::io::Write as _;
use std::path::{Path, PathBuf};

use chio_credentials::{
    PassportLifecycleRecord, PassportLifecycleState, PassportStatusDistribution,
};
use chio_security_types::clock::FixedClock;

use super::*;
use crate::passport_revocation::revoke_passport_status;
use crate::passport_revocation_feed::{
    passport_revocation_root_verifier, PassportRevocationLeavesPage,
    PassportRevocationRootDocument, PASSPORT_REVOCATION_LEAVES_SCHEMA,
};
use crate::passport_revocation_mirror::{
    partner_revocation_mirror_path, PartnerRevocationError, PartnerRevocationMirror,
};
use crate::passport_verifier::PassportStatusRegistry;
use crate::revocation_partner::RevocationPartner;
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

fn revocation_partner(authority: &Keypair) -> RevocationPartner {
    RevocationPartner {
        partner_id: "acme".to_owned(),
        issuer: "https://trust.acme.example".to_owned(),
        authority_public_key: authority.public_key(),
        revocation_freshness_ttl_seconds: Some(60),
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
    revocation_partner: &RevocationPartner,
) -> Result<chio_revocation_oracle::EpochRoot, PartnerRevocationError> {
    let deadline = PortableFetchDeadline::start()
        .map_err(|error| PartnerRevocationError::Fetch("acme".to_owned(), error.to_string()))?;
    let agent = build_portable_fetch_agent(vec![addr], false, &deadline)
        .map_err(|error| PartnerRevocationError::Fetch("acme".to_owned(), error.to_string()))?;
    let mut feed = PartnerRevocationFeed::new("acme", &format!("http://{addr}"), agent);
    mirror.sync(
        revocation_partner,
        &mut feed,
        &FixedClock::from_millis(NOW_MS),
    )
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
    let document: PassportRevocationRootDocument = serde_json::from_slice(&body)?;
    assert_eq!(document.schema, "chio.trust.passport-revocation-root.v1");
    let signed = document.into_signed_root()?;
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
    let revocation_partner = revocation_partner(&partner.authority);
    let registry = partner.registry.clone();
    let addr = serve(partner.state.clone()).await?;
    let dir = tempfile::tempdir()?;
    let mirror_path =
        partner_revocation_mirror_path(&dir.path().join("b-revocation-partners.json"), "acme")?;

    let (first, second) = tokio::task::spawn_blocking(move || {
        let mirror = PartnerRevocationMirror::open(&mirror_path, "acme")?;
        loopback_sync(addr, &mirror, &revocation_partner)?;
        let first = mirror.check_passport(&revocation_partner, PASSPORT, NOW_MS);
        revoke_passport_status(&registry, PASSPORT, Some("compromised"), Some(2_000))
            .map_err(|error| PartnerRevocationError::Fetch("acme".to_owned(), error.to_string()))?;
        loopback_sync(addr, &mirror, &revocation_partner)?;
        Ok::<_, PartnerRevocationError>((
            first,
            mirror.check_passport(&revocation_partner, PASSPORT, NOW_MS),
        ))
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
    let mut revocation_partner = revocation_partner(&partner.authority);
    revocation_partner.issuer = format!("https://{addr}");
    let dir = tempfile::tempdir()?;
    let mirror_path =
        partner_revocation_mirror_path(&dir.path().join("b-revocation-partners.json"), "acme")?;
    let clock: Arc<dyn chio_security_types::clock::Clock> =
        Arc::new(FixedClock::from_millis(NOW_MS));
    let synced = {
        let mirror_path = mirror_path.clone();
        tokio::task::spawn_blocking(move || {
            sync_partner_revocation_mirror(revocation_partner, mirror_path, clock)
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

/// One settable time shared by partner A and verifier B.
struct SharedClock(std::sync::atomic::AtomicU64);

impl SharedClock {
    fn advance_to(&self, unix_ms: u64) {
        self.0.store(unix_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

impl chio_security_types::clock::Clock for SharedClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        Ok(chio_security_types::clock::ClockReading::new(
            chio_security_types::clock::UnixMillis::new(
                self.0.load(std::sync::atomic::Ordering::SeqCst),
            ),
            chio_security_types::clock::MonotonicInstant::from_nanos(0),
        ))
    }
}

struct Door {
    _dir: tempfile::TempDir,
    config: TrustServiceConfig,
    registry: PathBuf,
}

fn door(entries: serde_json::Value) -> Result<Door, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("revocation-partners.json");
    std::fs::write(
        &registry,
        serde_json::to_vec(&serde_json::json!({
            "schema": crate::revocation_partner::REVOCATION_PARTNER_REGISTRY_SCHEMA,
            "partners": entries,
        }))?,
    )?;
    let mut config = metrics_state("service-secret").config;
    config.revocation_partners_file = Some(registry.clone());
    Ok(Door {
        _dir: dir,
        config,
        registry,
    })
}

fn acme_entry(authority: &Keypair, issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "acme": {
            "partnerId": "acme",
            "issuer": issuer,
            "authorityPublicKey": authority.public_key().to_hex(),
            "revocationFreshnessTtlSeconds": 60,
        }
    })
}

const ACME: &str = "https://trust.acme.example";

fn shared_clock(state: &mut TrustServiceState) -> Arc<SharedClock> {
    let clock = Arc::new(SharedClock(std::sync::atomic::AtomicU64::new(NOW_MS)));
    state.finding_challenge_clock = clock.clone();
    clock
}

fn loopback_sync_with(
    addr: std::net::SocketAddr,
    clock: Arc<SharedClock>,
) -> impl Fn(&RevocationPartner, &Path) -> Result<(), PartnerRevocationError> {
    move |partner, path| {
        let mirror = PartnerRevocationMirror::open(path, &partner.partner_id)?;
        let deadline = PortableFetchDeadline::start()
            .map_err(|error| PartnerRevocationError::Fetch("acme".to_owned(), error.to_string()))?;
        let agent = build_portable_fetch_agent(vec![addr], false, &deadline)
            .map_err(|error| PartnerRevocationError::Fetch("acme".to_owned(), error.to_string()))?;
        let mut feed = PartnerRevocationFeed::new("acme", &format!("http://{addr}"), agent);
        mirror.sync(partner, &mut feed, clock.as_ref()).map(|_| ())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_door_denies_a_partner_revocation_once_the_mirror_window_lapses() -> TestResult {
    let mut partner = partner()?;
    let clock = shared_clock(&mut partner.state);
    let addr = serve(partner.state.clone()).await?;
    let door = door(acme_entry(&partner.authority, ACME))?;
    let registry = partner.registry.clone();
    let outcomes = tokio::task::spawn_blocking(move || {
        let dyn_clock: Arc<dyn chio_security_types::clock::Clock> = clock.clone();
        let syncs = std::cell::Cell::new(0_u32);
        let inner = loopback_sync_with(addr, clock.clone());
        let sync = |partner: &RevocationPartner, path: &Path| {
            syncs.set(syncs.get() + 1);
            inner(partner, path)
        };
        let check = || {
            check_partner_passport_revocation_with(
                &door.config,
                VerifiedPassportIssuer::Url(ACME),
                PASSPORT,
                &dyn_clock,
                &sync,
            )
            .map_err(|error| error.to_string())
        };
        let before = check();
        revoke_passport_status(
            &registry,
            PASSPORT,
            Some("compromised"),
            Some(1_799_999_990),
        )
        .map_err(|error| error.to_string())?;
        clock.advance_to(NOW_MS + 1_000);
        let within_window = check();
        clock.advance_to(NOW_MS + 61_000);
        let after_window = check();
        Ok::<_, String>((before, within_window, after_window, syncs.get()))
    })
    .await?
    .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    assert_eq!(outcomes.0, Ok(()));
    assert_eq!(outcomes.1, Ok(()));
    let denied = outcomes
        .2
        .err()
        .ok_or("the lapsed window must resync and deny")?;
    assert!(
        denied.contains(
            &PartnerRevocationError::Revoked {
                partner_id: "acme".to_owned(),
                passport_id: PASSPORT.to_owned(),
            }
            .to_string()
        ),
        "{denied}"
    );
    assert_eq!(outcomes.3, 2);
    Ok(())
}

#[test]
fn the_door_fails_closed_when_a_stale_partner_cannot_sync() -> TestResult {
    let authority = Keypair::from_seed(&[31; 32]);
    let door = door(acme_entry(&authority, ACME))?;
    let clock: Arc<dyn chio_security_types::clock::Clock> =
        Arc::new(FixedClock::from_millis(NOW_MS));
    let unreachable = PartnerRevocationError::Fetch("acme".to_owned(), "unreachable".to_owned());
    let refused = check_partner_passport_revocation_with(
        &door.config,
        VerifiedPassportIssuer::Url(ACME),
        PASSPORT,
        &clock,
        &|_, _| Err(unreachable.clone()),
    )
    .err()
    .ok_or("an unsyncable stale partner must refuse")?;
    assert!(
        refused.to_string().contains(&unreachable.to_string()),
        "{refused}"
    );
    Ok(())
}

#[test]
fn the_door_passes_issuers_outside_the_registry_and_services_without_one() -> TestResult {
    let authority = Keypair::from_seed(&[31; 32]);
    let mut door = door(acme_entry(&authority, ACME))?;
    let clock: Arc<dyn chio_security_types::clock::Clock> =
        Arc::new(FixedClock::from_millis(NOW_MS));
    let never = |_: &RevocationPartner, _: &Path| -> Result<(), PartnerRevocationError> {
        Err(PartnerRevocationError::Fetch(
            "acme".to_owned(),
            "no partner may sync".to_owned(),
        ))
    };
    check_partner_passport_revocation_with(
        &door.config,
        VerifiedPassportIssuer::Url("https://trust.other.example"),
        PASSPORT,
        &clock,
        &never,
    )?;
    check_partner_passport_revocation_with(
        &door.config,
        VerifiedPassportIssuer::Dids(&[did(9)?]),
        PASSPORT,
        &clock,
        &never,
    )?;
    door.config.revocation_partners_file = None;
    check_partner_passport_revocation_with(
        &door.config,
        VerifiedPassportIssuer::Url(ACME),
        PASSPORT,
        &clock,
        &never,
    )?;
    Ok(())
}

#[test]
fn the_door_rereads_the_registry_and_refuses_an_invalid_or_missing_one() -> TestResult {
    let authority = Keypair::from_seed(&[31; 32]);
    let door = door(acme_entry(&authority, ACME))?;
    let clock: Arc<dyn chio_security_types::clock::Clock> =
        Arc::new(FixedClock::from_millis(NOW_MS));
    let never = |_: &RevocationPartner, _: &Path| -> Result<(), PartnerRevocationError> {
        Err(PartnerRevocationError::Fetch(
            "acme".to_owned(),
            "no partner may sync".to_owned(),
        ))
    };
    let mut entry = acme_entry(&authority, ACME);
    entry["acme"]["revocationFreshnessTtlSeconds"] = serde_json::json!(301);
    std::fs::write(
        &door.registry,
        serde_json::to_vec(&serde_json::json!({
            "schema": crate::revocation_partner::REVOCATION_PARTNER_REGISTRY_SCHEMA,
            "partners": entry,
        }))?,
    )?;
    let invalid = check_partner_passport_revocation_with(
        &door.config,
        VerifiedPassportIssuer::Url("https://trust.other.example"),
        PASSPORT,
        &clock,
        &never,
    )
    .err()
    .ok_or("an invalid registry must refuse")?;
    assert!(
        invalid.to_string().contains(
            &crate::revocation_partner::RevocationPartnerError::InvalidRevocationFreshnessTtl {
                partner_id: "acme".to_owned(),
                ttl: 301,
            }
            .to_string()
        ),
        "{invalid}"
    );
    std::fs::remove_file(&door.registry)?;
    let missing = check_partner_passport_revocation_with(
        &door.config,
        VerifiedPassportIssuer::Url(ACME),
        PASSPORT,
        &clock,
        &never,
    )
    .err()
    .ok_or("a missing registry must refuse")?;
    assert!(
        missing
            .to_string()
            .contains("revocation partner registry is unreadable"),
        "{missing}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_door_binds_native_passports_by_the_authority_key_did() -> TestResult {
    let mut partner = partner()?;
    let clock = shared_clock(&mut partner.state);
    revoke_passport_status(&partner.registry, PASSPORT, None, Some(1_799_999_990))?;
    let addr = serve(partner.state.clone()).await?;
    let door = door(acme_entry(&partner.authority, ACME))?;
    let issuer_did =
        chio_did::DidChio::from_public_key(partner.authority.public_key())?.to_string();
    let refused = tokio::task::spawn_blocking(move || {
        let dyn_clock: Arc<dyn chio_security_types::clock::Clock> = clock.clone();
        check_partner_passport_revocation_with(
            &door.config,
            VerifiedPassportIssuer::Dids(&[did(9).map_err(|error| error.to_string())?, issuer_did]),
            PASSPORT,
            &dyn_clock,
            &loopback_sync_with(addr, clock.clone()),
        )
        .map_err(|error| error.to_string())
    })
    .await?
    .err()
    .ok_or("a revoked native passport from a partner must refuse")?;
    assert!(
        refused.contains(
            &PartnerRevocationError::Revoked {
                partner_id: "acme".to_owned(),
                passport_id: PASSPORT.to_owned(),
            }
            .to_string()
        ),
        "{refused}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_production_door_syncs_only_over_the_strict_transport() -> TestResult {
    let partner = partner()?;
    let addr = serve(partner.state.clone()).await?;
    let issuer = format!("https://{addr}");
    let door = door(acme_entry(&partner.authority, &issuer))?;
    let refused = tokio::task::spawn_blocking(move || {
        let clock: Arc<dyn chio_security_types::clock::Clock> =
            Arc::new(FixedClock::from_millis(NOW_MS));
        check_partner_passport_revocation(
            &door.config,
            VerifiedPassportIssuer::Url(&issuer),
            PASSPORT,
            &clock,
        )
    })
    .await?
    .err()
    .ok_or("a loopback partner must refuse at the door")?;
    assert!(
        refused.to_string().to_lowercase().contains("loopback"),
        "{refused}"
    );
    Ok(())
}
