//! The public passport revocation feed routes publish the signed oracle root
//! and bounded leaf pages, and refuse when their state is not configured.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use chio_credentials::PassportStatusDistribution;
use chio_revocation_oracle::{PassportRevocationLeafKind, SqliteRevocationOracle};
use chio_security_types::clock::FixedClock;

use super::*;
use crate::passport_revocation::{passport_revocation_oracle_path, revoke_passport_status};
use crate::passport_revocation_feed::{
    passport_revocation_root_verifier, PassportRevocationLeavesPage,
    PassportRevocationRootDocument, PASSPORT_REVOCATION_LEAVES_SCHEMA,
    PASSPORT_REVOCATION_ROOT_SCHEMA,
};
use crate::passport_verifier::test_fixtures::passport_from_issuers;
use crate::passport_verifier::PassportStatusRegistry;
use crate::trust_control::service_runtime::router::build_router;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ISSUED_AT: u64 = 1_710_000_000;
const NOW_MS: u64 = (ISSUED_AT + 60) * 1_000;

struct Publisher {
    _dir: tempfile::TempDir,
    registry: PathBuf,
    passport_id: String,
    credential_digests: Vec<String>,
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

fn publisher() -> Result<Publisher, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let registry = dir.path().join("passport-statuses.json");
    let seed = dir.path().join("authority.seed");
    let authority = Keypair::from_seed(&[31; 32]);
    write_seed(&seed, &authority)?;
    let passport = passport_from_issuers(3, &[4], ISSUED_AT)?;
    let record = PassportStatusRegistry::update(&registry, |lifecycle| {
        lifecycle.publish(&passport, ISSUED_AT, PassportStatusDistribution::default())
    })?;
    let oracle = SqliteRevocationOracle::open(&passport_revocation_oracle_path(&registry)?)?;
    let mut state = metrics_state("service-secret");
    state.finding_challenge_clock = Arc::new(FixedClock::from_millis(NOW_MS));
    state.config.passport_statuses_file = Some(registry.clone());
    state.config.authority_seed_path = Some(seed);
    state.passport_revocation_oracle = Some(Arc::new(oracle));
    Ok(Publisher {
        _dir: dir,
        registry,
        passport_id: record.passport_id,
        credential_digests: record.credential_digests,
        authority,
        state,
    })
}

impl Publisher {
    fn revoke(&self) -> TestResult {
        revoke_passport_status(
            &self.registry,
            &self.passport_id,
            Some("compromised"),
            Some(ISSUED_AT + 1),
            ISSUED_AT + 2,
        )?;
        Ok(())
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

fn error_of(body: &[u8]) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice::<serde_json::Value>(body)?["error"].clone())
}

fn feed_uris() -> [String; 2] {
    [
        PUBLIC_PASSPORT_REVOCATION_ROOT_PATH.to_owned(),
        format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=0"),
    ]
}

#[tokio::test]
async fn the_root_route_signs_the_oracle_root_with_the_authority_key() -> TestResult {
    let publisher = publisher()?;
    publisher.revoke()?;
    let (status, body) = get(&publisher.state, PUBLIC_PASSPORT_REVOCATION_ROOT_PATH).await?;
    assert_eq!(status, StatusCode::OK);
    let document: PassportRevocationRootDocument = serde_json::from_slice(&body)?;
    assert_eq!(document.schema, PASSPORT_REVOCATION_ROOT_SCHEMA);
    let signed = document.into_signed_root()?;
    signed.verify(&passport_revocation_root_verifier(
        &publisher.authority.public_key(),
    ))?;
    assert_eq!(
        signed.root.leaf_count,
        1 + publisher.credential_digests.len()
    );
    assert_eq!(signed.root.issued_at_unix_ms, NOW_MS);
    Ok(())
}

#[tokio::test]
async fn the_leaves_route_pages_from_a_required_cursor() -> TestResult {
    let publisher = publisher()?;
    publisher.revoke()?;
    let (status, body) = get(
        &publisher.state,
        &format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=0"),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let page: PassportRevocationLeavesPage = serde_json::from_slice(&body)?;
    assert_eq!(page.schema, PASSPORT_REVOCATION_LEAVES_SCHEMA);
    let published = page
        .leaves
        .iter()
        .map(|leaf| (leaf.kind, leaf.subject.clone()))
        .collect::<Vec<_>>();
    let mut expected = vec![(
        PassportRevocationLeafKind::Passport,
        publisher.passport_id.clone(),
    )];
    expected.extend(
        publisher
            .credential_digests
            .iter()
            .map(|digest| (PassportRevocationLeafKind::Credential, digest.clone())),
    );
    assert_eq!(published, expected);

    for uri in [
        PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH.to_owned(),
        format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=-1"),
        format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=0&limit=5"),
        format!("{PUBLIC_PASSPORT_REVOCATION_LEAVES_PATH}?after=9007199254740992"),
    ] {
        let (status, _) = get(&publisher.state, &uri).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn the_feed_refuses_without_a_lifecycle_registry() -> TestResult {
    let mut publisher = publisher()?;
    publisher.state.config.passport_statuses_file = None;
    for uri in feed_uris() {
        let (status, body) = get(&publisher.state, &uri).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{uri}");
        assert_eq!(
            error_of(&body)?,
            "passport revocation feed requires --passport-statuses-file"
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_feed_refuses_when_the_oracle_was_not_opened() -> TestResult {
    let mut publisher = publisher()?;
    publisher.state.passport_revocation_oracle = None;
    for uri in feed_uris() {
        let (status, body) = get(&publisher.state, &uri).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert_eq!(error_of(&body)?, "passport revocation oracle is not open");
    }
    Ok(())
}

#[tokio::test]
async fn the_feed_refuses_a_lost_oracle_without_naming_its_path() -> TestResult {
    let publisher = publisher()?;
    publisher.revoke()?;
    std::fs::remove_file(passport_revocation_oracle_path(&publisher.registry)?)?;
    for uri in feed_uris() {
        let (status, body) = get(&publisher.state, &uri).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        assert_eq!(
            error_of(&body)?,
            "passport revocation feed state is unavailable"
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_root_route_refuses_without_an_authority() -> TestResult {
    let mut publisher = publisher()?;
    publisher.state.config.authority_seed_path = None;
    let (status, body) = get(&publisher.state, PUBLIC_PASSPORT_REVOCATION_ROOT_PATH).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        error_of(&body)?,
        "passport revocation feed requires a configured trust-control authority"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_at_the_partner_reaches_the_mirror_over_http() -> TestResult {
    use crate::passport_revocation_mirror::{
        partner_revocation_mirror_path, PartnerRevocationError, PartnerRevocationMirror,
    };
    use crate::revocation_partner::RevocationPartner;
    use crate::trust_control::{
        build_portable_fetch_agent, PartnerRevocationFeed, PortableFetchDeadline,
    };

    let publisher = publisher()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = build_router(publisher.state.clone());
    tokio::spawn(async move {
        let _served = axum::serve(listener, app).await;
    });
    let dir = tempfile::tempdir()?;
    let mirror_path =
        partner_revocation_mirror_path(&dir.path().join("b-revocation-partners.json"), "acme")?;
    let partner = RevocationPartner {
        partner_id: "acme".to_owned(),
        issuer: "https://trust.acme.example".to_owned(),
        authority_public_key: publisher.authority.public_key(),
        issuer_public_keys: vec![publisher.authority.public_key()],
        revocation_freshness_ttl_seconds: 60,
    };
    let mut subjects = vec![chio_revocation_oracle::passport_revocation_key(
        &publisher.passport_id,
    )];
    subjects.extend(
        publisher
            .credential_digests
            .iter()
            .map(|digest| chio_revocation_oracle::credential_revocation_key(digest)),
    );
    let registry = publisher.registry.clone();
    let passport_id = publisher.passport_id.clone();
    let outcomes = tokio::task::spawn_blocking(move || -> Result<_, String> {
        let mirror = PartnerRevocationMirror::open(&mirror_path, "acme")
            .map_err(|error| error.to_string())?;
        let sync = || -> Result<(), String> {
            let deadline = PortableFetchDeadline::start().map_err(|error| error.to_string())?;
            let agent = build_portable_fetch_agent(vec![addr], false, &deadline)
                .map_err(|error| error.to_string())?;
            let mut feed =
                PartnerRevocationFeed::new("acme", &format!("http://{addr}"), agent, deadline);
            mirror
                .sync(&partner, &mut feed, &FixedClock::from_millis(NOW_MS))
                .map(|_| ())
                .map_err(|error| error.to_string())
        };
        sync()?;
        let before = mirror.check_passport(&partner, &subjects, NOW_MS);
        revoke_passport_status(
            &registry,
            &passport_id,
            Some("compromised"),
            Some(ISSUED_AT + 1),
            ISSUED_AT + 2,
        )
        .map_err(|error| error.to_string())?;
        sync()?;
        let after = mirror.check_passport(&partner, &subjects, NOW_MS);
        Ok((before, after))
    })
    .await??;
    assert_eq!(outcomes.0, Ok(()));
    assert_eq!(
        outcomes.1,
        Err(PartnerRevocationError::Revoked {
            partner_id: "acme".to_owned(),
            subject: publisher.passport_id.clone(),
        })
    );
    Ok(())
}
