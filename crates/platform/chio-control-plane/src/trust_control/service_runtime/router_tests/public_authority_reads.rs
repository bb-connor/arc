//! Unauthenticated routes inspect existing authority storage. They never commit
//! an authority write, never wait on the authority write lock, and never
//! provision a missing database or signing seed.

use super::*;
use chio_credentials::{
    build_oid4vp_request_transport, Oid4vpVerifierMetadata, PortableJwkSet,
    SignedPublicDiscoveryTransparency, SignedPublicIssuerDiscovery,
};
use chio_store_sqlite::SqliteCapabilityAuthority;
use rusqlite::{Connection, OpenFlags};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ADVERTISE_URL: &str = "https://trust.example.com";
const UNISSUED_TOKEN_REQUEST: &str = r#"{"grantType":"urn:ietf:params:oauth:grant-type:pre-authorized_code","pre-authorized_code":"unissued-code"}"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Surface {
    /// A signed or plain public metadata document.
    Document,
    /// The liveness report, which describes authority availability.
    Health,
    /// Pre-authorized code redemption, refused for an unissued code.
    TokenRedemption,
}

struct PublicCall {
    surface: Surface,
    path: String,
}

struct PublicAuthorityFixture {
    directory: tempfile::TempDir,
    state: TrustServiceState,
    request_id: String,
}

impl PublicAuthorityFixture {
    /// A service whose authority database was provisioned by the writable owner.
    fn provisioned() -> Result<(Self, PathBuf), Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let authority_db = directory.path().join("authority.sqlite3");
        let signer = SqliteCapabilityAuthority::open_with_clock(
            &authority_db,
            chio_test_support::clock::clock(),
        )?
        .local_keypair()?;
        let fixture = Self::with_authority(
            directory,
            |config| config.authority_db_path = Some(authority_db.clone()),
            &signer,
        )?;
        Ok((fixture, authority_db))
    }

    fn with_authority(
        directory: tempfile::TempDir,
        configure: impl FnOnce(&mut TrustServiceConfig),
        request_signer: &Keypair,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut state = metrics_state("service-secret");
        state.finding_challenge_clock = chio_test_support::clock::clock();
        state.config.advertise_url = Some(ADVERTISE_URL.to_string());
        state.config.verifier_challenge_db_path =
            Some(directory.path().join("verifier-challenges.sqlite3"));
        state.config.passport_issuance_offers_file =
            Some(directory.path().join("issuance-offers.json"));
        configure(&mut state.config);
        let request_id = register_oid4vp_request(&state.config, request_signer)?;
        Ok(Self {
            directory,
            state,
            request_id,
        })
    }

    fn calls(&self) -> Vec<PublicCall> {
        let document = |path: &str| PublicCall {
            surface: Surface::Document,
            path: path.to_string(),
        };
        vec![
            document(PASSPORT_ISSUER_METADATA_PATH),
            document(PUBLIC_PASSPORT_ISSUER_DISCOVERY_PATH),
            document(PUBLIC_PASSPORT_VERIFIER_DISCOVERY_PATH),
            document(PUBLIC_PASSPORT_DISCOVERY_TRANSPARENCY_PATH),
            document(OID4VP_VERIFIER_METADATA_PATH),
            document(PASSPORT_ISSUER_JWKS_PATH),
            document(PUBLIC_GENERIC_NAMESPACE_PATH),
            document(PUBLIC_GENERIC_LISTINGS_PATH),
            document(&super::super::super::client::path_with_encoded_param(
                PUBLIC_PASSPORT_OID4VP_REQUEST_PATH,
                "request_id",
                &self.request_id,
            )),
            PublicCall {
                surface: Surface::Health,
                path: HEALTH_PATH.to_string(),
            },
            PublicCall {
                surface: Surface::TokenRedemption,
                path: PASSPORT_ISSUANCE_TOKEN_PATH.to_string(),
            },
        ]
    }

    async fn call(
        &self,
        call: &PublicCall,
    ) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error>> {
        let request = match call.surface {
            Surface::TokenRedemption => axum::http::Request::builder()
                .method("POST")
                .uri(&call.path)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(UNISSUED_TOKEN_REQUEST))?,
            Surface::Document | Surface::Health => axum::http::Request::builder()
                .method("GET")
                .uri(&call.path)
                .body(axum::body::Body::empty())?,
        };
        let response = super::super::build_router(self.state.clone())
            .oneshot(request)
            .await?;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, body.to_vec()))
    }

    async fn get(&self, path: &str) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error>> {
        self.call(&PublicCall {
            surface: Surface::Document,
            path: path.to_string(),
        })
        .await
    }
}

fn register_oid4vp_request(
    config: &TrustServiceConfig,
    signer: &Keypair,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = build_oid4vp_request_for_service(
        config,
        &CreateOid4vpRequest {
            disclosure_claims: Vec::new(),
            issuer_allowlist: Vec::new(),
            ttl_seconds: Some(600),
            identity_assertion: None,
        },
        chio_test_support::clock::unix_seconds(),
    )?;
    let transport = build_oid4vp_request_transport(&request, signer)?;
    let path = configured_verifier_challenge_db_path(config)?;
    Oid4vpVerifierTransactionStore::open(path)?.register(&request, &transport.request_jwt)?;
    Ok(request.jti)
}

fn health_authority(body: &[u8]) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut health: serde_json::Value = serde_json::from_slice(body)?;
    Ok(health["authority"].take())
}

fn excerpt(status: StatusCode, body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    format!("{status}: {}", text.chars().take(200).collect::<String>())
}

/// Why the route did not answer from existing authority state, if it did not.
fn unserved(call: &PublicCall, status: StatusCode, body: &[u8]) -> Option<String> {
    let served = match call.surface {
        Surface::Document => status == StatusCode::OK,
        Surface::Health => {
            status == StatusCode::OK
                && health_authority(body)
                    .is_ok_and(|authority| authority["available"] == serde_json::Value::Bool(true))
        }
        Surface::TokenRedemption => {
            status == StatusCode::BAD_REQUEST
                && String::from_utf8_lossy(body).contains("pre-authorized")
        }
    };
    (!served).then(|| format!("{} not served: {}", call.path, excerpt(status, body)))
}

/// Why the route did not refuse, if it served an authority it could not inspect.
fn unrefused(call: &PublicCall, status: StatusCode, body: &[u8]) -> Option<String> {
    let refused = match call.surface {
        Surface::Document | Surface::TokenRedemption => {
            status == StatusCode::NOT_FOUND || status == StatusCode::CONFLICT
        }
        Surface::Health => {
            status == StatusCode::OK
                && health_authority(body).is_ok_and(|authority| {
                    authority["configured"] == serde_json::Value::Bool(true)
                        && (authority["available"] == serde_json::Value::Bool(false)
                            || authority["publicKey"].is_null())
                })
        }
    };
    (!refused).then(|| format!("{} not refused: {}", call.path, excerpt(status, body)))
}

fn assert_no_violations(subject: &str, violations: &[String]) {
    assert!(
        violations.is_empty(),
        "{subject}:\n{}",
        violations.join("\n")
    );
}

/// A separate reader of the authority database. `PRAGMA data_version` changes
/// whenever any other connection commits a change to the database.
struct AuthorityDataWitness {
    connection: Connection,
    wal: PathBuf,
}

impl AuthorityDataWitness {
    fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut wal = path.as_os_str().to_os_string();
        wal.push("-wal");
        Ok(Self {
            connection: Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?,
            wal: PathBuf::from(wal),
        })
    }

    fn data_version(&self) -> rusqlite::Result<i64> {
        self.connection
            .query_row("PRAGMA data_version", [], |row| row.get(0))
    }

    /// Write transactions committed to the current WAL generation. Each commit
    /// ends with a frame whose header records the database size after it. This
    /// open witness keeps the last writer from checkpointing the WAL away.
    fn committed_transactions(&self) -> std::io::Result<usize> {
        let wal = match std::fs::read(&self.wal) {
            Ok(wal) => wal,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        };
        let word = |offset: usize| -> Option<u32> {
            Some(u32::from_be_bytes(
                wal.get(offset..offset + 4)?.try_into().ok()?,
            ))
        };
        let (Some(page_size), Some(salt)) = (word(8), wal.get(16..24)) else {
            return Ok(0);
        };
        let frame = 24 + page_size as usize;
        let mut offset = 32;
        let mut commits = 0;
        while offset + frame <= wal.len() && wal.get(offset + 8..offset + 16) == Some(salt) {
            if word(offset + 4).is_some_and(|size_after_commit| size_after_commit != 0) {
                commits += 1;
            }
            offset += frame;
        }
        Ok(commits)
    }

    /// Every persisted authority row, the schema stamp and the table definitions.
    fn persisted(&self) -> rusqlite::Result<Vec<String>> {
        let application_id: i64 =
            self.connection
                .query_row("PRAGMA application_id", [], |row| row.get(0))?;
        let mut rows = vec![format!("application_id={application_id}")];
        let mut schema = self
            .connection
            .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")?;
        let mut tables = Vec::new();
        let mut cursor = schema.query([])?;
        while let Some(row) = cursor.next()? {
            let (kind, name, sql): (String, String, Option<String>) =
                (row.get(0)?, row.get(1)?, row.get(2)?);
            rows.push(format!("{kind}:{name}:{sql:?}"));
            if kind == "table" {
                tables.push(name);
            }
        }
        for table in tables {
            let mut statement = self
                .connection
                .prepare(&format!("SELECT * FROM \"{table}\""))?;
            let width = statement.column_count();
            let mut cursor = statement.query([])?;
            let mut table_rows = BTreeSet::new();
            while let Some(row) = cursor.next()? {
                let values = (0..width)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                table_rows.insert(format!("{table}:{values:?}"));
            }
            rows.extend(table_rows);
        }
        Ok(rows)
    }

    fn observed_ms(&self) -> rusqlite::Result<i64> {
        self.connection.query_row(
            "SELECT observed_ms FROM authority_state WHERE singleton_id = 1",
            [],
            |row| row.get(0),
        )
    }
}

fn sidecars_absent(path: &Path) -> bool {
    ["-wal", "-shm", "-journal"].iter().all(|suffix| {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        !PathBuf::from(sidecar).exists()
    })
}

#[tokio::test]
async fn public_authority_routes_commit_no_authority_data_writes() -> TestResult {
    let (fixture, authority_db) = PublicAuthorityFixture::provisioned()?;
    let witness = AuthorityDataWitness::open(&authority_db)?;
    let mut violations = Vec::new();
    for call in fixture.calls() {
        let commits = witness.committed_transactions()?;
        let version = witness.data_version()?;
        let persisted = witness.persisted()?;
        let floor = witness.observed_ms()?;
        let (status, body) = fixture.call(&call).await?;
        let committed = witness
            .committed_transactions()?
            .checked_sub(commits)
            .map_or_else(|| "an unknown number of".to_string(), |n| n.to_string());
        let advanced = witness.observed_ms()?;
        if committed != "0"
            || witness.data_version()? != version
            || advanced != floor
            || witness.persisted()? != persisted
        {
            violations.push(format!(
                "{}: {committed} committed authority write transactions, clock floor {floor} -> {advanced}",
                call.path
            ));
        }
        violations.extend(unserved(&call, status, &body));
    }
    assert_no_violations("public routes wrote authority data", &violations);
    Ok(())
}

#[tokio::test]
async fn public_authority_routes_answer_while_an_authority_writer_holds_the_write_lock(
) -> TestResult {
    let (fixture, authority_db) = PublicAuthorityFixture::provisioned()?;
    let writer = Connection::open_with_flags(
        &authority_db,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    writer.execute_batch("BEGIN IMMEDIATE")?;
    let mut violations = Vec::new();
    for call in fixture.calls() {
        let (status, body) = fixture.call(&call).await?;
        violations.extend(unserved(&call, status, &body));
    }
    writer.execute_batch("ROLLBACK")?;
    assert_no_violations(
        "public routes waited on the authority write lock",
        &violations,
    );
    Ok(())
}

#[tokio::test]
async fn public_authority_routes_refuse_absent_storage_without_creating_it() -> TestResult {
    let throwaway_signer = Keypair::generate();
    let mut violations = Vec::new();

    let directory = chio_test_support::private_tempdir()?;
    let missing_parent = directory.path().join("missing");
    let nested_db = missing_parent.join("authority.sqlite3");
    let fixture = PublicAuthorityFixture::with_authority(
        directory,
        |config| config.authority_db_path = Some(nested_db.clone()),
        &throwaway_signer,
    )?;
    for call in fixture.calls() {
        let (status, body) = fixture.call(&call).await?;
        violations.extend(unrefused(&call, status, &body));
        if missing_parent.exists() {
            violations.push(format!(
                "{} created the authority parent directory",
                call.path
            ));
            std::fs::remove_dir_all(&missing_parent)?;
        }
    }

    let directory = chio_test_support::private_tempdir()?;
    let absent_db = directory.path().join("authority.sqlite3");
    let fixture = PublicAuthorityFixture::with_authority(
        directory,
        |config| config.authority_db_path = Some(absent_db.clone()),
        &throwaway_signer,
    )?;
    for call in fixture.calls() {
        let (status, body) = fixture.call(&call).await?;
        violations.extend(unrefused(&call, status, &body));
        if absent_db.exists() || !sidecars_absent(&absent_db) {
            violations.push(format!("{} created the authority database", call.path));
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let mut file = absent_db.as_os_str().to_os_string();
                file.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(file));
            }
        }
    }

    let directory = chio_test_support::private_tempdir()?;
    let empty_db = directory.path().join("authority.sqlite3");
    std::fs::write(&empty_db, b"")?;
    std::fs::set_permissions(&empty_db, std::fs::Permissions::from_mode(0o600))?;
    let fixture = PublicAuthorityFixture::with_authority(
        directory,
        |config| config.authority_db_path = Some(empty_db.clone()),
        &throwaway_signer,
    )?;
    for call in fixture.calls() {
        let (status, body) = fixture.call(&call).await?;
        violations.extend(unrefused(&call, status, &body));
        if std::fs::metadata(&empty_db)?.len() != 0 || !sidecars_absent(&empty_db) {
            violations.push(format!(
                "{} initialized an empty authority database",
                call.path
            ));
            break;
        }
    }

    let directory = chio_test_support::private_tempdir()?;
    let absent_seed = directory.path().join("authority.seed");
    let fixture = PublicAuthorityFixture::with_authority(
        directory,
        |config| config.authority_seed_path = Some(absent_seed.clone()),
        &throwaway_signer,
    )?;
    for call in fixture.calls() {
        let (status, body) = fixture.call(&call).await?;
        violations.extend(unrefused(&call, status, &body));
        if absent_seed.exists() {
            violations.push(format!("{} created an authority seed", call.path));
            std::fs::remove_file(&absent_seed)?;
        }
    }
    assert_no_violations(
        "public routes served or provisioned absent authority storage",
        &violations,
    );
    Ok(())
}

#[tokio::test]
async fn health_reports_an_initialized_authority_as_the_status_owner_does() -> TestResult {
    let (fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    let (status, body) = fixture.get(HEALTH_PATH).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let reported = health_authority(&body)?;
    let owner =
        match crate::trust_control::report_validation::load_authority_status(&fixture.state.config)
        {
            Ok(owner) => owner,
            Err(response) => {
                return Err(format!("status owner refused: {}", response.status()).into())
            }
        };
    let expected = serde_json::json!({
        "configured": owner.configured,
        "available": true,
        "backend": owner.backend,
        "publicKey": owner.public_key,
        "generation": owner.generation,
        "rotatedAt": owner.rotated_at,
        "appliesToFutureSessionsOnly": owner.applies_to_future_sessions_only,
        "trustedKeyCount": owner.trusted_public_keys.len(),
    });
    assert_eq!(
        serde_json::to_vec(&reported)?,
        serde_json::to_vec(&expected)?
    );
    Ok(())
}

fn issuable_passport(issued_at: u64) -> Result<AgentPassport, Box<dyn std::error::Error>> {
    let subject = Keypair::from_seed(&[93; 32]);
    let scorecard = chio_reputation::compute_local_scorecard(
        &subject.public_key().to_hex(),
        issued_at,
        &chio_reputation::LocalReputationCorpus::default(),
        &chio_reputation::ReputationConfig::default(),
    );
    let credential = chio_credentials::issue_reputation_credential(
        &Keypair::from_seed(&[94; 32]),
        scorecard,
        chio_credentials::ChioCredentialEvidence {
            query: chio_credentials::AttestationWindow {
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
        issued_at + 7_200,
    )?;
    let subject_did = credential.unsigned.credential_subject.id.clone();
    Ok(chio_credentials::build_agent_passport(
        &subject_did,
        vec![credential],
    )?)
}

#[tokio::test]
async fn public_issuer_metadata_is_identical_to_the_owner_view() -> TestResult {
    let (fixture, _authority_db) = PublicAuthorityFixture::provisioned()?;
    let clock = &fixture.state.finding_challenge_clock;
    assert_eq!(
        canonical_json_bytes(&public_passport_credential_issuer(
            &fixture.state.config,
            clock
        )?)?,
        canonical_json_bytes(&configured_passport_credential_issuer(
            &fixture.state.config
        )?)?
    );

    let directory = chio_test_support::private_tempdir()?;
    let seed = directory.path().join("authority.seed");
    crate::load_or_create_authority_keypair(&seed)?;
    let mut config = fixture.state.config.clone();
    config.authority_db_path = None;
    config.authority_seed_path = Some(seed);
    assert_eq!(
        canonical_json_bytes(&public_passport_credential_issuer(&config, clock)?)?,
        canonical_json_bytes(&configured_passport_credential_issuer(&config)?)?
    );
    Ok(())
}

#[tokio::test]
async fn token_redemption_redeems_an_issued_code_without_authority_writes() -> TestResult {
    let (fixture, authority_db) = PublicAuthorityFixture::provisioned()?;
    let issued_at = chio_test_support::clock::unix_seconds();
    let metadata = configured_passport_credential_issuer(&fixture.state.config)?;
    let mut registry = crate::passport_verifier::PassportIssuanceOfferRegistry::default();
    let offer = registry.issue_offer(
        &metadata,
        issuable_passport(issued_at)?,
        None,
        3_600,
        issued_at,
    )?;
    let offers = fixture
        .state
        .config
        .passport_issuance_offers_file
        .clone()
        .ok_or("offers file is configured")?;
    std::fs::write(&offers, canonical_json_bytes(&registry)?)?;

    let witness = AuthorityDataWitness::open(&authority_db)?;
    let commits = witness.committed_transactions()?;
    let persisted = witness.persisted()?;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(PASSPORT_ISSUANCE_TOKEN_PATH)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(
            &serde_json::json!({
                "grantType": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": offer.offer.pre_authorized_code()?,
            }),
        )?))?;
    let response = super::super::build_router(fixture.state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let token: serde_json::Value = serde_json::from_slice(&body)?;
    assert!(token["accessToken"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(witness.committed_transactions()?, commits);
    assert_eq!(witness.persisted()?, persisted);
    Ok(())
}

#[tokio::test]
async fn public_routes_refuse_absent_authority_with_a_typed_message() -> TestResult {
    let throwaway_signer = Keypair::generate();
    let directory = chio_test_support::private_tempdir()?;
    let absent_db = directory.path().join("authority.sqlite3");
    let fixture = PublicAuthorityFixture::with_authority(
        directory,
        |config| config.authority_db_path = Some(absent_db.clone()),
        &throwaway_signer,
    )?;
    let token = PublicCall {
        surface: Surface::TokenRedemption,
        path: PASSPORT_ISSUANCE_TOKEN_PATH.to_string(),
    };
    let (status, body) = fixture.call(&token).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(String::from_utf8_lossy(&body)
        .contains("requires a configured authority whose database its owner has initialized"));
    let (status, body) = fixture.get(HEALTH_PATH).await?;
    assert_eq!(status, StatusCode::OK);
    let health: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(health["ok"], serde_json::Value::Bool(true));
    assert_eq!(
        health["authority"],
        serde_json::json!({
            "configured": true,
            "available": false,
            "backend": "sqlite",
            "publicKey": null,
            "generation": null,
            "rotatedAt": null,
            "appliesToFutureSessionsOnly": true,
            "trustedKeyCount": 0,
        })
    );
    assert!(!absent_db.exists());
    let (status, body) = fixture.get(PASSPORT_ISSUER_JWKS_PATH).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(String::from_utf8_lossy(&body)
        .contains("requires a configured authority whose database its owner has initialized"));

    let directory = chio_test_support::private_tempdir()?;
    let absent_seed = directory.path().join("authority.seed");
    let fixture = PublicAuthorityFixture::with_authority(
        directory,
        |config| config.authority_seed_path = Some(absent_seed.clone()),
        &throwaway_signer,
    )?;
    let (status, body) = fixture.call(&token).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(String::from_utf8_lossy(&body)
        .contains("requires a configured authority signing seed that already exists"));
    assert!(!absent_seed.exists());
    Ok(())
}

#[tokio::test]
async fn public_authority_routes_publish_rotation_and_lifecycle() -> TestResult {
    let (fixture, authority_db) = PublicAuthorityFixture::provisioned()?;
    let writer = SqliteCapabilityAuthority::open_with_clock(
        &authority_db,
        chio_test_support::clock::clock(),
    )?;
    let original = writer.status()?;
    writer.initialize_replication("public-authority-read")?;
    let rotated = writer.rotate()?;
    assert_ne!(rotated.public_key, original.public_key);

    let (status, body) = fixture.get(OID4VP_VERIFIER_METADATA_PATH).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let metadata: Oid4vpVerifierMetadata = serde_json::from_slice(&body)?;
    assert_eq!(metadata.authority_generation, Some(rotated.generation));
    assert_eq!(metadata.trusted_key_count, 2);

    let (status, body) = fixture.get(PASSPORT_ISSUER_JWKS_PATH).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let published = serde_json::from_slice::<PortableJwkSet>(&body)?
        .keys
        .iter()
        .map(|entry| entry.jwk.to_public_key().map(|key| key.to_hex()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = [original.public_key.to_hex(), rotated.public_key.to_hex()]
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(published, expected);

    let (status, body) = fixture.get(PUBLIC_PASSPORT_ISSUER_DISCOVERY_PATH).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let discovery: SignedPublicIssuerDiscovery = serde_json::from_slice(&body)?;
    assert_eq!(discovery.body.signer_public_key, rotated.public_key);
    assert_eq!(discovery.body.version, rotated.generation);

    writer.revoke_issuer(&original.public_key)?;
    let (status, body) = fixture.get(PASSPORT_ISSUER_JWKS_PATH).await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let published = serde_json::from_slice::<PortableJwkSet>(&body)?
        .keys
        .iter()
        .map(|entry| entry.jwk.to_public_key().map(|key| key.to_hex()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(
        published,
        [rotated.public_key.to_hex()]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );

    let (status, body) = fixture
        .get(PUBLIC_PASSPORT_DISCOVERY_TRANSPARENCY_PATH)
        .await?;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let transparency: SignedPublicDiscoveryTransparency = serde_json::from_slice(&body)?;
    assert_eq!(transparency.body.signer_public_key, rotated.public_key);
    Ok(())
}

#[tokio::test]
async fn public_authority_routes_refuse_a_regressed_clock_and_unsafe_custody() -> TestResult {
    let (fixture, authority_db) = PublicAuthorityFixture::provisioned()?;
    let witness = AuthorityDataWitness::open(&authority_db)?;
    let floor_secs = u64::try_from(witness.observed_ms()?)? / 1_000;
    let persisted = witness.persisted()?;
    let mut violations = Vec::new();
    {
        let _regressed = chio_test_support::clock::scope_unix_secs(floor_secs - 3_600);
        for call in fixture.calls() {
            let (status, body) = fixture.call(&call).await?;
            violations.extend(unrefused(&call, status, &body));
            if witness.persisted()? != persisted {
                violations.push(format!("{} changed persisted authority state", call.path));
            }
        }
    }
    drop(witness);

    std::fs::set_permissions(&authority_db, std::fs::Permissions::from_mode(0o644))?;
    for call in fixture.calls() {
        let (status, body) = fixture.call(&call).await?;
        violations.extend(unrefused(&call, status, &body));
        if std::fs::metadata(&authority_db)?.permissions().mode() & 0o7777 != 0o644 {
            violations.push(format!("{} repaired custody", call.path));
        }
    }
    std::fs::set_permissions(&authority_db, std::fs::Permissions::from_mode(0o600))?;

    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o755),
    )?;
    for call in fixture.calls() {
        let (status, body) = fixture.call(&call).await?;
        violations.extend(unrefused(&call, status, &body));
    }
    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )?;
    assert_no_violations(
        "public routes served an authority below its clock floor or without private custody",
        &violations,
    );
    Ok(())
}
