//! The public OID4VP direct-post route must not fetch an untrusted issuer's
//! keys. An unauthenticated holder who presents a self-issued credential whose
//! issuer is neither the local advertised issuer nor in the signed request's
//! allowlist is refused before any outbound request, and a locally issued
//! credential is still accepted without any fetch.
use super::*;

use axum::body::to_bytes;
use axum::extract::{Form, State};
use chio_credentials::{
    build_agent_passport, issue_chio_passport_sd_jwt_vc, issue_reputation_credential,
    respond_to_oid4vp_request, AttestationWindow, ChioCredentialEvidence,
};
use chio_security_types::clock::{
    Clock, ClockError, ClockReading, FixedClock, MonotonicInstant, UnixMillis,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use chio_test_support::prelude::*;

/// A fixed point in the trusted-clock range used as every request's `iat`
/// anchor so the tests never read wall-clock time.
const BASE_UNIX_SECS: u64 = 2_000_000_000;

/// An injected clock that reports `base_secs` for its first `steps_before_jump`
/// reads and `jumped_secs` for every read after. It models trusted time
/// advancing during the handler's remote waits without any wall-clock sleep.
struct SteppingClock {
    base_secs: u64,
    jumped_secs: u64,
    steps_before_jump: usize,
    reads: AtomicUsize,
}

impl Clock for SteppingClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let nth = self.reads.fetch_add(1, Ordering::SeqCst);
        let secs = if nth < self.steps_before_jump {
            self.base_secs
        } else {
            self.jumped_secs
        };
        Ok(ClockReading::new(
            UnixMillis::from_secs(secs)?,
            MonotonicInstant::from_nanos(nth as u64),
        ))
    }
}

/// A loopback listener that would answer a JWKS fetch, recording whether the
/// direct-post handler ever reached out to it.
struct IssuerServer {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl IssuerServer {
    fn start(body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
        let addr = listener.local_addr().test_unwrap();
        listener.set_nonblocking(true).test_unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let served = Arc::clone(&connections);
        let halt = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        served.fetch_add(1, Ordering::SeqCst);
                        answer(&mut stream, &body);
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            addr,
            connections,
            stop,
            handle: Some(handle),
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for IssuerServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn answer(stream: &mut TcpStream, body: &str) {
    let mut buffer = [0u8; 1024];
    let _ = stream.read(&mut buffer);
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(response.as_bytes()).is_ok() {
        let _ = stream.flush();
    }
}

fn state_with(config: TrustServiceConfig, clock: Arc<dyn Clock>) -> TrustServiceState {
    TrustServiceState {
        finding_challenge_clock: clock,
        config,
        authority_keyring: None,
        authority_keyring_seed_path: None,
        joint_authority_store: None,
        fiscal_runtime: None,
        budget_store: None,
        revocation_store: None,
        receipt_store: None,
        receipt_query_snapshots: None,
        receipt_query_lane: Arc::new(tokio::sync::Semaphore::new(4)),
        evidence_export_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        enterprise_provider_registry: None,
        verifier_policy_registry: None,
        federation_admission_rate_limiter: Arc::new(Mutex::new(
            FederationAdmissionRateLimiter::default(),
        )),
        cluster: None,
        cluster_progress: None,
        leader_forward_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        authority_health_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        public_passport_challenge_lane: Arc::new(tokio::sync::Semaphore::new(
            crate::trust_control::report_rendering::PUBLIC_PASSPORT_CHALLENGE_PERMITS,
        )),
        finding_rail: None,
        finding_purchase_executor: None,
        finding_purchase_execution_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_proof_egress_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_seller_submission_executor: None,
        finding_seller_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_challenge_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_authority_status_resolver: None,
        finding_challenge_executor: None,
    }
}

fn config_with(
    advertise_url: &str,
    seed_path: &std::path::Path,
    db_path: &std::path::Path,
) -> TrustServiceConfig {
    TrustServiceConfig {
        transport: Default::default(),
        listen: "127.0.0.1:0".parse().test_unwrap(),
        service_token: "token".to_string(),
        tenant_read_tokens: BTreeMap::new(),
        authority_workload_token: None,
        receipt_db_path: None,
        receipt_query_snapshot_quota_bytes: 2_147_483_648,
        revocation_db_path: None,
        authority_seed_path: Some(seed_path.to_path_buf()),
        authority_db_path: None,
        authority_keyring_config_path: None,
        authority_keyring_receipt_anchor_root: None,
        budget_db_path: None,
        joint_authority_db_path: None,
        fiscal_runtime: None,
        enterprise_providers_file: None,
        federation_policies_file: None,
        scim_lifecycle_file: None,
        verifier_policies_file: None,
        verifier_challenge_db_path: Some(db_path.to_path_buf()),
        passport_statuses_file: None,
        passport_issuance_offers_file: None,
        certification_registry_file: None,
        certification_discovery_file: None,
        issuance_policy: None,
        runtime_assurance_policy: None,
        advertise_url: Some(advertise_url.to_string()),
        allow_local_peer_urls: true,
        certification_public_metadata_ttl_seconds: 300,
        peer_urls: Vec::new(),
        cluster_sync_interval: Duration::from_millis(200),
        authority_replication_max_future_skew_seconds: 0,
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: None,
    }
}

fn build_passport(subject: &Keypair, now: u64) -> chio_credentials::AgentPassport {
    build_passport_until(subject, now, now.saturating_add(86_400))
}

fn build_passport_until(
    subject: &Keypair,
    now: u64,
    valid_until: u64,
) -> chio_credentials::AgentPassport {
    let subject_did = chio_did::DidChio::from_public_key(subject.public_key())
        .test_unwrap()
        .to_string();
    let credential = issue_reputation_credential(
        &Keypair::generate(),
        chio_reputation::compute_local_scorecard(
            &subject.public_key().to_hex(),
            now.saturating_sub(120),
            &chio_reputation::LocalReputationCorpus::default(),
            &chio_reputation::ReputationConfig::default(),
        ),
        ChioCredentialEvidence {
            query: AttestationWindow {
                since: None,
                until: now.saturating_sub(120),
            },
            receipt_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_roots: Vec::new(),
            receipt_log_urls: Vec::new(),
            lineage_records: 0,
            uncheckpointed_receipts: 0,
            runtime_attestation: None,
        },
        now.saturating_sub(120),
        valid_until,
    )
    .test_unwrap();
    build_agent_passport(&subject_did, vec![credential]).test_unwrap()
}

fn register_request(
    config: &TrustServiceConfig,
    issuer_allowlist: Vec<String>,
    now: u64,
) -> Oid4vpRequestObject {
    let payload = CreateOid4vpRequest {
        disclosure_claims: Vec::new(),
        issuer_allowlist,
        ttl_seconds: Some(300),
        identity_assertion: None,
    };
    let request = build_oid4vp_request_for_service(config, &payload, now).test_unwrap();
    let signing_key = resolve_oid4vp_verifier_signing_key(config).test_unwrap();
    let transport =
        chio_credentials::build_oid4vp_request_transport(&request, &signing_key).test_unwrap();
    let db_path = configured_verifier_challenge_db_path(config).test_unwrap();
    let store = Oid4vpVerifierTransactionStore::open(db_path).test_unwrap();
    store
        .register(&request, &transport.request_jwt)
        .test_unwrap();
    request
}

async fn response_parts(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn public_direct_post_refuses_untrusted_issuer_before_any_fetch() {
    let now = BASE_UNIX_SECS;
    let dir = tempfile::tempdir().test_unwrap();
    let config = config_with(
        "https://verifier.example",
        &dir.path().join("authority.seed"),
        &dir.path().join("verifier.sqlite3"),
    );

    // An attacker-controlled issuer JWKS endpoint on loopback. If the handler
    // trusted the credential's own issuer, it would fetch here (SSRF).
    let attacker = Keypair::generate();
    let subject = Keypair::generate();
    let passport = build_passport(&subject, now);
    let jwks =
        chio_credentials::build_portable_jwks("http://issuer.invalid", &[attacker.public_key()])
            .test_unwrap();
    let server = IssuerServer::start(serde_json::to_string(&jwks).test_unwrap());
    let issuer_url = format!("http://{}", server.addr);
    let envelope =
        issue_chio_passport_sd_jwt_vc(&passport, &issuer_url, &attacker, now, None).test_unwrap();

    // The verifier request carries an EMPTY issuer allowlist.
    let request = register_request(&config, Vec::new(), now);
    let response_jwt =
        respond_to_oid4vp_request(&subject, &envelope.compact, &request, now).test_unwrap();

    let response = handle_public_submit_oid4vp_response(
        State(state_with(config, Arc::new(FixedClock::new(now)))),
        Form(Oid4vpDirectPostForm {
            response: response_jwt,
        }),
    )
    .await;
    let (status, body) = response_parts(response).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "untrusted issuer must be refused, body: {body}"
    );
    assert_eq!(
        server.connections(),
        0,
        "the handler must not fetch an untrusted issuer's JWKS"
    );
}

#[tokio::test]
async fn public_direct_post_accepts_locally_issued_credential_without_fetch() {
    let now = BASE_UNIX_SECS;
    let advertise_url = "https://verifier.example";
    let dir = tempfile::tempdir().test_unwrap();
    let config = config_with(
        advertise_url,
        &dir.path().join("authority.seed"),
        &dir.path().join("verifier.sqlite3"),
    );

    // The verifier's own authority key signs the credential, so the credential
    // issuer equals the advertised issuer and local trust applies with no fetch.
    let authority = resolve_oid4vp_verifier_signing_key(&config).test_unwrap();
    let subject = Keypair::generate();
    let passport = build_passport(&subject, now);
    let envelope = issue_chio_passport_sd_jwt_vc(&passport, advertise_url, &authority, now, None)
        .test_unwrap();

    let request = register_request(&config, Vec::new(), now);
    let response_jwt =
        respond_to_oid4vp_request(&subject, &envelope.compact, &request, now).test_unwrap();

    let response = handle_public_submit_oid4vp_response(
        State(state_with(config, Arc::new(FixedClock::new(now)))),
        Form(Oid4vpDirectPostForm {
            response: response_jwt,
        }),
    )
    .await;
    let (status, body) = response_parts(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "local issuance must verify, body: {body}"
    );
}

#[tokio::test]
async fn public_direct_post_refuses_acceptance_past_request_expiry() {
    // The request window is base..base+300. Trusted time reads `base` for the
    // entry lookup and credential verification, then jumps past the request
    // expiry for the post-wait acceptance read, so the atomic consume refuses
    // and records no consumption.
    let base = BASE_UNIX_SECS;
    let jumped = base + 600;
    let advertise_url = "https://verifier.example";
    let dir = tempfile::tempdir().test_unwrap();
    let config = config_with(
        advertise_url,
        &dir.path().join("authority.seed"),
        &dir.path().join("verifier.sqlite3"),
    );

    let authority = resolve_oid4vp_verifier_signing_key(&config).test_unwrap();
    let subject = Keypair::generate();
    let passport = build_passport(&subject, base);
    let envelope = issue_chio_passport_sd_jwt_vc(&passport, advertise_url, &authority, base, None)
        .test_unwrap();
    let request = register_request(&config, Vec::new(), base);
    let response_jwt =
        respond_to_oid4vp_request(&subject, &envelope.compact, &request, base).test_unwrap();

    let clock = Arc::new(SteppingClock {
        base_secs: base,
        jumped_secs: jumped,
        steps_before_jump: 2,
        reads: AtomicUsize::new(0),
    });
    let state = state_with(config, clock);

    let response = handle_public_submit_oid4vp_response(
        State(state.clone()),
        Form(Oid4vpDirectPostForm {
            response: response_jwt,
        }),
    )
    .await;
    let (status, body) = response_parts(response).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "acceptance past request expiry must be refused, body: {body}"
    );
    assert!(body.contains("expired"), "refusal must cite expiry: {body}");

    let store = Oid4vpVerifierTransactionStore::open(
        configured_verifier_challenge_db_path(&state.config).test_unwrap(),
    )
    .test_unwrap();
    let snapshot = store.snapshot(&request.jti, base).test_unwrap();
    assert_ne!(
        snapshot.transaction.status.label(),
        "consumed",
        "an expired acceptance must not consume the request"
    );
}

#[tokio::test]
async fn public_direct_post_refuses_credential_expired_during_the_wait() {
    // The credential expires at base+100, before the request expiry at base+300.
    // Trusted time reads base for the entry lookup and first verification, then
    // jumps to base+200 for the post-wait acceptance read: the request is still
    // live but the credential has expired, so the final revalidation refuses and
    // the request stays unconsumed.
    let base = BASE_UNIX_SECS;
    let credential_valid_until = base + 100;
    let jumped = base + 200;
    let advertise_url = "https://verifier.example";
    let dir = tempfile::tempdir().test_unwrap();
    let config = config_with(
        advertise_url,
        &dir.path().join("authority.seed"),
        &dir.path().join("verifier.sqlite3"),
    );

    let authority = resolve_oid4vp_verifier_signing_key(&config).test_unwrap();
    let subject = Keypair::generate();
    let passport = build_passport_until(&subject, base, credential_valid_until);
    let envelope = issue_chio_passport_sd_jwt_vc(&passport, advertise_url, &authority, base, None)
        .test_unwrap();
    let request = register_request(&config, Vec::new(), base);
    let response_jwt =
        respond_to_oid4vp_request(&subject, &envelope.compact, &request, base).test_unwrap();

    let clock = Arc::new(SteppingClock {
        base_secs: base,
        jumped_secs: jumped,
        steps_before_jump: 2,
        reads: AtomicUsize::new(0),
    });
    let state = state_with(config, clock);

    let response = handle_public_submit_oid4vp_response(
        State(state.clone()),
        Form(Oid4vpDirectPostForm {
            response: response_jwt,
        }),
    )
    .await;
    let (status, body) = response_parts(response).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a credential that expired during the wait must be refused, body: {body}"
    );

    let store = Oid4vpVerifierTransactionStore::open(
        configured_verifier_challenge_db_path(&state.config).test_unwrap(),
    )
    .test_unwrap();
    let snapshot = store.snapshot(&request.jti, base).test_unwrap();
    assert_ne!(
        snapshot.transaction.status.label(),
        "consumed",
        "a credential expired during the wait must not consume the request"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn public_direct_post_reads_the_local_authority_database_without_writing() {
    let now = BASE_UNIX_SECS;
    let advertise_url = "https://verifier.example";
    let dir = chio_test_support::private_tempdir().test_unwrap();
    let authority_db = dir.path().join("authority.sqlite3");
    let authority = chio_store_sqlite::SqliteCapabilityAuthority::open_with_clock(
        &authority_db,
        chio_test_support::clock::clock(),
    )
    .test_unwrap()
    .local_keypair()
    .test_unwrap();
    let mut config = config_with(
        advertise_url,
        &dir.path().join("unused.seed"),
        &dir.path().join("verifier.sqlite3"),
    );
    config.authority_seed_path = None;
    config.authority_db_path = Some(authority_db.clone());

    let subject = Keypair::generate();
    let passport = build_passport(&subject, now);
    let envelope = issue_chio_passport_sd_jwt_vc(&passport, advertise_url, &authority, now, None)
        .test_unwrap();
    let request = register_request(&config, Vec::new(), now);
    let response_jwt =
        respond_to_oid4vp_request(&subject, &envelope.compact, &request, now).test_unwrap();

    let witness = rusqlite::Connection::open_with_flags(
        &authority_db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .test_unwrap();
    let data_version = |witness: &rusqlite::Connection| -> i64 {
        witness
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .test_unwrap()
    };
    let observed_ms = |witness: &rusqlite::Connection| -> i64 {
        witness
            .query_row(
                "SELECT observed_ms FROM authority_state WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .test_unwrap()
    };
    let version = data_version(&witness);
    let floor = observed_ms(&witness);

    let response = handle_public_submit_oid4vp_response(
        State(state_with(config, Arc::new(FixedClock::new(now)))),
        Form(Oid4vpDirectPostForm {
            response: response_jwt,
        }),
    )
    .await;
    let (status, body) = response_parts(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "local issuance must verify, body: {body}"
    );
    assert_eq!(
        data_version(&witness),
        version,
        "the public direct post committed an authority write"
    );
    assert_eq!(
        observed_ms(&witness),
        floor,
        "the public direct post advanced the authority clock floor"
    );
}
