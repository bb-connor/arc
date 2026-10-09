//! Trust-before-fetch, strict transport, DNS pinning, body bounds and bounded
//! async offload for portable-issuer and lifecycle resolution.
use super::*;

use chio_credentials::{
    build_agent_passport, build_portable_jwks, inspect_chio_passport_sd_jwt_vc_unverified,
    issue_chio_passport_sd_jwt_vc, issue_reputation_credential, respond_to_oid4vp_request,
    verify_oid4vp_direct_post_response_with_any_issuer_key, AttestationWindow,
    ChioCredentialEvidence, Oid4vpDcqlQuery, Oid4vpRequestObject, Oid4vpRequestedCredential,
    CHIO_PASSPORT_SD_JWT_VC_FORMAT, CHIO_PASSPORT_SD_JWT_VC_TYPE,
    OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI, OID4VP_RESPONSE_MODE_DIRECT_POST_JWT,
    OID4VP_RESPONSE_TYPE_VP_TOKEN,
};
use futures_util::FutureExt;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

use chio_test_support::prelude::*;

const GLOBAL_IPV4: &str = "8.8.8.8";

fn empty_config() -> TrustServiceConfig {
    TrustServiceConfig {
        transport: Default::default(),
        listen: "127.0.0.1:0".parse().test_unwrap(),
        service_token: "token".to_string(),
        tenant_read_tokens: BTreeMap::new(),
        authority_workload_token: None,
        receipt_db_path: None,
        receipt_query_snapshot_quota_bytes: 2_147_483_648,
        revocation_db_path: None,
        authority_seed_path: None,
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
        verifier_challenge_db_path: None,
        passport_statuses_file: None,
        passport_issuance_offers_file: None,
        certification_registry_file: None,
        certification_discovery_file: None,
        issuance_policy: None,
        runtime_assurance_policy: None,
        advertise_url: None,
        allow_local_peer_urls: false,
        certification_public_metadata_ttl_seconds: 900,
        peer_urls: Vec::new(),
        cluster_sync_interval: Duration::from_millis(200),
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: None,
    }
}

fn jwks_body(issuer: &str, key: &PublicKey) -> String {
    let jwks = build_portable_jwks(issuer, std::slice::from_ref(key)).test_unwrap();
    serde_json::to_string(&jwks).test_unwrap()
}

/// A loopback listener that answers each accepted connection with `status` and
/// `body`, recording how many connections it served.
struct RecordingServer {
    addr: std::net::SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RecordingServer {
    fn start(status: &'static str, body: String) -> Self {
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
                    Ok((stream, _)) => {
                        served.fetch_add(1, Ordering::SeqCst);
                        serve_once(stream, status, &body);
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

impl Drop for RecordingServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_once(mut stream: TcpStream, status: &str, body: &str) {
    let mut buffer = [0u8; 1024];
    let _ = stream.read(&mut buffer);
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(response.as_bytes()).is_ok() {
        let _ = stream.flush();
    }
}

fn loopback_fetch_agent(addr: std::net::SocketAddr) -> Agent {
    build_portable_fetch_agent(vec![addr], false)
}

#[test]
fn empty_allowlist_refuses_remote_issuer_without_network() {
    let config = empty_config();
    let allowed = BTreeSet::new();
    let resolution = plan_portable_issuer_keys(
        &config,
        "https://issuer.example",
        &allowed,
        &chio_test_support::clock::clock(),
    )
    .test_unwrap();
    assert!(matches!(resolution, PortableIssuerResolution::Untrusted));
}

#[test]
fn non_allowlisted_issuer_is_untrusted() {
    let config = empty_config();
    let allowed = BTreeSet::from(["https://good.example".to_string()]);
    let resolution = plan_portable_issuer_keys(
        &config,
        "https://evil.example",
        &allowed,
        &chio_test_support::clock::clock(),
    )
    .test_unwrap();
    assert!(matches!(resolution, PortableIssuerResolution::Untrusted));
}

#[test]
fn allowlisted_https_issuer_plans_a_strict_remote_fetch() {
    let config = empty_config();
    let allowed = BTreeSet::from(["https://good.example".to_string()]);
    let resolution = plan_portable_issuer_keys(
        &config,
        "https://good.example",
        &allowed,
        &chio_test_support::clock::clock(),
    )
    .test_unwrap();
    let PortableIssuerResolution::Remote(fetch) = resolution else {
        panic!("allowlisted https issuer must plan a remote fetch");
    };
    assert_eq!(fetch.jwks_url, "https://good.example/.well-known/jwks.json");
    assert!(fetch.contract.deny_loopback);
    assert!(fetch.contract.deny_link_local);
    assert!(fetch.contract.deny_ipv6_ula);
    assert!(fetch.contract.allowed_schemes.contains("https"));
    assert!(!fetch.contract.allowed_schemes.contains("http"));
}

#[test]
fn http_allowlisted_issuer_is_refused_before_any_fetch() {
    let config = empty_config();
    let allowed = BTreeSet::from(["http://good.example".to_string()]);
    let error = plan_portable_issuer_keys(
        &config,
        "http://good.example",
        &allowed,
        &chio_test_support::clock::clock(),
    )
    .test_unwrap_err();
    assert!(error.to_string().to_lowercase().contains("scheme"));
}

#[test]
fn pin_checked_addrs_refuses_private_resolution() {
    let config = empty_config();
    let allowed = BTreeSet::from(["https://good.example".to_string()]);
    let PortableIssuerResolution::Remote(fetch) = plan_portable_issuer_keys(
        &config,
        "https://good.example",
        &allowed,
        &chio_test_support::clock::clock(),
    )
    .test_unwrap() else {
        panic!("expected a remote fetch plan");
    };
    let url = Url::parse(&fetch.jwks_url).test_unwrap();
    let private =
        |_host: &str, port: u16| Ok(vec![format!("127.0.0.1:{port}").parse().test_unwrap()]);
    let error = pin_checked_https_addrs(&fetch.contract, &url, private).test_unwrap_err();
    assert!(error.to_string().to_lowercase().contains("loopback"));
}

#[test]
fn dns_resolution_is_pinned_to_the_checked_addresses_once() {
    let config = empty_config();
    let allowed = BTreeSet::from(["https://good.example".to_string()]);
    let PortableIssuerResolution::Remote(fetch) = plan_portable_issuer_keys(
        &config,
        "https://good.example",
        &allowed,
        &chio_test_support::clock::clock(),
    )
    .test_unwrap() else {
        panic!("expected a remote fetch plan");
    };
    let url = Url::parse(&fetch.jwks_url).test_unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    // A rebinding resolver: public on the first lookup, private on any second
    // lookup. Pinning must resolve exactly once and reuse the checked address,
    // so the private rebind is never reachable by the connection.
    let rebinding = move |_host: &str, port: u16| {
        let nth = observed.fetch_add(1, Ordering::SeqCst);
        if nth == 0 {
            Ok(vec![format!("{GLOBAL_IPV4}:{port}").parse().test_unwrap()])
        } else {
            Ok(vec![format!("127.0.0.1:{port}").parse().test_unwrap()])
        }
    };
    let pinned = pin_checked_https_addrs(&fetch.contract, &url, rebinding).test_unwrap();
    assert_eq!(
        pinned,
        vec![format!("{GLOBAL_IPV4}:443").parse().test_unwrap()]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn fetch_returns_only_the_pinned_loopback_keys() {
    let issuer_keypair = Keypair::generate();
    let server = RecordingServer::start(
        "200 OK",
        jwks_body(
            "https://remote.issuer.example",
            &issuer_keypair.public_key(),
        ),
    );
    let agent = loopback_fetch_agent(server.addr);
    let keys =
        fetch_portable_issuer_jwks(&agent, "http://remote.issuer.example/.well-known/jwks.json")
            .test_unwrap();
    assert_eq!(keys, vec![issuer_keypair.public_key()]);
    assert_eq!(server.connections(), 1);
}

#[test]
fn fetch_error_status_does_not_reflect_the_response_body() {
    let secret = "SECRET-INTERNAL-METADATA-abcdef";
    let server = RecordingServer::start("500 Internal Server Error", secret.to_string());
    let agent = loopback_fetch_agent(server.addr);
    let error =
        fetch_portable_issuer_jwks(&agent, "http://remote.issuer.example/.well-known/jwks.json")
            .test_unwrap_err();
    let message = error.to_string();
    assert!(
        !message.contains(secret),
        "fetch error must not echo the upstream body: {message}"
    );
    assert!(message.contains("500"));
}

#[test]
fn fetch_bounds_an_oversized_body() {
    let oversized = "a".repeat(PORTABLE_ISSUER_FETCH_MAX_BODY_BYTES + 4_096);
    let server = RecordingServer::start("200 OK", oversized);
    let agent = loopback_fetch_agent(server.addr);
    let error =
        fetch_portable_issuer_jwks(&agent, "http://remote.issuer.example/.well-known/jwks.json")
            .test_unwrap_err();
    assert!(!error.to_string().contains("aaaa"));
}

#[tokio::test(flavor = "current_thread")]
async fn aborted_fetch_response_does_not_reflect_panic_payload() {
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let outcome =
        run_portable_issuer_fetch_with_lane(lane, || panic!("SECRET_PANIC_PAYLOAD_do_not_leak"))
            .await;
    let refusal = match outcome {
        Err(refusal) => refusal,
        Ok(()) => panic!("a panicking fetch must not report success"),
    };
    let response = refusal.into_response(plain_http_error);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        !body.contains("SECRET_PANIC_PAYLOAD_do_not_leak"),
        "the response must not echo the panic payload: {body}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn offload_refuses_when_no_permit_is_free() {
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let _held = Arc::clone(&lane).try_acquire_owned().test_unwrap();
    let outcome = run_portable_issuer_fetch_with_lane(lane, || 7u32).await;
    assert!(matches!(outcome, Err(PortableFetchRefusal::AtCapacity)));
}

#[tokio::test(flavor = "current_thread")]
async fn cancellation_keeps_admission_until_the_blocking_fetch_finishes() {
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let fetch = tokio::spawn(run_portable_issuer_fetch_with_lane(
        Arc::clone(&lane),
        move || {
            entered_tx.send(()).test_unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(30))
                .test_unwrap();
        },
    ));
    tokio::time::timeout(Duration::from_secs(30), entered_rx)
        .await
        .test_unwrap()
        .test_unwrap();

    fetch.abort();
    let cancelled = tokio::time::timeout(Duration::from_secs(30), fetch)
        .await
        .test_unwrap();
    assert!(matches!(cancelled, Err(error) if error.is_cancelled()));
    assert_eq!(lane.available_permits(), 0);
    // One poll must return the refusal; queued admission is also a failure.
    let refused = run_portable_issuer_fetch_with_lane(Arc::clone(&lane), || ())
        .now_or_never()
        .test_unwrap();
    assert!(matches!(refused, Err(PortableFetchRefusal::AtCapacity)));

    release_tx.send(()).test_unwrap();
    let returned = tokio::time::timeout(Duration::from_secs(30), lane.acquire_owned())
        .await
        .test_unwrap()
        .test_unwrap();
    drop(returned);
}

#[tokio::test(flavor = "current_thread")]
async fn offload_leaves_the_async_worker_free_while_the_remote_stalls() {
    // A listener that accepts and never answers. The pinned fetch runs on the
    // blocking pool, so a second task on the single async worker must make
    // progress while the fetch is still outstanding.
    let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
    let addr = listener.local_addr().test_unwrap();
    let (accepted_tx, accepted_rx) = mpsc::channel::<TcpStream>();
    let server = std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            // Hold the connection open and unanswered until the test ends.
            let _ = accepted_tx.send(stream);
        }
    });

    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let fetch_done = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&fetch_done);
    let fetch = tokio::spawn(run_portable_issuer_fetch_with_lane(lane, move || {
        let agent = build_portable_fetch_agent(vec![addr], false);
        let outcome = fetch_portable_issuer_jwks(
            &agent,
            "http://remote.issuer.example/.well-known/jwks.json",
        );
        done.store(true, Ordering::SeqCst);
        outcome
    }));

    let observed = Arc::clone(&fetch_done);
    let progressed = tokio::spawn(async move {
        tokio::task::yield_now().await;
        !observed.load(Ordering::SeqCst)
    });
    let progressed_while_outstanding = tokio::time::timeout(Duration::from_secs(30), progressed)
        .await
        .test_unwrap()
        .test_unwrap();
    assert!(
        progressed_while_outstanding,
        "a task on the fetch worker made no progress until the stalled fetch ended"
    );

    fetch.abort();
    let _ = fetch.await;
    drop(accepted_rx);
    let _ = server.join();
}

#[test]
fn lifecycle_without_status_reference_resolves_locally() {
    let config = empty_config();
    let plan = plan_oid4vp_passport_lifecycle(&config, "passport-1", None, 1_000).test_unwrap();
    assert!(matches!(plan, PassportLifecyclePlan::Resolved(None)));
}

/// An allowlisted remote issuer verifies end to end: the request admits the
/// issuer, the bounded pinned fetch returns its keys, and a holder response
/// signed under that issuer is accepted. The same credential under an empty
/// allowlist is refused before any fetch.
#[test]
fn allowlisted_remote_issuer_verifies_end_to_end() {
    let now = 1_000_000u64;
    let issuer_url = "https://remote.issuer.example";
    let issuer_keypair = Keypair::generate();
    let subject = Keypair::generate();
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
        now.saturating_add(86_400),
    )
    .test_unwrap();
    let passport = build_agent_passport(&subject_did, vec![credential]).test_unwrap();
    let envelope = issue_chio_passport_sd_jwt_vc(&passport, issuer_url, &issuer_keypair, now, None)
        .test_unwrap();

    let request = Oid4vpRequestObject {
        client_id: "https://verifier.example".to_string(),
        client_id_scheme: OID4VP_CLIENT_ID_SCHEME_REDIRECT_URI.to_string(),
        response_uri: "https://verifier.example/v1/public/passport/oid4vp/direct-post".to_string(),
        response_mode: OID4VP_RESPONSE_MODE_DIRECT_POST_JWT.to_string(),
        response_type: OID4VP_RESPONSE_TYPE_VP_TOKEN.to_string(),
        nonce: "nonce-remote".to_string(),
        state: "state-remote".to_string(),
        iat: now,
        exp: now.saturating_add(300),
        jti: "request-remote".to_string(),
        request_uri: "https://verifier.example/v1/public/passport/oid4vp/requests/request-remote"
            .to_string(),
        dcql_query: Oid4vpDcqlQuery {
            credentials: vec![Oid4vpRequestedCredential {
                id: "chio-passport".to_string(),
                format: CHIO_PASSPORT_SD_JWT_VC_FORMAT.to_string(),
                vct: CHIO_PASSPORT_SD_JWT_VC_TYPE.to_string(),
                claims: Vec::new(),
                issuer_allowlist: vec![issuer_url.to_string()],
            }],
        },
        identity_assertion: None,
    };
    let response_jwt =
        respond_to_oid4vp_request(&subject, &envelope.compact, &request, now).test_unwrap();

    let credential = inspect_chio_passport_sd_jwt_vc_unverified(&envelope.compact).test_unwrap();
    assert_eq!(credential.issuer, issuer_url);

    let config = empty_config();
    let allowed: BTreeSet<String> = request.dcql_query.credentials[0]
        .issuer_allowlist
        .iter()
        .cloned()
        .collect();
    assert!(matches!(
        plan_portable_issuer_keys(
            &config,
            &credential.issuer,
            &allowed,
            &chio_test_support::clock::clock()
        )
        .test_unwrap(),
        PortableIssuerResolution::Remote(_)
    ));
    assert!(matches!(
        plan_portable_issuer_keys(
            &config,
            &credential.issuer,
            &BTreeSet::new(),
            &chio_test_support::clock::clock()
        )
        .test_unwrap(),
        PortableIssuerResolution::Untrusted
    ));

    // The bounded pinned fetch returns the issuer's published key over a
    // loopback listener standing in for the remote JWKS endpoint.
    let server = RecordingServer::start(
        "200 OK",
        jwks_body(issuer_url, &issuer_keypair.public_key()),
    );
    let agent = loopback_fetch_agent(server.addr);
    let fetched =
        fetch_portable_issuer_jwks(&agent, "http://remote.issuer.example/.well-known/jwks.json")
            .test_unwrap();
    assert_eq!(fetched, vec![issuer_keypair.public_key()]);

    let verification = verify_oid4vp_direct_post_response_with_any_issuer_key(
        &response_jwt,
        &request,
        &fetched,
        now,
    )
    .test_unwrap();
    assert_eq!(verification.issuer, issuer_url);
    assert_eq!(verification.subject_did, subject_did);
}
