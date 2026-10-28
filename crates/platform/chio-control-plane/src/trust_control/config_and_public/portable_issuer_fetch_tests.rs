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

use crate::bounded_worker_pool::tests::{drain, single_worker_pool};

const GLOBAL_IPV4: &str = "8.8.8.8";
const HANG_GUARD: Duration = Duration::from_secs(30);

/// A fetch deadline with only `left` remaining, as if the fetch had already
/// spent the rest of its total budget.
fn deadline_with(left: Duration) -> PortableFetchDeadline {
    let start = Instant::now()
        .checked_sub(PORTABLE_ISSUER_FETCH_TOTAL_TIMEOUT - left)
        .test_unwrap();
    PortableFetchDeadline::starting_at(start).test_unwrap()
}

fn open_deadline() -> PortableFetchDeadline {
    PortableFetchDeadline::start().test_unwrap()
}

fn strict_jwks_fetch_target() -> (Url, HttpEgressContract) {
    let url = Url::parse("https://good.example/.well-known/jwks.json").test_unwrap();
    let contract =
        strict_portable_fetch_contract(url.as_str(), "control-plane.portable-issuer-jwks")
            .test_unwrap();
    (url, contract)
}

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
        revocation_partners_file: None,
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
        authority_replication_max_future_skew_seconds: 0,
        roster_policy: None,
        capital_authority: None,
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
    build_portable_fetch_agent(vec![addr], false, &open_deadline()).test_unwrap()
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
        let agent = loopback_fetch_agent(addr);
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
fn healthy_fetch_runs_dns_through_decode_on_a_single_worker() {
    let issuer_keypair = Keypair::generate();
    let server = RecordingServer::start(
        "200 OK",
        jwks_body(
            "https://remote.issuer.example",
            &issuer_keypair.public_key(),
        ),
    );
    let server_addr = server.addr;
    let (url, contract) = strict_jwks_fetch_target();
    let pool = BoundedWorkerPool::new(1, 1);

    let keys = run_portable_fetch(&pool, open_deadline(), move |deadline| {
        let pinned = pin_checked_https_addrs(&contract, &url, |_host: &str, port: u16| {
            Ok(vec![format!("{GLOBAL_IPV4}:{port}").parse().test_unwrap()])
        })?;
        assert_eq!(
            pinned,
            vec![format!("{GLOBAL_IPV4}:443").parse().test_unwrap()]
        );
        let agent = build_portable_fetch_agent(vec![server_addr], false, &deadline)?;
        fetch_portable_issuer_jwks(&agent, "http://remote.issuer.example/.well-known/jwks.json")
    })
    .test_unwrap();

    assert_eq!(keys, vec![issuer_keypair.public_key()]);
    assert_eq!(server.connections(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_fetch_holds_its_worker_but_not_the_fetch_permit() {
    let pool = Arc::new(single_worker_pool());
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let fetch_pool = Arc::clone(&pool);

    // Stands in for a peer trickling its TLS handshake: the fetch job keeps
    // running until the test releases it, long after the fetch deadline.
    let outcome = run_portable_issuer_fetch_with_lane(Arc::clone(&lane), move || {
        run_portable_fetch(
            &fetch_pool,
            deadline_with(Duration::from_secs(2)),
            move |_| {
                entered_tx.send(()).test_unwrap();
                release_rx.recv_timeout(HANG_GUARD).test_unwrap();
                Ok(())
            },
        )
    })
    .await;

    let Ok(Err(error)) = outcome else {
        panic!("a stalled fetch must end with a refusal at its deadline");
    };
    assert_eq!(
        error.to_string(),
        portable_fetch_deadline_exceeded().to_string()
    );
    entered_rx.recv_timeout(HANG_GUARD).test_unwrap();
    assert_eq!(lane.available_permits(), 1);

    // The stalled fetch still holds the only worker, so the next fetch reaches
    // its deadline in the queue and never starts.
    let started = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&started);
    let queued = run_portable_fetch(
        &pool,
        deadline_with(Duration::from_millis(250)),
        move |_| {
            observed.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .test_unwrap_err();
    assert_eq!(
        queued.to_string(),
        portable_fetch_deadline_exceeded().to_string()
    );

    release_tx.send(()).test_unwrap();
    drain(&pool);
    assert!(
        !started.load(Ordering::SeqCst),
        "a fetch dequeued after its deadline must not start"
    );
}

#[test]
fn fetch_success_observed_after_the_deadline_is_refused() {
    let pool = BoundedWorkerPool::new(1, 1);
    let error = run_portable_fetch(
        &pool,
        deadline_with(Duration::from_millis(250)),
        |deadline| {
            // Succeed, but only once the original deadline has passed.
            while deadline.remaining().is_ok() {
                std::hint::spin_loop();
            }
            Ok(())
        },
    )
    .test_unwrap_err();
    assert_eq!(
        error.to_string(),
        portable_fetch_deadline_exceeded().to_string()
    );
}

#[test]
fn http_phase_is_bounded_by_the_budget_left_after_resolution() {
    // A listener that accepts and never answers. Under a full budget the read
    // timeout would end the fetch; the remaining budget must end it first.
    let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
    let addr = listener.local_addr().test_unwrap();
    let (accepted_tx, accepted_rx) = mpsc::channel::<TcpStream>();
    let server = std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let _ = accepted_tx.send(stream);
        }
    });

    let agent = build_portable_fetch_agent(
        vec![addr],
        false,
        &deadline_with(Duration::from_millis(200)),
    )
    .test_unwrap();
    let started = Instant::now();
    let error =
        fetch_portable_issuer_jwks(&agent, "http://remote.issuer.example/.well-known/jwks.json")
            .test_unwrap_err();
    let elapsed = started.elapsed();

    assert_eq!(
        error.to_string(),
        CliError::cli_other_error("portable issuer JWKS endpoint was unreachable").to_string()
    );
    assert!(
        elapsed < PORTABLE_ISSUER_FETCH_READ_TIMEOUT,
        "the HTTP phase must get only the remaining budget, took {elapsed:?}"
    );
    drop(accepted_rx);
    let _ = server.join();
}

#[tokio::test(flavor = "current_thread")]
async fn connect_stage_cannot_outlive_the_fetch_deadline() {
    // A listener whose one-slot accept queue is already full, so the kernel
    // leaves the next connection attempt unanswered.
    let socket = tokio::net::TcpSocket::new_v4().test_unwrap();
    socket
        .bind("127.0.0.1:0".parse().test_unwrap())
        .test_unwrap();
    let listener = socket.listen(0).test_unwrap();
    let addr = listener.local_addr().test_unwrap();
    let _queued = TcpStream::connect(addr).test_unwrap();

    // Resolution has spent all but a sliver of the budget, far less than the
    // connect timeout a fresh connect clock would allow.
    let deadline = deadline_with(Duration::from_millis(300));
    let agent = build_portable_fetch_agent(vec![addr], false, &deadline).test_unwrap();
    let error =
        fetch_portable_issuer_jwks(&agent, "http://remote.issuer.example/.well-known/jwks.json")
            .test_unwrap_err();

    assert_eq!(
        error.to_string(),
        CliError::cli_other_error("portable issuer JWKS endpoint was unreachable").to_string()
    );
    let overrun = Instant::now().saturating_duration_since(deadline.0);
    assert!(
        overrun < Duration::from_secs(1),
        "the connect stage outlived the fetch deadline by {overrun:?}"
    );
}

#[test]
fn exhausted_deadline_refuses_the_http_phase() {
    let error = build_portable_fetch_agent(
        vec![format!("{GLOBAL_IPV4}:443").parse().test_unwrap()],
        true,
        &deadline_with(Duration::ZERO),
    )
    .test_unwrap_err();
    assert_eq!(
        error.to_string(),
        portable_fetch_deadline_exceeded().to_string()
    );
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

fn remote_status_ref(
    cache_ttl_secs: Option<u64>,
) -> chio_credentials::Oid4vciChioPassportStatusReference {
    chio_credentials::Oid4vciChioPassportStatusReference {
        passport_id: "passport-1".to_owned(),
        distribution: chio_credentials::PassportStatusDistribution {
            resolve_urls: vec!["https://status.example/v1/passports".to_owned()],
            cache_ttl_secs,
        },
    }
}

fn remote_lifecycle() -> PassportLifecycleResolution {
    PassportLifecycleResolution {
        passport_id: "passport-1".to_owned(),
        subject: "did:chio:holder".to_owned(),
        issuers: Vec::new(),
        issuer_count: 1,
        state: PassportLifecycleState::Active,
        published_at: Some(900),
        updated_at: None,
        superseded_by: None,
        revoked_at: None,
        revoked_reason: None,
        distribution: chio_credentials::PassportStatusDistribution::default(),
        valid_until: "2100-01-01T00:00:00Z".to_owned(),
        source: None,
    }
}

#[test]
fn a_remote_lifecycle_within_its_ttl_holds_at_acceptance() {
    let status_ref = remote_status_ref(Some(30));
    let held = recheck_oid4vp_passport_lifecycle(
        &empty_config(),
        "passport-1",
        Some(&status_ref),
        Some(remote_lifecycle()),
        1_000,
        1_030,
    )
    .test_unwrap();
    assert_eq!(held, Some(remote_lifecycle()));
}

#[test]
fn a_remote_lifecycle_older_than_its_ttl_at_acceptance_is_refused() {
    let status_ref = remote_status_ref(Some(30));
    let error = recheck_oid4vp_passport_lifecycle(
        &empty_config(),
        "passport-1",
        Some(&status_ref),
        Some(remote_lifecycle()),
        1_000,
        1_031,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("cache TTL"), "{error}");
}

#[test]
fn a_remote_lifecycle_without_a_ttl_is_refused_at_acceptance() {
    let status_ref = remote_status_ref(None);
    let error = recheck_oid4vp_passport_lifecycle(
        &empty_config(),
        "passport-1",
        Some(&status_ref),
        Some(remote_lifecycle()),
        1_000,
        1_000,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("cache TTL"), "{error}");
}

#[test]
fn a_local_lifecycle_is_resolved_again_at_acceptance() {
    let dir = tempfile::tempdir().test_unwrap();
    let statuses = dir.path().join("passport-statuses.json");
    let mut config = empty_config();
    config.passport_statuses_file = Some(statuses.clone());
    let PassportLifecyclePlan::Resolved(planned) =
        plan_oid4vp_passport_lifecycle(&config, "passport-1", None, 1_000).test_unwrap()
    else {
        panic!("a local registry plans without a fetch");
    };
    std::fs::write(&statuses, b"{").test_unwrap();
    let unreadable = PassportStatusRegistry::load(&statuses)
        .test_unwrap_err()
        .to_string();
    let recheck =
        recheck_oid4vp_passport_lifecycle(&config, "passport-1", None, planned, 1_000, 2_000)
            .test_unwrap_err();
    assert_eq!(recheck.to_string(), unreadable);
}
