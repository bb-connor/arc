#![allow(clippy::expect_used, clippy::too_many_arguments, clippy::unwrap_used)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::capability::{
    attenuation::{DelegationLink, DelegationLinkBody},
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    lineage::ChildRequestReceipt, lineage::ChildRequestReceiptBody,
};
use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_kernel::BudgetStore;
use chio_store_sqlite::SqliteBudgetStore;
use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde_json::{json, Value};

const TRUST_CLUSTER_QUALIFICATION_RUNS: usize = 5;
const MULTI_REGION_PARTITION_SAMPLES: usize = 20;
const CLUSTER_NODE_ID_HEADER: &str = "x-chio-cluster-node-id";
const CLUSTER_AUTH_METHOD_HEADER: &str = "x-chio-cluster-auth-method";
const CLUSTER_AUTH_ISSUED_AT_HEADER: &str = "x-chio-cluster-auth-issued-at";
const CLUSTER_AUTH_NONCE_HEADER: &str = "x-chio-cluster-auth-nonce";
const CLUSTER_AUTH_BODY_DIGEST_HEADER: &str = "x-chio-cluster-body-digest";
const CLUSTER_AUTH_SIGNATURE_HEADER: &str = "x-chio-cluster-auth-signature";
const CLUSTER_AUTH_TERM_HEADER: &str = "x-chio-cluster-auth-term";
const CLUSTER_AUTH_DOMAIN: &str = "chio.cluster.membership-request.v2";
const PARTITION_PROXY_BYPASS_HEADER: &str = "x-chio-test-partition-proxy-bypass";
const PARTITION_PROXY_HEADER_MAX_BYTES: usize = 64 * 1024;

fn internal_peer_registry() -> &'static Mutex<HashMap<String, String>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn partition_proxy_registry() -> &'static Mutex<HashMap<String, Arc<PartitionProxyControl>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<PartitionProxyControl>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn partition_proxy_registered(base_url: &str) -> bool {
    partition_proxy_registry()
        .lock()
        .expect("lock partition proxy registry")
        .contains_key(base_url)
}

fn trust_cluster_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn register_internal_peer(base_url: &str, peer_urls: &[String]) {
    let mut registry = internal_peer_registry()
        .lock()
        .expect("lock internal peer registry");
    if let Some(peer_url) = peer_urls.first() {
        registry.insert(base_url.to_string(), peer_url.clone());
    } else {
        registry.remove(base_url);
    }
}

fn internal_peer_node_id(base_url: &str) -> Option<String> {
    internal_peer_registry()
        .lock()
        .expect("lock internal peer registry")
        .get(base_url)
        .cloned()
}

fn deterministic_cluster_node_key(node_id: &str) -> Keypair {
    let seed = sha256_hex(format!("chio.cli.cluster-test-node.v1\0{node_id}").as_bytes());
    Keypair::from_seed_hex(&seed).expect("derive deterministic cluster test node key")
}

fn cluster_peer_auth_signature(
    node_id: &str,
    receiver_id: &str,
    method: &str,
    endpoint: &str,
    issued_at: i64,
    nonce: &str,
    term: Option<u64>,
    body_digest: &str,
) -> String {
    let payload = canonical_json_bytes(&json!({
        "bodyDigest": body_digest,
        "domain": CLUSTER_AUTH_DOMAIN,
        "endpoint": endpoint,
        "issuedAt": issued_at,
        "method": method,
        "nonce": nonce,
        "peerId": node_id,
        "receiverId": receiver_id,
        "term": term,
    }))
    .expect("encode cluster peer auth payload");
    deterministic_cluster_node_key(node_id)
        .sign(&payload)
        .to_hex()
}

fn cluster_empty_body_digest() -> String {
    sha256_hex(&[])
}

fn cluster_json_body_digest(body: &Value) -> String {
    sha256_hex(&canonical_json_bytes(body).expect("canonicalize cluster request body"))
}

fn canonical_revocation_set_json(ids: &[&str]) -> Value {
    let mut ids = ids.iter().map(|id| (*id).to_string()).collect::<Vec<_>>();
    ids.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let canonical = canonical_json_bytes(&ids).expect("canonical revocation set members");
    let mut digest_input = b"chio.revocation-set.v1\0".to_vec();
    digest_input.extend_from_slice(&canonical);
    json!({
        "ids": ids,
        "digest": sha256_hex(&digest_input),
    })
}

fn composite_authorize_payload(
    capability_id: &str,
    grant_index: usize,
    requested_exposure_units: u64,
    max_exposure_per_invocation: u64,
    max_total_exposure_units: u64,
    max_invocations: u32,
    hold_id: &str,
    event_id: &str,
) -> Value {
    let operation_id = format!(
        "operation-{}",
        &sha256_hex(format!("{capability_id}\0{hold_id}\0{event_id}").as_bytes())[..16]
    );
    let request_binding_hash = sha256_hex(
        format!(
            "chio.cluster.composite-authorization.v1\0{operation_id}\0{capability_id}\0{grant_index}\0{hold_id}\0{event_id}"
        )
        .as_bytes(),
    );
    json!({
        "operationId": operation_id,
        "requestBindingHash": request_binding_hash,
        "capabilityId": capability_id,
        "grantIndex": grant_index,
        "requestedExposureUnits": requested_exposure_units,
        "maxExposurePerInvocation": max_exposure_per_invocation,
        "maxTotalExposureUnits": max_total_exposure_units,
        "holdId": hold_id,
        "eventId": event_id,
        "admissionEvidence": {
            "invocationQuotas": [{
                "key": {
                    "profile": "chio.grant-invocation.v1",
                    "ownerId": capability_id,
                    "grantIndex": grant_index
                },
                "maxInvocations": max_invocations
            }],
            "revocationSet": canonical_revocation_set_json(&[capability_id])
        }
    })
}

fn unique_test_dir() -> PathBuf {
    chio_test_support::private_fs::private_tempdir("chio-cli-trust-cluster-")
        .expect("create private trust cluster test directory")
        .keep()
}

fn create_private_test_dir(path: &Path) {
    fs::create_dir_all(path).expect("create private trust cluster directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)
            .expect("inspect private trust cluster directory")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions).expect("secure private trust cluster directory");
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

fn reserve_cluster_nodes(count: usize) -> Vec<(SocketAddr, String)> {
    let mut nodes = (0..count)
        .map(|_| {
            let addr = reserve_listen_addr();
            (addr, format!("http://{addr}"))
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.1.cmp(&right.1));
    nodes
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Default)]
struct PartitionProxyControl {
    blocked_sources: Mutex<HashSet<String>>,
}

impl PartitionProxyControl {
    fn set_source_blocked(&self, source_url: &str, blocked: bool) {
        let mut blocked_sources = self
            .blocked_sources
            .lock()
            .expect("lock partition proxy control");
        if blocked {
            blocked_sources.insert(source_url.to_string());
        } else {
            blocked_sources.remove(source_url);
        }
    }

    fn blocks(&self, source_url: &str) -> bool {
        self.blocked_sources
            .lock()
            .expect("lock partition proxy control")
            .contains(source_url)
    }
}

struct PartitionProxyGuard {
    advertised_url: String,
    listen: SocketAddr,
    control: Arc<PartitionProxyControl>,
    shutdown: Arc<AtomicBool>,
    listener_thread: Option<thread::JoinHandle<()>>,
}

impl Drop for PartitionProxyGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.listen);
        if let Some(listener_thread) = self.listener_thread.take() {
            let _ = listener_thread.join();
        }
        let mut registry = partition_proxy_registry()
            .lock()
            .expect("lock partition proxy registry");
        let owns_registration = registry
            .get(&self.advertised_url)
            .is_some_and(|control| Arc::ptr_eq(control, &self.control));
        if owns_registration {
            registry.remove(&self.advertised_url);
        }
    }
}

struct PartitionableServerGuard {
    _server: ServerGuard,
    _proxy: PartitionProxyGuard,
}

fn spawn_partition_proxy(
    listen: SocketAddr,
    backend: SocketAddr,
    advertised_url: &str,
) -> PartitionProxyGuard {
    let listener = TcpListener::bind(listen).expect("bind cluster partition proxy");
    listener
        .set_nonblocking(true)
        .expect("set cluster partition proxy nonblocking");
    let control = Arc::new(PartitionProxyControl::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_control = Arc::clone(&control);
    let listener_shutdown = Arc::clone(&shutdown);
    let listener_thread = thread::spawn(move || {
        while !listener_shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let connection_control = Arc::clone(&listener_control);
                    let _connection_thread = thread::spawn(move || {
                        let _ =
                            proxy_partitionable_connection(stream, backend, &connection_control);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) if listener_shutdown.load(Ordering::Acquire) => break,
                Err(error) => panic!("cluster partition proxy accept failed: {error}"),
            }
        }
    });

    let previous = partition_proxy_registry()
        .lock()
        .expect("lock partition proxy registry")
        .insert(advertised_url.to_string(), Arc::clone(&control));
    assert!(
        previous.is_none(),
        "duplicate cluster partition proxy registration for {advertised_url}"
    );

    PartitionProxyGuard {
        advertised_url: advertised_url.to_string(),
        listen,
        control,
        shutdown,
        listener_thread: Some(listener_thread),
    }
}

fn proxy_partitionable_connection(
    mut downstream: TcpStream,
    backend: SocketAddr,
    control: &PartitionProxyControl,
) -> io::Result<()> {
    downstream.set_nonblocking(false)?;
    downstream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let (request_prefix, header_end) = read_partition_proxy_request_prefix(&mut downstream)?;
    downstream.set_read_timeout(None)?;
    let request_head = std::str::from_utf8(&request_prefix[..header_end - 4])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let bypass =
        partition_proxy_header_value(request_head, PARTITION_PROXY_BYPASS_HEADER) == Some("1");
    let source_node_id = signed_partition_proxy_source_node_id(request_head);
    if !bypass && source_node_id.is_some_and(|source| control.blocks(source)) {
        let _ = downstream.shutdown(Shutdown::Both);
        return Ok(());
    }

    let forwarded_request =
        partition_proxy_request_with_connection_close(request_head, &request_prefix[header_end..])?;
    let mut upstream = TcpStream::connect_timeout(&backend, Duration::from_secs(5))?;
    upstream.write_all(&forwarded_request)?;

    let mut downstream_reader = downstream.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;
    let upload_thread = thread::spawn(move || {
        let _ = io::copy(&mut downstream_reader, &mut upstream_writer);
        let _ = upstream_writer.shutdown(Shutdown::Write);
    });
    let response_result = io::copy(&mut upstream, &mut downstream).map(|_| ());
    let _ = downstream.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    let _ = upload_thread.join();
    response_result
}

fn read_partition_proxy_request_prefix(stream: &mut TcpStream) -> io::Result<(Vec<u8>, usize)> {
    let mut prefix = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "cluster partition proxy request ended before headers",
            ));
        }
        prefix.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = prefix
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        {
            return Ok((prefix, header_end));
        }
        if prefix.len() > PARTITION_PROXY_HEADER_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cluster partition proxy request headers exceed limit",
            ));
        }
    }
}

fn partition_proxy_header_value<'a>(request_head: &'a str, name: &str) -> Option<&'a str> {
    request_head
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find_map(|(header_name, value)| {
            if header_name.trim().eq_ignore_ascii_case(name) {
                Some(value.trim())
            } else {
                None
            }
        })
}

fn signed_partition_proxy_source_node_id(request_head: &str) -> Option<&str> {
    let source_node_id = partition_proxy_header_value(request_head, CLUSTER_NODE_ID_HEADER)?;
    partition_proxy_header_value(request_head, CLUSTER_AUTH_METHOD_HEADER)?;
    partition_proxy_header_value(request_head, CLUSTER_AUTH_ISSUED_AT_HEADER)?;
    partition_proxy_header_value(request_head, CLUSTER_AUTH_NONCE_HEADER)?;
    partition_proxy_header_value(request_head, CLUSTER_AUTH_BODY_DIGEST_HEADER)?;
    partition_proxy_header_value(request_head, CLUSTER_AUTH_SIGNATURE_HEADER)?;
    Some(source_node_id)
}

fn partition_proxy_request_with_connection_close(
    request_head: &str,
    buffered_body: &[u8],
) -> io::Result<Vec<u8>> {
    let mut lines = request_head.split("\r\n");
    let request_line = lines
        .next()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cluster partition proxy request line is missing",
            )
        })?;
    let mut forwarded = Vec::with_capacity(request_head.len() + buffered_body.len() + 32);
    forwarded.extend_from_slice(request_line.as_bytes());
    forwarded.extend_from_slice(b"\r\n");
    for line in lines {
        let Some((name, _)) = line.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cluster partition proxy request contains malformed header",
            ));
        };
        if name.trim().eq_ignore_ascii_case("connection")
            || name.trim().eq_ignore_ascii_case("proxy-connection")
            || name
                .trim()
                .eq_ignore_ascii_case(PARTITION_PROXY_BYPASS_HEADER)
        {
            continue;
        }
        forwarded.extend_from_slice(line.as_bytes());
        forwarded.extend_from_slice(b"\r\n");
    }
    forwarded.extend_from_slice(b"Connection: close\r\n\r\n");
    forwarded.extend_from_slice(buffered_body);
    Ok(forwarded)
}

fn spawn_trust_service(
    listen: SocketAddr,
    service_token: &str,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    admission_db_path: &Path,
    policy_path: Option<&Path>,
    advertise_url: &str,
    peer_urls: &[String],
) -> ServerGuard {
    let effective_revocation_db_path = if peer_urls.is_empty() {
        revocation_db_path
    } else {
        admission_db_path
    };
    let mut args = vec![
        "--receipt-db".to_string(),
        receipt_db_path
            .to_str()
            .expect("receipt db path")
            .to_string(),
        "--revocation-db".to_string(),
        effective_revocation_db_path
            .to_str()
            .expect("revocation db path")
            .to_string(),
        "--budget-db".to_string(),
        admission_db_path
            .to_str()
            .expect("admission db path")
            .to_string(),
    ];
    if peer_urls.is_empty() {
        args.push("--authority-db".to_string());
        args.push(
            authority_db_path
                .to_str()
                .expect("authority db path")
                .to_string(),
        );
    }
    args.extend([
        "trust".to_string(),
        "serve".to_string(),
        "--listen".to_string(),
        listen.to_string(),
        "--service-token".to_string(),
        service_token.to_string(),
    ]);
    if peer_urls.is_empty() {
        args.push("--authority-admin-token".to_string());
        args.push("cluster-test-authority-admin-token".to_string());
    } else {
        let cluster_node_key = deterministic_cluster_node_key(advertise_url);
        let cluster_node_seed_path = receipt_db_path.with_extension("cluster-node.seed");
        chio_control_plane::persist_authority_keypair(&cluster_node_seed_path, &cluster_node_key)
            .expect("persist strict cluster node seed");
        let cluster_replay_db_path = receipt_db_path.with_extension("cluster-replay.sqlite3");
        args.extend([
            "--advertise-url".to_string(),
            advertise_url.to_string(),
            "--allow-local-peer-urls".to_string(),
            "--cluster-node-seed-file".to_string(),
            cluster_node_seed_path
                .to_str()
                .expect("cluster node seed path")
                .to_string(),
            "--cluster-replay-db".to_string(),
            cluster_replay_db_path
                .to_str()
                .expect("cluster replay db path")
                .to_string(),
            "--cluster-sync-interval-ms".to_string(),
            "2000".to_string(),
        ]);
        for member_url in std::iter::once(advertise_url).chain(peer_urls.iter().map(String::as_str))
        {
            args.push("--cluster-member".to_string());
            args.push(format!(
                "{member_url}={}",
                deterministic_cluster_node_key(member_url)
                    .public_key()
                    .to_hex()
            ));
        }
        for peer_url in peer_urls {
            args.push("--peer-url".to_string());
            args.push(peer_url.clone());
        }
        register_internal_peer(advertise_url, peer_urls);
    }
    if let Some(policy_path) = policy_path {
        args.push("--policy".to_string());
        args.push(policy_path.to_str().expect("policy path").to_string());
    }
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn chio trust serve");

    ServerGuard { child }
}

fn spawn_partitionable_trust_service(
    listen: SocketAddr,
    service_token: &str,
    receipt_db_path: &Path,
    legacy_revocation_db_path: &Path,
    authority_db_path: &Path,
    admission_db_path: &Path,
    policy_path: Option<&Path>,
    advertise_url: &str,
    peer_urls: &[String],
) -> PartitionableServerGuard {
    let backend = reserve_listen_addr();
    let proxy = spawn_partition_proxy(listen, backend, advertise_url);
    let server = spawn_trust_service(
        backend,
        service_token,
        receipt_db_path,
        legacy_revocation_db_path,
        authority_db_path,
        admission_db_path,
        policy_path,
        advertise_url,
        peer_urls,
    );
    PartitionableServerGuard {
        _server: server,
        _proxy: proxy,
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn wait_until<F>(label: &str, timeout: Duration, mut condition: F)
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("condition `{label}` not satisfied before timeout");
}

fn wait_until_with_diagnostics<F, D>(
    label: &str,
    timeout: Duration,
    mut condition: F,
    diagnostics: D,
) where
    F: FnMut() -> bool,
    D: Fn() -> Value,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let diagnostics = diagnostics();
    panic!(
        "condition `{label}` not satisfied before timeout\n{}",
        serde_json::to_string_pretty(&diagnostics).expect("serialize timeout diagnostics")
    );
}

fn measure_until_with_diagnostics<F, D>(
    label: &str,
    started_at: Instant,
    timeout: Duration,
    mut condition: F,
    diagnostics: D,
) -> u64
where
    F: FnMut() -> bool,
    D: Fn() -> Value,
{
    let deadline = started_at + timeout;
    while Instant::now() < deadline {
        if condition() {
            return u64::try_from(started_at.elapsed().as_millis())
                .expect("latency milliseconds fit u64");
        }
        thread::sleep(Duration::from_millis(50));
    }
    let diagnostics = diagnostics();
    panic!(
        "condition `{label}` not satisfied before timeout\n{}",
        serde_json::to_string_pretty(&diagnostics).expect("serialize timeout diagnostics")
    );
}

fn get_json(client: &Client, url: &str, token: &str) -> Value {
    client
        .get(url)
        .header(AUTHORIZATION, bearer(token))
        .send()
        .expect("send GET")
        .error_for_status()
        .expect("successful GET")
        .json()
        .expect("decode json")
}

fn try_get_json(client: &Client, url: &str, token: &str) -> Option<Value> {
    client
        .get(url)
        .header(AUTHORIZATION, bearer(token))
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .ok()
}

fn try_internal_cluster_status(client: &Client, base_url: &str, _token: &str) -> Option<Value> {
    try_internal_get_json(client, base_url, "/v1/internal/cluster/status")
}

fn try_internal_get_json(client: &Client, base_url: &str, endpoint: &str) -> Option<Value> {
    let node_id = internal_peer_node_id(base_url)?;
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;
    let nonce = uuid::Uuid::new_v4().to_string();
    let body_digest = cluster_empty_body_digest();
    let signature = cluster_peer_auth_signature(
        &node_id,
        base_url,
        "GET",
        endpoint,
        issued_at,
        &nonce,
        None,
        &body_digest,
    );
    let mut request = client
        .get(format!("{base_url}{endpoint}"))
        .header(CLUSTER_NODE_ID_HEADER, node_id)
        .header(CLUSTER_AUTH_METHOD_HEADER, "GET")
        .header(CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string())
        .header(CLUSTER_AUTH_NONCE_HEADER, nonce)
        .header(CLUSTER_AUTH_BODY_DIGEST_HEADER, body_digest)
        .header(CLUSTER_AUTH_SIGNATURE_HEADER, signature);
    if partition_proxy_registered(base_url) {
        request = request.header(PARTITION_PROXY_BYPASS_HEADER, "1");
    }
    request.send().ok()?.error_for_status().ok()?.json().ok()
}

fn post_internal_json_status(
    client: &Client,
    base_url: &str,
    token: &str,
    endpoint: &str,
    node_id: &str,
    term: Option<u64>,
    body: &Value,
) -> (u16, String) {
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;
    let nonce = uuid::Uuid::new_v4().to_string();
    let body_digest = cluster_json_body_digest(body);
    let signature = cluster_peer_auth_signature(
        node_id,
        base_url,
        "POST",
        endpoint,
        issued_at,
        &nonce,
        term,
        &body_digest,
    );
    let mut request = client
        .post(format!("{base_url}{endpoint}"))
        .header(AUTHORIZATION, bearer(token))
        .header(CLUSTER_NODE_ID_HEADER, node_id)
        .header(CLUSTER_AUTH_METHOD_HEADER, "POST")
        .header(CLUSTER_AUTH_ISSUED_AT_HEADER, issued_at.to_string())
        .header(CLUSTER_AUTH_NONCE_HEADER, nonce)
        .header(CLUSTER_AUTH_BODY_DIGEST_HEADER, body_digest)
        .header(CLUSTER_AUTH_SIGNATURE_HEADER, signature);
    if partition_proxy_registered(base_url) {
        request = request.header(PARTITION_PROXY_BYPASS_HEADER, "1");
    }
    if let Some(term) = term {
        request = request.header(CLUSTER_AUTH_TERM_HEADER, term.to_string());
    }
    let response = request.json(body).send().expect("send internal POST");
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    (status, body)
}

fn set_cluster_partition(
    _client: &Client,
    base_url: &str,
    _token: &str,
    blocked_peer_urls: &[String],
) -> Value {
    let registry = partition_proxy_registry()
        .lock()
        .expect("lock partition proxy registry");
    assert!(
        registry.contains_key(base_url),
        "cluster partition source is not registered: {base_url}"
    );
    for blocked_peer_url in blocked_peer_urls {
        assert!(
            registry.contains_key(blocked_peer_url),
            "cluster partition target is not registered: {blocked_peer_url}"
        );
    }
    let blocked = blocked_peer_urls.iter().cloned().collect::<HashSet<_>>();
    for (target_url, control) in registry.iter() {
        control.set_source_blocked(base_url, blocked.contains(target_url));
    }
    let node_count = registry.len();
    let reachable_nodes = node_count.saturating_sub(blocked.len());
    let quorum_size = node_count / 2 + 1;
    let has_quorum = reachable_nodes >= quorum_size;
    json!({
        "selfUrl": base_url,
        "blockedPeerUrls": blocked_peer_urls,
        "leaderUrl": Value::Null,
        "role": if has_quorum { "follower" } else { "candidate" },
        "hasQuorum": has_quorum,
        "reachableNodes": reachable_nodes,
        "quorumSize": quorum_size,
        "electionTerm": Value::Null,
        "authorityLease": Value::Null,
    })
}

fn post_json_status(client: &Client, url: &str, token: &str, body: &Value) -> (u16, String) {
    let response = client
        .post(url)
        .header(AUTHORIZATION, bearer(token))
        .json(body)
        .send()
        .expect("send POST");
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    (status, body)
}

fn cluster_status_diagnostics(client: &Client, urls: &[String], token: &str) -> Value {
    Value::Array(
        urls.iter()
            .map(|base_url| {
                json!({
                    "baseUrl": base_url,
                    "health": try_get_json(client, &format!("{base_url}/health"), token),
                    "clusterStatus": try_internal_cluster_status(client, base_url, token),
                })
            })
            .collect(),
    )
}

fn percentile_nearest_rank(samples: &[u64], percentile: usize) -> u64 {
    assert!(
        !samples.is_empty(),
        "percentiles require at least one sample"
    );
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = ((percentile * sorted.len()).saturating_add(99)) / 100;
    let index = rank.saturating_sub(1).min(sorted.len().saturating_sub(1));
    sorted[index]
}

fn latency_summary(samples: &[u64]) -> Value {
    let min = *samples.iter().min().expect("latency samples");
    let max = *samples.iter().max().expect("latency samples");
    json!({
        "count": samples.len(),
        "minMs": min,
        "maxMs": max,
        "p50Ms": percentile_nearest_rank(samples, 50),
        "p95Ms": percentile_nearest_rank(samples, 95),
        "p99Ms": percentile_nearest_rank(samples, 99),
    })
}

fn multi_region_qualification_report_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join("trust-cluster-qualification")
        .join("298-multi-region-qualification.json")
}

fn write_multi_region_qualification_report(report: &Value) -> PathBuf {
    let path = multi_region_qualification_report_path();
    fs::create_dir_all(path.parent().expect("report parent directory"))
        .expect("create qualification report directory");
    fs::write(
        &path,
        serde_json::to_vec_pretty(report).expect("serialize qualification report"),
    )
    .expect("write qualification report");
    path
}

fn tool_receipt_visible(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
    receipt_id: &str,
) -> bool {
    try_get_json(
        client,
        &format!(
            "{base_url}/v1/receipts/tools?capabilityId={capability_id}&toolServer=wrapped-http-mock&toolName=echo_json&decision=allow&limit=10"
        ),
        token,
    )
    .and_then(|value| value["receipts"].as_array().cloned())
    .is_some_and(|receipts| {
        receipts
            .iter()
            .any(|receipt| receipt["id"].as_str() == Some(receipt_id))
    })
}

fn try_tool_receipt_count(client: &Client, base_url: &str, token: &str) -> Option<u64> {
    try_get_json(
        client,
        &format!("{base_url}/v1/receipts/tools?limit=100"),
        token,
    )?["count"]
        .as_u64()
}

fn node_diagnostics(client: &Client, base_url: &str, token: &str, capability_id: &str) -> Value {
    json!({
        "health": try_get_json(client, &format!("{base_url}/health"), token),
        "clusterStatus": try_internal_cluster_status(client, base_url, token),
        "lineage": try_get_json(
            client,
            &format!("{base_url}/v1/lineage/{capability_id}/chain"),
            token,
        ),
        "budgets": try_get_json(
            client,
            &format!("{base_url}/v1/budgets?capabilityId={capability_id}&limit=10"),
            token,
        ),
    })
}

fn cluster_timeout_diagnostics(
    client: &Client,
    leader_url: &str,
    follower_url: &str,
    token: &str,
    capability_id: &str,
) -> Value {
    json!({
        "leaderUrl": leader_url,
        "followerUrl": follower_url,
        "leader": node_diagnostics(client, leader_url, token, capability_id),
        "follower": node_diagnostics(client, follower_url, token, capability_id),
    })
}

fn wait_for_node_health(client: &Client, base_url: &str, token: &str, label: &str) {
    wait_until_with_diagnostics(
        label,
        Duration::from_secs(30),
        || try_get_json(client, &format!("{base_url}/health"), token).is_some(),
        || {
            json!({
                "baseUrl": base_url,
                "health": try_get_json(client, &format!("{base_url}/health"), token),
                "clusterStatus": try_internal_cluster_status(client, base_url, token),
            })
        },
    );
}

fn post_json(client: &Client, url: &str, token: &str, body: &Value) -> Value {
    let mut last_error = None;
    for _ in 0..120 {
        match client
            .post(url)
            .header(AUTHORIZATION, bearer(token))
            .json(body)
            .send()
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return response.json().expect("decode json");
                }
                let response_body = response.text().unwrap_or_default();
                last_error = Some(format!("{status} body={response_body}"));
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "POST {url} did not succeed after retries: {}",
        last_error.unwrap_or_else(|| "unknown error".to_string())
    );
}

fn post_json_eventually_ok_with_diagnostics<D>(
    client: &Client,
    url: &str,
    token: &str,
    body: &Value,
    label: &str,
    timeout: Duration,
    diagnostics: D,
) -> Value
where
    D: Fn() -> Value,
{
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    while Instant::now() < deadline {
        match client
            .post(url)
            .header(AUTHORIZATION, bearer(token))
            .json(body)
            .send()
        {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    return response.json().expect("decode json");
                }
                let response_body = response.text().unwrap_or_default();
                last_error = Some(format!("{status} body={response_body}"));
            }
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(Duration::from_millis(250));
    }
    let diagnostics = diagnostics();
    panic!(
        "POST {url} did not eventually succeed for `{label}`: {}\n{}",
        last_error.unwrap_or_else(|| "unknown error".to_string()),
        serde_json::to_string_pretty(&diagnostics).expect("serialize timeout diagnostics")
    );
}

fn wait_for_leader_convergence(
    client: &Client,
    service_token: &str,
    url_a: &str,
    url_b: &str,
    expected_leader_url: &str,
) {
    let urls = vec![url_a.to_string(), url_b.to_string()];
    wait_until_with_diagnostics(
        "cluster leader convergence",
        Duration::from_secs(90),
        || {
            let Some(health_a) = try_get_json(client, &format!("{url_a}/health"), service_token)
            else {
                return false;
            };
            let Some(health_b) = try_get_json(client, &format!("{url_b}/health"), service_token)
            else {
                return false;
            };
            let Some(status_a) = try_internal_cluster_status(client, url_a, service_token) else {
                return false;
            };
            let Some(status_b) = try_internal_cluster_status(client, url_b, service_token) else {
                return false;
            };
            health_a.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && health_b.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && status_a.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && status_b.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && status_a.get("electionTerm").and_then(Value::as_u64)
                    == status_b.get("electionTerm").and_then(Value::as_u64)
                && status_a.get("hasQuorum").and_then(Value::as_bool) == Some(true)
                && status_b.get("hasQuorum").and_then(Value::as_bool) == Some(true)
        },
        || cluster_status_diagnostics(client, &urls, service_token),
    );
}

fn wait_for_cluster_leader_convergence(
    client: &Client,
    service_token: &str,
    urls: &[String],
    label: &str,
) -> String {
    let mut converged_leader = None;
    wait_until_with_diagnostics(
        label,
        Duration::from_secs(90),
        || {
            let mut observed = None::<String>;
            for base_url in urls {
                let Some(health) =
                    try_get_json(client, &format!("{base_url}/health"), service_token)
                else {
                    return false;
                };
                let Some(current_leader) = health.get("leaderUrl").and_then(Value::as_str) else {
                    return false;
                };
                // Also require the internal cluster status endpoint to be queryable on every
                // node and to agree on the same leader. Without this, callers can race between
                // /health (which is up early) and /v1/internal/cluster/status (which depends on
                // the cluster state machine being initialized) and observe a transient None.
                let Some(status) = try_internal_cluster_status(client, base_url, service_token)
                else {
                    return false;
                };
                if status.get("leaderUrl").and_then(Value::as_str) != Some(current_leader) {
                    return false;
                }
                if status.get("hasQuorum").and_then(Value::as_bool) != Some(true) {
                    return false;
                }
                if let Some(expected_leader) = observed.as_deref() {
                    if expected_leader != current_leader {
                        return false;
                    }
                } else {
                    observed = Some(current_leader.to_string());
                }
            }
            converged_leader = observed;
            converged_leader.is_some()
        },
        || cluster_status_diagnostics(client, urls, service_token),
    );
    converged_leader.expect("converged leader url")
}

/// Polls `try_internal_cluster_status` against `base_url` until it returns `Some`.
///
/// The internal cluster status endpoint can transiently fail with HTTP errors during cluster
/// state transitions (initial bring-up, leader failover, follower restart) even when the node's
/// `/health` endpoint is already up. Single-shot callers that immediately panic on `None` are
/// the source of intermittent flakes.
/// This helper bounds the wait with a deadline and returns the first non-`None` snapshot.
fn wait_for_internal_cluster_status(
    client: &Client,
    base_url: &str,
    token: &str,
    label: &str,
) -> Value {
    let timeout = Duration::from_secs(30);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = try_internal_cluster_status(client, base_url, token) {
            return status;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let diagnostics = json!({
        "baseUrl": base_url,
        "health": try_get_json(client, &format!("{base_url}/health"), token),
        "clusterStatus": try_internal_cluster_status(client, base_url, token),
    });
    panic!(
        "internal cluster status `{label}` did not become available before timeout\n{}",
        serde_json::to_string_pretty(&diagnostics).expect("serialize timeout diagnostics")
    );
}

fn sample_receipt(id: &str, capability_id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(json!({"message": "cluster"}))
        .expect("hash receipt parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: capability_id.to_string(),
            tool_server: "wrapped-http-mock".to_string(),
            tool_name: "echo_json".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign receipt")
}

fn sample_child_receipt(id: &str, request_suffix: &str) -> ChildRequestReceipt {
    let keypair = Keypair::generate();
    ChildRequestReceipt::sign(
        ChildRequestReceiptBody {
            id: id.to_string(),
            timestamp: 2,
            session_id: SessionId::new(format!("sess-{request_suffix}")),
            parent_request_id: RequestId::new(format!("parent-{request_suffix}")),
            request_id: RequestId::new(format!("child-{request_suffix}")),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: "outcome-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            metadata: Some(json!({ "source": "trust-cluster" })),
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign child receipt")
}

fn sample_capability(id: &str, subject_kp: &Keypair, issuer_kp: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: ChioScope::default(),
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer_kp,
    )
    .expect("sign capability")
}

fn sample_delegated_capability(
    id: &str,
    subject_kp: &Keypair,
    delegator_kp: &Keypair,
    parent: &CapabilityToken,
) -> CapabilityToken {
    let issued_at = parent.issued_at.saturating_add(1);
    let mut delegation_chain = parent.delegation_chain.clone();
    delegation_chain.push(
        DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent.id.clone(),
                delegator: delegator_kp.public_key(),
                delegatee: subject_kp.public_key(),
                attenuations: Vec::new(),
                timestamp: issued_at,
                scope_hash: None,
                aggregate_budget: None,
                cumulative_approval: None,
                aggregate_family_preservation: None,
            },
            delegator_kp,
        )
        .expect("sign delegation link"),
    );
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: delegator_kp.public_key(),
            subject: subject_kp.public_key(),
            scope: parent.scope.clone(),
            issued_at,
            expires_at: parent.expires_at,
            delegation_chain,
            aggregate_invocation_budget: None,
        },
        delegator_kp,
    )
    .expect("sign delegated capability")
}

fn assert_write_visibility_metadata(response: &Value) -> &str {
    assert_eq!(
        response["visibleAtLeader"].as_bool(),
        Some(true),
        "expected leader-visible write metadata: {response}"
    );
    let leader_url = response["leaderUrl"].as_str().expect("leaderUrl metadata");
    assert_eq!(response["handledBy"].as_str(), Some(leader_url));
    leader_url
}

fn assert_expected_write_visibility_metadata(response: &Value, leader_url: &str) {
    assert_eq!(assert_write_visibility_metadata(response), leader_url);
}

fn assert_leader_visible_metadata(response: &Value) {
    assert_eq!(response["visibleAtLeader"].as_bool(), Some(true));
    assert!(response["leaderUrl"].as_str().is_some());
    assert!(response["handledBy"].as_str().is_some());
}

fn assert_budget_commit_metadata(
    response: &Value,
    expected_authority_id: &str,
    quorum_size: u64,
    committed_nodes: u64,
    expected_witnesses: &[&str],
) {
    let commit = &response["budgetCommit"];
    assert_eq!(commit["authorityId"].as_str(), Some(expected_authority_id));
    assert_eq!(commit["budgetTerm"], commit["leaseEpoch"]);
    assert_eq!(commit["quorumCommitted"].as_bool(), Some(true));
    assert_eq!(commit["quorumSize"].as_u64(), Some(quorum_size));
    assert_eq!(commit["committedNodes"].as_u64(), Some(committed_nodes));
    assert!(
        commit["budgetSeq"].as_u64().unwrap_or(0) > 0,
        "expected positive budget seq in commit metadata: {commit}"
    );
    assert!(
        commit["commitIndex"].as_u64().unwrap_or(0)
            >= commit["budgetSeq"].as_u64().unwrap_or(u64::MAX),
        "consensus commit index must cover the budget mutation: {commit}"
    );
    let witnesses = commit["witnessUrls"]
        .as_array()
        .expect("budget commit witnesses array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert_eq!(witnesses.len(), expected_witnesses.len());
    for witness in expected_witnesses {
        assert!(
            witnesses.contains(witness),
            "missing witness `{witness}` in budget commit metadata: {commit}"
        );
    }
}

fn assert_budget_authority_metadata(
    response: &Value,
    expected_authority_id: &str,
    expected_guarantee_level: &str,
) {
    let authority = &response["budgetAuthority"];
    assert_eq!(
        authority["authorityId"].as_str(),
        Some(expected_authority_id)
    );
    assert!(
        authority["leaderUrl"]
            .as_str()
            .is_some_and(|leader_url| !leader_url.is_empty()),
        "expected non-empty consensus leader URL: {authority}"
    );
    assert_eq!(
        authority["guaranteeLevel"].as_str(),
        Some(expected_guarantee_level)
    );
    assert!(
        authority["budgetTerm"].as_u64().unwrap_or(0) > 0,
        "expected positive budget term in authority metadata: {authority}"
    );
    assert_eq!(authority["leaseEpoch"], authority["budgetTerm"]);
    assert!(
        authority["leaseId"]
            .as_str()
            .unwrap_or_default()
            .contains(expected_authority_id),
        "expected lease id to include authority id: {authority}"
    );
}

fn assert_authority_generation(client: &Client, base_url: &str, token: &str, expected: u64) {
    let authority_url = format!("{base_url}/v1/authority");
    let mut authority = None;
    wait_until_with_diagnostics(
        &format!("authority generation {expected} visible at {base_url}"),
        Duration::from_secs(90),
        || {
            authority = try_get_json(client, &authority_url, token);
            authority
                .as_ref()
                .and_then(|value| value["generation"].as_u64())
                == Some(expected)
        },
        || {
            json!({
                "baseUrl": base_url,
                "health": try_get_json(client, &format!("{base_url}/health"), token),
                "clusterStatus": try_internal_cluster_status(client, base_url, token),
                "authority": try_get_json(client, &authority_url, token),
            })
        },
    );
    let authority = authority.expect("matching authority generation observed");
    assert_eq!(authority["generation"].as_u64(), Some(expected));
}

fn assert_tool_receipt_visible(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
    receipt_id: &str,
) {
    let receipts = get_json(
        client,
        &format!(
            "{base_url}/v1/receipts/tools?capabilityId={capability_id}&toolServer=wrapped-http-mock&toolName=echo_json&decision=allow&limit=10"
        ),
        token,
    );
    let receipts = receipts["receipts"]
        .as_array()
        .expect("tool receipts array");
    assert!(receipts
        .iter()
        .any(|receipt| receipt["id"].as_str() == Some(receipt_id)));
}

fn assert_child_receipt_visible(
    client: &Client,
    base_url: &str,
    token: &str,
    request_id: &str,
    receipt_id: &str,
) {
    let url = format!("{base_url}/v1/receipts/children?requestId={request_id}&limit=10");
    wait_until_with_diagnostics(
        &format!("child receipt {receipt_id} visible for {request_id}"),
        Duration::from_secs(30),
        || {
            let Some(receipts) = try_get_json(client, &url, token) else {
                return false;
            };
            receipts["receipts"]
                .as_array()
                .map(|receipts| {
                    receipts
                        .iter()
                        .any(|receipt| receipt["id"].as_str() == Some(receipt_id))
                })
                .unwrap_or(false)
        },
        || {
            json!({
                "url": url,
                "health": try_get_json(client, &format!("{base_url}/health"), token),
                "children": try_get_json(client, &url, token),
            })
        },
    );
}

fn assert_revocation_visible(client: &Client, base_url: &str, token: &str, capability_id: &str) {
    let revocations = get_json(
        client,
        &format!("{base_url}/v1/revocations?capabilityId={capability_id}&limit=10"),
        token,
    );
    assert_eq!(revocations["revoked"].as_bool(), Some(true));
    assert!(revocations["revocations"]
        .as_array()
        .expect("revocations array")
        .iter()
        .any(|entry| entry["capabilityId"].as_str() == Some(capability_id)));
}

fn assert_budget_invocation_count(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
    grant_index: u64,
    expected: u64,
) {
    let budgets = get_json(
        client,
        &format!("{base_url}/v1/budgets?capabilityId={capability_id}&limit=10"),
        token,
    );
    let usage = budgets["usages"]
        .as_array()
        .expect("budgets array")
        .iter()
        .find(|usage| usage["grantIndex"].as_u64() == Some(grant_index))
        .expect("matching budget usage");
    assert_eq!(usage["invocationCount"].as_u64(), Some(expected));
}

fn assert_budget_totals(
    client: &Client,
    base_url: &str,
    token: &str,
    capability_id: &str,
    grant_index: u64,
    expected_exposure: u64,
    expected_realized_spend: u64,
) {
    let budgets = get_json(
        client,
        &format!("{base_url}/v1/budgets?capabilityId={capability_id}&limit=10"),
        token,
    );
    let usage = budgets["usages"]
        .as_array()
        .expect("budgets array")
        .iter()
        .find(|usage| usage["grantIndex"].as_u64() == Some(grant_index))
        .expect("matching budget usage");
    assert_eq!(
        usage["totalExposureCharged"].as_u64(),
        Some(expected_exposure)
    );
    assert_eq!(
        usage["totalRealizedSpend"].as_u64(),
        Some(expected_realized_spend)
    );
}

#[cfg(unix)]
fn send_signal(child: &Child, signal: &str) {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(child.id().to_string())
        .status()
        .expect("send signal to child");
    assert!(
        status.success(),
        "signal {signal} should succeed for child {}",
        child.id()
    );
}

fn assert_lineage_visible(client: &Client, base_url: &str, token: &str, capability_id: &str) {
    wait_until_with_diagnostics(
        &format!("lineage visible for {capability_id}"),
        Duration::from_secs(20),
        || {
            let Some(lineage) = try_get_json(
                client,
                &format!("{base_url}/v1/lineage/{capability_id}"),
                token,
            ) else {
                return false;
            };
            lineage["capabilityId"]
                .as_str()
                .or_else(|| lineage["capability_id"].as_str())
                == Some(capability_id)
        },
        || node_diagnostics(client, base_url, token, capability_id),
    );
}

include!("trust_cluster/core_scenarios.rs");

include!("trust_cluster/snapshot_and_partition.rs");
