#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_core::capability::{
    ArcScope, CapabilityToken, CapabilityTokenBody, Constraint, MonetaryAmount, Operation,
    ToolGrant,
};
use arc_core::crypto::Keypair;
use arc_core::receipt::{
    ArcReceipt, ArcReceiptBody, ChildRequestReceipt, ChildRequestReceiptBody, Decision,
    ToolCallAction,
};
use arc_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use arc_kernel::BudgetStore;
use arc_store_sqlite::SqliteBudgetStore;
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde_json::{json, Value};

const TRUST_CLUSTER_QUALIFICATION_RUNS: usize = 5;
const MULTI_REGION_PARTITION_SAMPLES: usize = 20;

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("arc-cli-trust-cluster-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn reserve_listen_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
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

fn spawn_trust_service(
    listen: SocketAddr,
    service_token: &str,
    receipt_db_path: &Path,
    revocation_db_path: &Path,
    authority_db_path: &Path,
    budget_db_path: &Path,
    policy_path: Option<&Path>,
    advertise_url: &str,
    peer_urls: &[String],
) -> ServerGuard {
    let mut args = vec![
        "--receipt-db".to_string(),
        receipt_db_path
            .to_str()
            .expect("receipt db path")
            .to_string(),
        "--revocation-db".to_string(),
        revocation_db_path
            .to_str()
            .expect("revocation db path")
            .to_string(),
        "--authority-db".to_string(),
        authority_db_path
            .to_str()
            .expect("authority db path")
            .to_string(),
        "--budget-db".to_string(),
        budget_db_path.to_str().expect("budget db path").to_string(),
        "trust".to_string(),
        "serve".to_string(),
        "--listen".to_string(),
        listen.to_string(),
        "--service-token".to_string(),
        service_token.to_string(),
        "--advertise-url".to_string(),
        advertise_url.to_string(),
        "--cluster-sync-interval-ms".to_string(),
        "200".to_string(),
    ];
    for peer_url in peer_urls {
        args.push("--peer-url".to_string());
        args.push(peer_url.clone());
    }
    if let Some(policy_path) = policy_path {
        args.push("--policy".to_string());
        args.push(policy_path.to_str().expect("policy path").to_string());
    }

    let child = Command::new(env!("CARGO_BIN_EXE_arc"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn arc trust serve");

    ServerGuard { child }
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
    timeout: Duration,
    mut condition: F,
    diagnostics: D,
) -> u64
where
    F: FnMut() -> bool,
    D: Fn() -> Value,
{
    let started_at = Instant::now();
    let deadline = started_at + timeout;
    while Instant::now() < deadline {
        if condition() {
            return started_at.elapsed().as_millis() as u64;
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

fn try_internal_cluster_status(client: &Client, base_url: &str, token: &str) -> Option<Value> {
    try_get_json(
        client,
        &format!("{base_url}/v1/internal/cluster/status"),
        token,
    )
}

fn set_cluster_partition(
    client: &Client,
    base_url: &str,
    token: &str,
    blocked_peer_urls: &[String],
) -> Value {
    post_json(
        client,
        &format!("{base_url}/v1/internal/cluster/partition"),
        token,
        &json!({ "blockedPeerUrls": blocked_peer_urls }),
    )
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
    .map(|receipts| {
        receipts
            .iter()
            .any(|receipt| receipt["id"].as_str() == Some(receipt_id))
    })
    .unwrap_or(false)
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

fn tool_receipt_count(client: &Client, base_url: &str, token: &str) -> u64 {
    get_json(
        client,
        &format!("{base_url}/v1/receipts/tools?limit=100"),
        token,
    )["count"]
        .as_u64()
        .expect("tool receipt count")
}

fn node_diagnostics(client: &Client, base_url: &str, token: &str, capability_id: &str) -> Value {
    json!({
        "health": try_get_json(client, &format!("{base_url}/health"), token),
        "clusterStatus": try_get_json(
            client,
            &format!("{base_url}/v1/internal/cluster/status"),
            token,
        ),
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

fn post_json(client: &Client, url: &str, token: &str, body: &Value) -> Value {
    let mut last_error = None;
    for _ in 0..4 {
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

fn wait_for_leader_convergence(
    client: &Client,
    service_token: &str,
    url_a: &str,
    url_b: &str,
    expected_leader_url: &str,
) {
    wait_until(
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
            health_a.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
                && health_b.get("leaderUrl").and_then(Value::as_str) == Some(expected_leader_url)
        },
    );
}

fn sample_receipt(id: &str, capability_id: &str) -> ArcReceipt {
    let keypair = Keypair::generate();
    ArcReceipt::sign(
        ArcReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: capability_id.to_string(),
            tool_server: "wrapped-http-mock".to_string(),
            tool_name: "echo_json".to_string(),
            action: ToolCallAction {
                parameters: json!({"message": "cluster"}),
                parameter_hash: "param-hash".to_string(),
            },
            decision: Decision::Allow,
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: arc_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
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
            session_id: SessionId::new(&format!("sess-{request_suffix}")),
            parent_request_id: RequestId::new(&format!("parent-{request_suffix}")),
            request_id: RequestId::new(&format!("child-{request_suffix}")),
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
            scope: ArcScope::default(),
            issued_at: 1_000,
            expires_at: 9_000,
            delegation_chain: vec![],
        },
        issuer_kp,
    )
    .expect("sign capability")
}

fn assert_write_visibility_metadata<'a>(response: &'a Value) -> &'a str {
    assert_eq!(response["visibleAtLeader"].as_bool(), Some(true));
    let leader_url = response["leaderUrl"].as_str().expect("leaderUrl metadata");
    assert_eq!(response["handledBy"].as_str(), Some(leader_url));
    leader_url
}

fn assert_expected_write_visibility_metadata(response: &Value, leader_url: &str) {
    assert_eq!(assert_write_visibility_metadata(response), leader_url);
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
    assert_eq!(commit["commitIndex"], commit["budgetSeq"]);
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
    assert_eq!(authority["leaderUrl"].as_str(), Some(expected_authority_id));
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
    let authority = get_json(client, &format!("{base_url}/v1/authority"), token);
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
    let receipts = get_json(
        client,
        &format!("{base_url}/v1/receipts/children?requestId={request_id}&limit=10"),
        token,
    );
    let receipts = receipts["receipts"]
        .as_array()
        .expect("child receipts array");
    assert!(receipts
        .iter()
        .any(|receipt| receipt["id"].as_str() == Some(receipt_id)));
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
    let lineage = get_json(
        client,
        &format!("{base_url}/v1/lineage/{capability_id}"),
        token,
    );
    assert_eq!(
        lineage["capabilityId"]
            .as_str()
            .or_else(|| lineage["capability_id"].as_str()),
        Some(capability_id)
    );
}

fn run_trust_control_cluster_proving_scenario(run_index: usize, run_total: usize) {
    println!("trust-cluster proving run {run_index}/{run_total}");

    let dir = unique_test_dir().join(format!("run-{run_index}-of-{run_total}"));
    fs::create_dir_all(&dir).expect("create test dir");
    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let service_token = "cluster-token";

    let receipt_db_a = dir.join("receipts-a.sqlite3");
    let revocation_db_a = dir.join("revocations-a.sqlite3");
    let authority_db_a = dir.join("authority-a.sqlite3");
    let budget_db_a = dir.join("budgets-a.sqlite3");
    let receipt_db_b = dir.join("receipts-b.sqlite3");
    let revocation_db_b = dir.join("revocations-b.sqlite3");
    let authority_db_b = dir.join("authority-b.sqlite3");
    let budget_db_b = dir.join("budgets-b.sqlite3");

    let mut server_a = Some(spawn_trust_service(
        addr_a,
        service_token,
        &receipt_db_a,
        &revocation_db_a,
        &authority_db_a,
        &budget_db_a,
        None,
        &url_a,
        std::slice::from_ref(&url_b.to_string()),
    ));
    let mut server_b = Some(spawn_trust_service(
        addr_b,
        service_token,
        &receipt_db_b,
        &revocation_db_b,
        &authority_db_b,
        &budget_db_b,
        None,
        &url_b,
        std::slice::from_ref(&url_a.to_string()),
    ));

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build client");

    wait_until("node A health reachable", Duration::from_secs(20), || {
        try_get_json(&client, &format!("{url_a}/health"), service_token).is_some()
    });
    wait_until("node B health reachable", Duration::from_secs(20), || {
        try_get_json(&client, &format!("{url_b}/health"), service_token).is_some()
    });
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let leader_url = expected_leader_url;
    let follower_url = if leader_url == url_a {
        url_b.clone()
    } else {
        url_a.clone()
    };

    assert_authority_generation(&client, &leader_url, service_token, 1);

    let rotated_leader = post_json(
        &client,
        &format!("{leader_url}/v1/authority"),
        service_token,
        &json!({}),
    );
    assert_eq!(rotated_leader["generation"].as_u64(), Some(2));
    assert_expected_write_visibility_metadata(&rotated_leader, &leader_url);
    assert_authority_generation(&client, &leader_url, service_token, 2);

    let rotated_follower = post_json(
        &client,
        &format!("{follower_url}/v1/authority"),
        service_token,
        &json!({}),
    );
    assert_eq!(rotated_follower["generation"].as_u64(), Some(3));
    assert_expected_write_visibility_metadata(&rotated_follower, &leader_url);
    assert_authority_generation(&client, &leader_url, service_token, 3);

    wait_until(
        "authority generation replication",
        Duration::from_secs(90),
        || {
            try_get_json(
                &client,
                &format!("{follower_url}/v1/authority"),
                service_token,
            )
            .and_then(|value| value["generation"].as_u64())
                == Some(3)
        },
    );

    let leader_tool_receipt =
        serde_json::to_value(sample_receipt("cluster-tool-leader", "cap-tool-leader"))
            .expect("tool receipt json");
    let stored_leader_tool = post_json(
        &client,
        &format!("{leader_url}/v1/receipts/tools"),
        service_token,
        &leader_tool_receipt,
    );
    assert_eq!(stored_leader_tool["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_leader_tool, &leader_url);
    assert_tool_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "cap-tool-leader",
        "cluster-tool-leader",
    );

    let follower_tool_receipt =
        serde_json::to_value(sample_receipt("cluster-tool-follower", "cap-tool-follower"))
            .expect("tool receipt json");
    let stored_follower_tool = post_json(
        &client,
        &format!("{follower_url}/v1/receipts/tools"),
        service_token,
        &follower_tool_receipt,
    );
    assert_eq!(stored_follower_tool["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_follower_tool, &leader_url);
    assert_tool_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "cap-tool-follower",
        "cluster-tool-follower",
    );

    wait_until("tool receipt replication", Duration::from_secs(90), || {
        try_get_json(
            &client,
            &format!("{follower_url}/v1/receipts/tools?limit=10"),
            service_token,
        )
        .and_then(|value| value["count"].as_u64())
            == Some(2)
    });

    let leader_child_receipt =
        serde_json::to_value(sample_child_receipt("cluster-child-leader", "leader"))
            .expect("child receipt json");
    let stored_leader_child = post_json(
        &client,
        &format!("{leader_url}/v1/receipts/children"),
        service_token,
        &leader_child_receipt,
    );
    assert_eq!(stored_leader_child["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_leader_child, &leader_url);
    assert_child_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "child-leader",
        "cluster-child-leader",
    );

    let follower_child_receipt =
        serde_json::to_value(sample_child_receipt("cluster-child-follower", "follower"))
            .expect("child receipt json");
    let stored_follower_child = post_json(
        &client,
        &format!("{follower_url}/v1/receipts/children"),
        service_token,
        &follower_child_receipt,
    );
    assert_eq!(stored_follower_child["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_follower_child, &leader_url);
    assert_child_receipt_visible(
        &client,
        &leader_url,
        service_token,
        "child-follower",
        "cluster-child-follower",
    );

    wait_until("child receipt replication", Duration::from_secs(90), || {
        try_get_json(
            &client,
            &format!("{follower_url}/v1/receipts/children?limit=10"),
            service_token,
        )
        .and_then(|value| value["count"].as_u64())
            == Some(2)
    });

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let child_kp = Keypair::generate();
    let root_capability = sample_capability("cluster-lineage-root", &root_kp, &issuer_kp);
    let child_capability = sample_capability("cluster-lineage-child", &child_kp, &issuer_kp);

    let stored_root_lineage = post_json(
        &client,
        &format!("{leader_url}/v1/lineage"),
        service_token,
        &json!({
            "capability": root_capability,
        }),
    );
    assert_eq!(stored_root_lineage["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_root_lineage, &leader_url);
    assert_lineage_visible(&client, &leader_url, service_token, "cluster-lineage-root");

    let stored_child_lineage = post_json(
        &client,
        &format!("{follower_url}/v1/lineage"),
        service_token,
        &json!({
            "capability": child_capability,
            "parentCapabilityId": "cluster-lineage-root",
        }),
    );
    assert_eq!(stored_child_lineage["stored"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&stored_child_lineage, &leader_url);
    assert_lineage_visible(&client, &leader_url, service_token, "cluster-lineage-child");

    wait_until_with_diagnostics(
        "lineage replication",
        Duration::from_secs(90),
        || {
            let Some(lineage) = try_get_json(
                &client,
                &format!("{follower_url}/v1/lineage/cluster-lineage-child/chain"),
                service_token,
            ) else {
                return false;
            };
            let Some(chain) = lineage.as_array() else {
                return false;
            };
            chain.len() == 2
                && chain[0]["capability_id"].as_str() == Some("cluster-lineage-root")
                && chain[1]["capability_id"].as_str() == Some("cluster-lineage-child")
        },
        || {
            cluster_timeout_diagnostics(
                &client,
                &leader_url,
                &follower_url,
                service_token,
                "cluster-lineage-child",
            )
        },
    );

    let revoked_leader = post_json(
        &client,
        &format!("{leader_url}/v1/revocations"),
        service_token,
        &json!({"capabilityId": "cap-revoke-leader"}),
    );
    assert_eq!(revoked_leader["revoked"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&revoked_leader, &leader_url);
    assert_revocation_visible(&client, &leader_url, service_token, "cap-revoke-leader");

    let revoked_follower = post_json(
        &client,
        &format!("{follower_url}/v1/revocations"),
        service_token,
        &json!({"capabilityId": "cap-revoke-follower"}),
    );
    assert_eq!(revoked_follower["revoked"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&revoked_follower, &leader_url);
    assert_revocation_visible(&client, &leader_url, service_token, "cap-revoke-follower");

    wait_until("revocation replication", Duration::from_secs(90), || {
        let leader_revocation = try_get_json(
            &client,
            &format!("{follower_url}/v1/revocations?capabilityId=cap-revoke-leader&limit=1"),
            service_token,
        )
        .and_then(|value| value["revoked"].as_bool());
        let follower_revocation = try_get_json(
            &client,
            &format!("{follower_url}/v1/revocations?capabilityId=cap-revoke-follower&limit=1"),
            service_token,
        )
        .and_then(|value| value["revoked"].as_bool());
        leader_revocation == Some(true) && follower_revocation == Some(true)
    });

    let leader_budget = post_json(
        &client,
        &format!("{leader_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(leader_budget["allowed"].as_bool(), Some(true));
    assert_eq!(leader_budget["invocationCount"].as_u64(), Some(1));
    assert_expected_write_visibility_metadata(&leader_budget, &leader_url);
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 1);

    let second_budget = post_json(
        &client,
        &format!("{follower_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(second_budget["allowed"].as_bool(), Some(true));
    assert_eq!(second_budget["invocationCount"].as_u64(), Some(2));
    assert_expected_write_visibility_metadata(&second_budget, &leader_url);
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 2);

    let rapid_budget = post_json(
        &client,
        &format!("{leader_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(rapid_budget["allowed"].as_bool(), Some(true));
    assert_eq!(rapid_budget["invocationCount"].as_u64(), Some(3));
    assert_expected_write_visibility_metadata(&rapid_budget, &leader_url);
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 3);

    wait_until_with_diagnostics(
        "follower budget visibility",
        Duration::from_secs(90),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!("{follower_url}/v1/budgets?capabilityId=cap-shared&limit=10"),
                service_token,
            ) else {
                return false;
            };
            budgets["count"].as_u64() == Some(1)
                && budgets["usages"][0]["invocationCount"].as_u64() == Some(3)
        },
        || {
            cluster_timeout_diagnostics(
                &client,
                &leader_url,
                &follower_url,
                service_token,
                "cap-shared",
            )
        },
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 3);
    assert_budget_invocation_count(&client, &follower_url, service_token, "cap-shared", 0, 3);
    assert_budget_totals(&client, &leader_url, service_token, "cap-shared", 0, 0, 0);

    let authorized_budget = post_json(
        &client,
        &format!("{follower_url}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4,
            "exposureUnits": 75,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-shared-hold-1",
            "eventId": "cap-shared-hold-1:authorize"
        }),
    );
    assert_eq!(authorized_budget["allowed"].as_bool(), Some(true));
    assert_eq!(authorized_budget["invocationCount"].as_u64(), Some(4));
    assert_eq!(authorized_budget["totalExposureCharged"].as_u64(), Some(75));
    assert_eq!(authorized_budget["totalRealizedSpend"].as_u64(), Some(0));
    assert_expected_write_visibility_metadata(&authorized_budget, &leader_url);
    assert_budget_authority_metadata(&authorized_budget, &leader_url, "ha_quorum_commit");
    assert_budget_commit_metadata(
        &authorized_budget,
        &leader_url,
        2,
        2,
        &[leader_url.as_str(), follower_url.as_str()],
    );
    assert_budget_invocation_count(&client, &leader_url, service_token, "cap-shared", 0, 4);
    assert_budget_totals(&client, &leader_url, service_token, "cap-shared", 0, 75, 0);

    let survivor_url = if leader_url == url_a {
        drop(server_a.take());
        url_b.clone()
    } else {
        drop(server_b.take());
        url_a.clone()
    };
    wait_until(
        "quorum loss after leader failure",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &survivor_url, service_token)
            else {
                return false;
            };
            status["leaderUrl"].is_null()
                && status["hasQuorum"].as_bool() == Some(false)
                && status["reachableNodes"].as_u64() == Some(1)
        },
    );

    let (status, body) = post_json_status(
        &client,
        &format!("{survivor_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("quorum") || body.contains("leader"),
        "expected quorum failure body, got: {body}"
    );

    let budgets = get_json(
        &client,
        &format!("{survivor_url}/v1/budgets?capabilityId=cap-shared&limit=10"),
        service_token,
    );
    assert_eq!(budgets["count"].as_u64(), Some(1));
    assert_eq!(budgets["usages"][0]["invocationCount"].as_u64(), Some(4));
    assert_eq!(
        budgets["usages"][0]["totalExposureCharged"].as_u64(),
        Some(75)
    );
}

#[test]
fn trust_control_cluster_replicates_state_and_fails_closed_without_quorum() {
    run_trust_control_cluster_proving_scenario(1, 1);
}

#[test]
#[ignore = "qualification lane exercises trust-control runtime assurance issuance"]
fn trust_cluster_runtime_assurance_policy_gates_capability_issuance() {
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");

    let addr = reserve_listen_addr();
    let base_url = format!("http://{addr}");
    let service_token = "runtime-assurance-token";
    let receipt_db = dir.join("receipts.sqlite3");
    let revocation_db = dir.join("revocations.sqlite3");
    let authority_db = dir.join("authority.sqlite3");
    let budget_db = dir.join("budgets.sqlite3");
    let policy_path = dir.join("runtime-assurance-policy.yaml");
    fs::write(
        &policy_path,
        r#"
hushspec: "0.1.0"
name: runtime-assurance
rules:
  tool_access:
    enabled: true
    allow: ["payments.charge"]
extensions:
  runtime_assurance:
    tiers:
      baseline:
        minimum_attestation_tier: none
        max_scope:
          operations: ["invoke"]
          max_invocations: 5
          max_cost_per_invocation:
            units: 50
            currency: USD
          max_total_cost:
            units: 100
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 30
      attested:
        minimum_attestation_tier: attested
        max_scope:
          operations: ["invoke"]
          max_invocations: 20
          max_cost_per_invocation:
            units: 250
            currency: USD
          max_total_cost:
            units: 1000
            currency: USD
          max_delegation_depth: 0
          ttl_seconds: 300
"#,
    )
    .expect("write policy");

    let _server = spawn_trust_service(
        addr,
        service_token,
        &receipt_db,
        &revocation_db,
        &authority_db,
        &budget_db,
        Some(&policy_path),
        &base_url,
        &[],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build client");
    wait_until(
        "runtime assurance health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
    );

    let health = get_json(&client, &format!("{base_url}/health"), service_token);
    assert_eq!(
        health["federation"]["runtimeAssurancePolicyConfigured"].as_bool(),
        Some(true)
    );

    let subject = Keypair::generate();
    let runtime_attestation =
        serde_json::to_value(arc_core::capability::RuntimeAttestationEvidence {
            schema: "arc.runtime-attestation.v1".to_string(),
            verifier: "verifier.arc".to_string(),
            tier: arc_core::capability::RuntimeAssuranceTier::Attested,
            issued_at: 1,
            expires_at: 4_102_444_800u64,
            evidence_sha256: "attestation-digest".to_string(),
            runtime_identity: Some("spiffe://arc/runtime/test".to_string()),
            workload_identity: None,
            claims: None,
        })
        .expect("serialize runtime attestation");
    let scope = ArcScope {
        grants: vec![ToolGrant {
            server_id: "payments".to_string(),
            tool_name: "charge".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::GovernedIntentRequired],
            max_invocations: Some(10),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 250,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1_000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    };

    let denied = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&json!({
            "subjectPublicKey": subject.public_key().to_hex(),
            "scope": scope,
            "ttlSeconds": 120
        }))
        .send()
        .expect("send denied issue request");
    assert_eq!(denied.status().as_u16(), 403);

    let allowed = client
        .post(format!("{base_url}/v1/capabilities/issue"))
        .header(AUTHORIZATION, bearer(service_token))
        .json(&json!({
            "subjectPublicKey": subject.public_key().to_hex(),
            "scope": scope,
            "ttlSeconds": 120,
            "runtimeAttestation": runtime_attestation
        }))
        .send()
        .expect("send allowed issue request");
    assert_eq!(allowed.status().as_u16(), 200);
    let allowed_json: serde_json::Value = allowed.json().expect("parse allowed issue response");
    let capability: CapabilityToken =
        serde_json::from_value(allowed_json["capability"].clone()).expect("decode capability");
    assert!(
        capability.scope.grants[0]
            .constraints
            .contains(&Constraint::MinimumRuntimeAssurance(
                arc_core::capability::RuntimeAssuranceTier::Attested
            )),
        "issued capability should retain the required runtime assurance tier"
    );
}

#[test]
fn trust_control_cluster_requires_quorum_and_heals_after_partition() {
    let dir = unique_test_dir().join("quorum-heal");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-quorum-token";
    let expected_leader_url = url_a.clone();
    let majority_urls = vec![url_a.clone(), url_b.clone()];
    let isolated_url = url_c.clone();

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );
    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &dir.join("receipts-c.sqlite3"),
        &dir.join("revocations-c.sqlite3"),
        &dir.join("authority-c.sqlite3"),
        &dir.join("budgets-c.sqlite3"),
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build client");

    for base_url in &urls {
        wait_until(
            "cluster node health reachable",
            Duration::from_secs(20),
            || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
        );
    }

    wait_until_with_diagnostics(
        "three-node quorum convergence",
        Duration::from_secs(90),
        || {
            urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["quorumSize"].as_u64() == Some(2)
                    && status["reachableNodes"].as_u64() == Some(3)
            })
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    for base_url in &majority_urls {
        let response = set_cluster_partition(
            &client,
            base_url,
            service_token,
            std::slice::from_ref(&isolated_url),
        );
        assert_eq!(response["hasQuorum"].as_bool(), Some(true));
    }
    let isolated_response = set_cluster_partition(
        &client,
        &isolated_url,
        service_token,
        &[url_a.clone(), url_b.clone()],
    );
    assert_eq!(isolated_response["hasQuorum"].as_bool(), Some(false));

    wait_until_with_diagnostics(
        "minority partition loses quorum",
        Duration::from_secs(90),
        || {
            let majority_ok = majority_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            });
            let Some(isolated_status) =
                try_internal_cluster_status(&client, &isolated_url, service_token)
            else {
                return false;
            };
            majority_ok
                && isolated_status["leaderUrl"].is_null()
                && isolated_status["hasQuorum"].as_bool() == Some(false)
                && isolated_status["reachableNodes"].as_u64() == Some(1)
                && isolated_status["role"].as_str() == Some("candidate")
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    let (status, body) = post_json_status(
        &client,
        &format!("{isolated_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-quorum-heal",
            "grantIndex": 0,
            "maxInvocations": 5
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("quorum") || body.contains("leader"),
        "expected quorum failure body, got: {body}"
    );

    let majority_write = post_json(
        &client,
        &format!("{url_b}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-quorum-heal",
            "grantIndex": 0,
            "maxInvocations": 5
        }),
    );
    assert_eq!(majority_write["allowed"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&majority_write, &expected_leader_url);

    for base_url in &urls {
        let response = set_cluster_partition(&client, base_url, service_token, &[]);
        assert_eq!(
            response["blockedPeerUrls"].as_array().map(Vec::len),
            Some(0)
        );
    }

    wait_until_with_diagnostics(
        "three-node quorum heal convergence",
        Duration::from_secs(90),
        || {
            urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(3)
            })
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );

    wait_until_with_diagnostics(
        "healed minority catches up from snapshot",
        Duration::from_secs(90),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!("{isolated_url}/v1/budgets?capabilityId=cap-quorum-heal&limit=10"),
                service_token,
            ) else {
                return false;
            };
            let Some(status) = try_internal_cluster_status(&client, &isolated_url, service_token)
            else {
                return false;
            };
            budgets["count"].as_u64() == Some(1)
                && budgets["usages"][0]["invocationCount"].as_u64() == Some(1)
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 1)
        },
        || cluster_status_diagnostics(&client, &urls, service_token),
    );
}

#[cfg(unix)]
#[test]
fn trust_control_cluster_failed_quorum_does_not_leave_orphaned_exposure() {
    let dir = unique_test_dir().join("budget-quorum-commit-timeout");
    fs::create_dir_all(&dir).expect("create test dir");

    let addr_a = reserve_listen_addr();
    let addr_b = reserve_listen_addr();
    let url_a = format!("http://{addr_a}");
    let url_b = format!("http://{addr_b}");
    let expected_leader_url = std::cmp::min(url_a.clone(), url_b.clone());
    let service_token = "budget-quorum-commit-timeout-token";

    let server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        std::slice::from_ref(&url_b),
    );
    let server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        std::slice::from_ref(&url_a),
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build client");

    wait_until(
        "budget quorum timeout cluster health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_a}/health"), service_token).is_some(),
    );
    wait_until(
        "budget quorum timeout peer health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_b}/health"), service_token).is_some(),
    );
    wait_for_leader_convergence(&client, service_token, &url_a, &url_b, &expected_leader_url);

    let stopped_peer = if expected_leader_url == url_a {
        &server_b.child
    } else {
        &server_a.child
    };
    send_signal(stopped_peer, "STOP");

    let (status, body) = post_json_status(
        &client,
        &format!("{expected_leader_url}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-stalled-commit",
            "grantIndex": 0,
            "maxInvocations": 5,
            "exposureUnits": 60,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-stalled-commit-hold-1",
            "eventId": "cap-stalled-commit-hold-1:authorize"
        }),
    );
    assert_eq!(status, 503);
    assert!(
        body.contains("leader-visible") || body.contains("quorum commit"),
        "expected explicit quorum-commit failure body, got: {body}"
    );
    wait_until(
        "failed quorum authorize rollback removes orphaned exposure",
        Duration::from_secs(10),
        || {
            let Some(budgets) = try_get_json(
                &client,
                &format!(
                    "{expected_leader_url}/v1/budgets?capabilityId=cap-stalled-commit&limit=10"
                ),
                service_token,
            ) else {
                return false;
            };
            let Some(usage) = budgets["usages"].as_array().and_then(|usages| {
                usages
                    .iter()
                    .find(|usage| usage["grantIndex"].as_u64() == Some(0))
            }) else {
                return false;
            };
            usage["invocationCount"].as_u64() == Some(0)
                && usage["totalExposureCharged"].as_u64() == Some(0)
                && usage["totalRealizedSpend"].as_u64() == Some(0)
        },
    );
}

#[test]
fn trust_control_cluster_late_joiner_catches_up_from_snapshot_and_compacts() {
    let dir = unique_test_dir().join("late-joiner");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let warm_urls = vec![url_a.clone(), url_b.clone()];
    let all_urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let service_token = "cluster-snapshot-token";
    let expected_leader_url = url_a.clone();

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build client");

    for base_url in &warm_urls {
        wait_until(
            "warm node health reachable",
            Duration::from_secs(20),
            || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
        );
    }

    wait_until_with_diagnostics(
        "two-node quorum convergence with third node absent",
        Duration::from_secs(90),
        || {
            warm_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    for index in 0..10 {
        let receipt = serde_json::to_value(sample_receipt(
            &format!("snapshot-prejoin-{index}"),
            &format!("cap-prejoin-{index}"),
        ))
        .expect("serialize prejoin receipt");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_expected_write_visibility_metadata(&stored, &expected_leader_url);
    }

    wait_until_with_diagnostics(
        "warm nodes replicate prejoin receipts",
        Duration::from_secs(90),
        || {
            tool_receipt_count(&client, &url_a, service_token) == 10
                && tool_receipt_count(&client, &url_b, service_token) == 10
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &dir.join("receipts-c.sqlite3"),
        &dir.join("revocations-c.sqlite3"),
        &dir.join("authority-c.sqlite3"),
        &dir.join("budgets-c.sqlite3"),
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    wait_until(
        "late joiner health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{url_c}/health"), service_token).is_some(),
    );

    wait_until_with_diagnostics(
        "late joiner snapshot catch-up",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &url_c, service_token) else {
                return false;
            };
            tool_receipt_count(&client, &url_c, service_token) == 10
                && status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                && status["hasQuorum"].as_bool() == Some(true)
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| {
                        peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 1
                            && peer["lastSnapshotAt"].as_u64().is_some()
                    })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );

    for index in 10..20 {
        let receipt = serde_json::to_value(sample_receipt(
            &format!("snapshot-postjoin-{index}"),
            &format!("cap-postjoin-{index}"),
        ))
        .expect("serialize postjoin receipt");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_expected_write_visibility_metadata(&stored, &expected_leader_url);
    }

    wait_until_with_diagnostics(
        "late joiner snapshot compaction after sustained deltas",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &url_c, service_token) else {
                return false;
            };
            tool_receipt_count(&client, &url_c, service_token) == 20
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| {
                        peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 2
                            && peer["forceSnapshot"].as_bool() == Some(false)
                    })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );
}

#[test]
fn trust_control_cluster_snapshot_replays_holds_and_mutation_events() {
    let dir = unique_test_dir().join("snapshot-budget-holds");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_late, late_url) = nodes[0].clone();
    let (addr_a, url_a) = nodes[1].clone();
    let (addr_b, url_b) = nodes[2].clone();
    let warm_urls = vec![url_a.clone(), url_b.clone()];
    let all_urls = vec![late_url.clone(), url_a.clone(), url_b.clone()];
    let service_token = "cluster-snapshot-budget-token";
    let warm_leader_url = url_a.clone();
    let late_budget_db = dir.join("budgets-late.sqlite3");

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[late_url.clone(), url_b.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[late_url.clone(), url_a.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build client");

    for base_url in &warm_urls {
        wait_until(
            "warm budget node health reachable",
            Duration::from_secs(20),
            || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
        );
    }

    wait_until_with_diagnostics(
        "warm budget cluster converges without late joiner",
        Duration::from_secs(90),
        || {
            warm_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(warm_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &warm_urls, service_token),
    );

    let authorize = post_json(
        &client,
        &format!("{url_b}/v1/budgets/authorize-exposure"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "maxInvocations": 5,
            "exposureUnits": 90,
            "maxExposurePerInvocation": 100,
            "maxTotalExposureUnits": 400,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:authorize"
        }),
    );
    assert_eq!(authorize["allowed"].as_bool(), Some(true));
    assert_expected_write_visibility_metadata(&authorize, &warm_leader_url);

    let release = post_json(
        &client,
        &format!("{url_a}/v1/budgets/reconcile-spend"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "reductionUnits": 30,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:release"
        }),
    );
    assert_eq!(release["releasedExposureUnits"].as_u64(), Some(30));
    assert_expected_write_visibility_metadata(&release, &warm_leader_url);
    assert_budget_invocation_count(
        &client,
        &warm_leader_url,
        service_token,
        "cap-snapshot-hold",
        0,
        1,
    );
    assert_budget_totals(
        &client,
        &warm_leader_url,
        service_token,
        "cap-snapshot-hold",
        0,
        60,
        0,
    );

    let _late_server = spawn_trust_service(
        addr_late,
        service_token,
        &dir.join("receipts-late.sqlite3"),
        &dir.join("revocations-late.sqlite3"),
        &dir.join("authority-late.sqlite3"),
        &late_budget_db,
        None,
        &late_url,
        &[url_a.clone(), url_b.clone()],
    );

    wait_until(
        "late budget node health reachable",
        Duration::from_secs(20),
        || try_get_json(&client, &format!("{late_url}/health"), service_token).is_some(),
    );

    wait_until_with_diagnostics(
        "late joiner snapshots budget hold history",
        Duration::from_secs(90),
        || {
            let Some(status) = try_internal_cluster_status(&client, &late_url, service_token)
            else {
                return false;
            };
            let Some(budgets) = try_get_json(
                &client,
                &format!("{late_url}/v1/budgets?capabilityId=cap-snapshot-hold&limit=10"),
                service_token,
            ) else {
                return false;
            };
            status["leaderUrl"].as_str() == Some(late_url.as_str())
                && status["hasQuorum"].as_bool() == Some(true)
                && budgets["count"].as_u64() == Some(1)
                && budgets["usages"][0]["invocationCount"].as_u64() == Some(1)
                && budgets["usages"][0]["totalExposureCharged"].as_u64() == Some(60)
                && budgets["usages"][0]["totalRealizedSpend"].as_u64() == Some(0)
                && status["peers"]
                    .as_array()
                    .expect("peer status array")
                    .iter()
                    .any(|peer| peer["snapshotAppliedCount"].as_u64().unwrap_or(0) >= 1)
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );

    let late_store = SqliteBudgetStore::open(&late_budget_db).expect("open late budget db");
    let pre_reconcile_events = late_store
        .list_mutation_events(10, Some("cap-snapshot-hold"), Some(0))
        .expect("list replayed mutation events");
    let pre_reconcile_event_ids = pre_reconcile_events
        .iter()
        .map(|event| event.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        pre_reconcile_event_ids,
        vec![
            "cap-snapshot-hold-1:authorize",
            "cap-snapshot-hold-1:release",
        ]
    );
    drop(late_store);

    let reconcile = post_json(
        &client,
        &format!("{late_url}/v1/budgets/reconcile-spend"),
        service_token,
        &json!({
            "capabilityId": "cap-snapshot-hold",
            "grantIndex": 0,
            "authorizedExposureUnits": 60,
            "realizedSpendUnits": 45,
            "holdId": "cap-snapshot-hold-1",
            "eventId": "cap-snapshot-hold-1:reconcile"
        }),
    );
    assert_eq!(reconcile["releasedExposureUnits"].as_u64(), Some(15));
    assert_expected_write_visibility_metadata(&reconcile, &late_url);
    assert_budget_totals(
        &client,
        &late_url,
        service_token,
        "cap-snapshot-hold",
        0,
        0,
        45,
    );

    let late_store = SqliteBudgetStore::open(&late_budget_db).expect("reopen late budget db");
    let usage = late_store
        .get_usage("cap-snapshot-hold", 0)
        .expect("get replayed budget usage")
        .expect("late usage row");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.total_cost_realized_spend, 45);

    let post_reconcile_event_ids = late_store
        .list_mutation_events(10, Some("cap-snapshot-hold"), Some(0))
        .expect("list late mutation events after reconcile")
        .into_iter()
        .map(|event| event.event_id)
        .collect::<Vec<_>>();
    assert_eq!(
        post_reconcile_event_ids,
        vec![
            "cap-snapshot-hold-1:authorize".to_string(),
            "cap-snapshot-hold-1:release".to_string(),
            "cap-snapshot-hold-1:reconcile".to_string(),
        ]
    );
}

#[test]
fn trust_control_cluster_multi_region_partition_qualification() {
    let dir = unique_test_dir().join("multi-region-qualification");
    fs::create_dir_all(&dir).expect("create test dir");

    let nodes = reserve_cluster_nodes(3);
    let (addr_a, url_a) = nodes[0].clone();
    let (addr_b, url_b) = nodes[1].clone();
    let (addr_c, url_c) = nodes[2].clone();
    let all_urls = vec![url_a.clone(), url_b.clone(), url_c.clone()];
    let majority_urls = vec![url_a.clone(), url_b.clone()];
    let isolated_url = url_c.clone();
    let expected_leader_url = url_a.clone();
    let service_token = "cluster-multi-region-token";

    let _server_a = spawn_trust_service(
        addr_a,
        service_token,
        &dir.join("receipts-a.sqlite3"),
        &dir.join("revocations-a.sqlite3"),
        &dir.join("authority-a.sqlite3"),
        &dir.join("budgets-a.sqlite3"),
        None,
        &url_a,
        &[url_b.clone(), url_c.clone()],
    );
    let _server_b = spawn_trust_service(
        addr_b,
        service_token,
        &dir.join("receipts-b.sqlite3"),
        &dir.join("revocations-b.sqlite3"),
        &dir.join("authority-b.sqlite3"),
        &dir.join("budgets-b.sqlite3"),
        None,
        &url_b,
        &[url_a.clone(), url_c.clone()],
    );
    let _server_c = spawn_trust_service(
        addr_c,
        service_token,
        &dir.join("receipts-c.sqlite3"),
        &dir.join("revocations-c.sqlite3"),
        &dir.join("authority-c.sqlite3"),
        &dir.join("budgets-c.sqlite3"),
        None,
        &url_c,
        &[url_a.clone(), url_b.clone()],
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("build client");

    for base_url in &all_urls {
        wait_until(
            "cluster node health reachable",
            Duration::from_secs(20),
            || try_get_json(&client, &format!("{base_url}/health"), service_token).is_some(),
        );
    }

    wait_until_with_diagnostics(
        "simulated three-region leader convergence",
        Duration::from_secs(90),
        || {
            all_urls.iter().all(|base_url| {
                let Some(status) = try_internal_cluster_status(&client, base_url, service_token)
                else {
                    return false;
                };
                status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                    && status["hasQuorum"].as_bool() == Some(true)
                    && status["reachableNodes"].as_u64() == Some(3)
                    && status["quorumSize"].as_u64() == Some(2)
            })
        },
        || cluster_status_diagnostics(&client, &all_urls, service_token),
    );

    let mut healed_partition_samples_ms = Vec::new();
    for index in 0..MULTI_REGION_PARTITION_SAMPLES {
        for base_url in &majority_urls {
            let response = set_cluster_partition(
                &client,
                base_url,
                service_token,
                std::slice::from_ref(&isolated_url),
            );
            assert_eq!(response["hasQuorum"].as_bool(), Some(true));
        }
        let isolated_partition = set_cluster_partition(
            &client,
            &isolated_url,
            service_token,
            &[url_a.clone(), url_b.clone()],
        );
        assert_eq!(isolated_partition["hasQuorum"].as_bool(), Some(false));

        wait_until_with_diagnostics(
            &format!("partition convergence sample {index}"),
            Duration::from_secs(90),
            || {
                let majority_ok = majority_urls.iter().all(|base_url| {
                    let Some(status) =
                        try_internal_cluster_status(&client, base_url, service_token)
                    else {
                        return false;
                    };
                    status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                        && status["hasQuorum"].as_bool() == Some(true)
                        && status["reachableNodes"].as_u64() == Some(2)
                });
                let Some(isolated_status) =
                    try_internal_cluster_status(&client, &isolated_url, service_token)
                else {
                    return false;
                };
                majority_ok
                    && isolated_status["leaderUrl"].is_null()
                    && isolated_status["hasQuorum"].as_bool() == Some(false)
                    && isolated_status["reachableNodes"].as_u64() == Some(1)
                    && isolated_status["role"].as_str() == Some("candidate")
            },
            || cluster_status_diagnostics(&client, &all_urls, service_token),
        );

        if index == 0 {
            let denied_receipt = serde_json::to_value(sample_receipt(
                "multi-region-denied",
                "cap-multi-region-denied",
            ))
            .expect("denied receipt json");
            let (status, body) = post_json_status(
                &client,
                &format!("{isolated_url}/v1/receipts/tools"),
                service_token,
                &denied_receipt,
            );
            assert_eq!(status, 503);
            assert!(
                body.contains("quorum") || body.contains("leader"),
                "expected quorum failure body, got: {body}"
            );
        }

        let receipt_id = format!("multi-region-heal-{index}");
        let capability_id = format!("cap-multi-region-heal-{index}");
        let receipt = serde_json::to_value(sample_receipt(&receipt_id, &capability_id))
            .expect("receipt json");
        let stored = post_json(
            &client,
            &format!("{url_b}/v1/receipts/tools"),
            service_token,
            &receipt,
        );
        assert_eq!(stored["stored"].as_bool(), Some(true));
        assert_expected_write_visibility_metadata(&stored, &expected_leader_url);

        for base_url in &all_urls {
            let response = set_cluster_partition(&client, base_url, service_token, &[]);
            assert_eq!(
                response["blockedPeerUrls"].as_array().map(Vec::len),
                Some(0)
            );
        }

        let lag_ms = measure_until_with_diagnostics(
            &format!("post-heal replication sample {index}"),
            Duration::from_secs(90),
            || {
                let converged = all_urls.iter().all(|base_url| {
                    let Some(status) =
                        try_internal_cluster_status(&client, base_url, service_token)
                    else {
                        return false;
                    };
                    status["leaderUrl"].as_str() == Some(expected_leader_url.as_str())
                        && status["hasQuorum"].as_bool() == Some(true)
                        && status["reachableNodes"].as_u64() == Some(3)
                        && tool_receipt_visible(
                            &client,
                            base_url,
                            service_token,
                            &capability_id,
                            &receipt_id,
                        )
                });
                converged
            },
            || cluster_status_diagnostics(&client, &all_urls, service_token),
        );
        healed_partition_samples_ms.push(lag_ms);
    }

    let report = json!({
        "phase": 298,
        "scenario": "local-simulated-three-region-partition-qualification",
        "generatedAt": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs(),
        "clusterSyncIntervalMs": 200,
        "regions": [
            {"name": "region-a", "baseUrl": url_a},
            {"name": "region-b", "baseUrl": url_b},
            {"name": "region-c", "baseUrl": url_c},
        ],
        "consistencyChecks": {
            "leaderUrl": expected_leader_url,
            "minorityWritesFailClosed": true,
            "healedClusterRestoresQuorum": true,
            "splitBrainObserved": false,
        },
        "postHealReplicationMs": {
            "samples": healed_partition_samples_ms,
            "summary": latency_summary(&healed_partition_samples_ms),
        },
        "notes": [
            "This artifact records local simulated-region qualification numbers, not hosted WAN latencies.",
            "Replication lag is measured from partition heal until all nodes converge on the expected replicated receipt visibility."
        ]
    });
    let report_path = write_multi_region_qualification_report(&report);
    assert!(report_path.exists(), "qualification report should exist");
    println!(
        "multi-region qualification report: {}",
        report_path.display()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize qualification report")
    );
}

#[test]
#[ignore = "qualification lane repeats the full failover scenario"]
fn trust_control_cluster_repeat_run_qualification() {
    for run_index in 1..=TRUST_CLUSTER_QUALIFICATION_RUNS {
        run_trust_control_cluster_proving_scenario(run_index, TRUST_CLUSTER_QUALIFICATION_RUNS);
    }
}
