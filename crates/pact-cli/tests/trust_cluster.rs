#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pact_core::capability::{CapabilityToken, CapabilityTokenBody, PactScope};
use pact_core::crypto::Keypair;
use pact_core::receipt::{
    ChildRequestReceipt, ChildRequestReceiptBody, Decision, PactReceipt, PactReceiptBody,
    ToolCallAction,
};
use pact_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use serde_json::{json, Value};

const TRUST_CLUSTER_QUALIFICATION_RUNS: usize = 5;

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pact-cli-trust-cluster-{nonce}"))
}

fn reserve_listen_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
    let addr = listener.local_addr().expect("listener addr");
    drop(listener);
    addr
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

    let child = Command::new(env!("CARGO_BIN_EXE_pact"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pact trust serve");

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
            Ok(response) => match response.error_for_status() {
                Ok(response) => return response.json().expect("decode json"),
                Err(error) => last_error = Some(error.to_string()),
            },
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

fn sample_receipt(id: &str, capability_id: &str) -> PactReceipt {
    let keypair = Keypair::generate();
    PactReceipt::sign(
        PactReceiptBody {
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
            scope: PactScope::default(),
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

    let survivor_url = if leader_url == url_a {
        drop(server_a.take());
        url_b.clone()
    } else {
        drop(server_b.take());
        url_a.clone()
    };
    wait_until("leader failover", Duration::from_secs(90), || {
        try_get_json(&client, &format!("{survivor_url}/health"), service_token)
            .and_then(|value| value["leaderUrl"].as_str().map(ToOwned::to_owned))
            .as_deref()
            == Some(survivor_url.as_str())
    });

    let third_budget = post_json(
        &client,
        &format!("{survivor_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(third_budget["allowed"].as_bool(), Some(true));
    assert_eq!(third_budget["invocationCount"].as_u64(), Some(4));
    assert_expected_write_visibility_metadata(&third_budget, &survivor_url);
    assert_budget_invocation_count(&client, &survivor_url, service_token, "cap-shared", 0, 4);

    let exhausted = post_json(
        &client,
        &format!("{survivor_url}/v1/budgets/increment"),
        service_token,
        &json!({
            "capabilityId": "cap-shared",
            "grantIndex": 0,
            "maxInvocations": 4
        }),
    );
    assert_eq!(exhausted["allowed"].as_bool(), Some(false));
    assert_eq!(exhausted["invocationCount"].as_u64(), Some(4));
    assert_expected_write_visibility_metadata(&exhausted, &survivor_url);

    let budgets = get_json(
        &client,
        &format!("{survivor_url}/v1/budgets?capabilityId=cap-shared&limit=10"),
        service_token,
    );
    assert_eq!(budgets["count"].as_u64(), Some(1));
    assert_eq!(budgets["usages"][0]["invocationCount"].as_u64(), Some(4));
}

#[test]
fn trust_control_cluster_replicates_state_and_survives_leader_failover() {
    run_trust_control_cluster_proving_scenario(1, 1);
}

#[test]
#[ignore = "qualification lane repeats the full failover scenario"]
fn trust_control_cluster_repeat_run_qualification() {
    for run_index in 1..=TRUST_CLUSTER_QUALIFICATION_RUNS {
        run_trust_control_cluster_proving_scenario(run_index, TRUST_CLUSTER_QUALIFICATION_RUNS);
    }
}
