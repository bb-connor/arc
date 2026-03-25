//! Integration tests for GET /v1/receipts/query endpoint.
//!
//! Tests verify filtering, cursor pagination, total_count, and auth enforcement.
//! Also covers lineage endpoints (GET /v1/lineage/:id, /chain) and agent filter.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::capability::{
    CapabilityToken, CapabilityTokenBody, MonetaryAmount, Operation, PactScope, ToolGrant,
};
use pact_core::crypto::Keypair;
use pact_core::receipt::{
    Decision, FinancialReceiptMetadata, PactReceipt, PactReceiptBody, ReceiptAttributionMetadata,
    SettlementStatus, ToolCallAction,
};
use pact_kernel::SqliteReceiptStore;
use pact_kernel::{
    build_checkpoint, BudgetUsageRecord, CapabilitySnapshot, FederatedEvidenceShareImport,
    ReceiptStore, SqliteBudgetStore, StoredToolReceipt,
};
use reqwest::blocking::Client;

// --- Test helpers ---

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn reserve_listen_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind temp listener");
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
    listen: std::net::SocketAddr,
    service_token: &str,
    receipt_db_path: &PathBuf,
    revocation_db_path: &PathBuf,
    authority_db_path: &PathBuf,
    budget_db_path: &PathBuf,
) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--revocation-db",
            revocation_db_path.to_str().expect("revocation db path"),
            "--authority-db",
            authority_db_path.to_str().expect("authority db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--service-token",
            service_token,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

fn wait_for_trust_service(client: &Client, base_url: &str) {
    for _ in 0..300 {
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
    panic!("trust service did not become ready");
}

/// Build a PactReceipt for test insertion.
fn make_receipt(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    decision: Decision,
    timestamp: u64,
    cost: Option<u64>,
) -> PactReceipt {
    let keypair = Keypair::generate();
    let metadata = cost.map(|c| {
        serde_json::json!({
            "financial": {
                "grant_index": 0u32,
                "cost_charged": c,
                "currency": "USD",
                "budget_remaining": 1000u64,
                "budget_total": 2000u64,
                "delegation_depth": 0u32,
                "root_budget_holder": "root-agent",
                "settlement_status": "pending"
            }
        })
    });
    PactReceipt::sign(
        PactReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({}),
                parameter_hash: "abc123".to_string(),
            },
            decision,
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

fn make_financial_receipt(
    id: &str,
    capability_id: &str,
    subject_key: Option<&str>,
    issuer_key: &str,
    tool_server: &str,
    tool_name: &str,
    decision: Decision,
    timestamp: u64,
    cost_charged: u64,
    attempted_cost: Option<u64>,
    root_budget_holder: &str,
    delegation_depth: u32,
) -> PactReceipt {
    let keypair = Keypair::generate();
    let metadata = serde_json::json!({
        "attribution": subject_key.map(|subject_key| ReceiptAttributionMetadata {
            subject_key: subject_key.to_string(),
            issuer_key: issuer_key.to_string(),
            delegation_depth,
            grant_index: Some(0),
        }),
        "financial": FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged,
            currency: "USD".to_string(),
            budget_remaining: 900u64,
            budget_total: 1000u64,
            delegation_depth,
            root_budget_holder: root_budget_holder.to_string(),
            payment_reference: None,
            settlement_status: if attempted_cost.is_some() && cost_charged == 0 {
                SettlementStatus::NotApplicable
            } else {
                SettlementStatus::Settled
            },
            cost_breakdown: None,
            attempted_cost,
        }
    });
    PactReceipt::sign(
        PactReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({}),
                parameter_hash: format!("param-{id}"),
            },
            decision,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .unwrap()
}

/// Common test setup: create temp dir, insert receipts, start trust service, return setup info.
struct TestSetup {
    dir: PathBuf,
    _receipt_db_path: PathBuf,
    _revocation_db_path: PathBuf,
    _authority_db_path: PathBuf,
    _budget_db_path: PathBuf,
    base_url: String,
    service_token: String,
    _service: ServerGuard,
    client: Client,
}

fn setup_with_receipts(prefix: &str) -> TestSetup {
    let dir = unique_dir(prefix);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    // Insert test receipts directly into SQLite before the service starts.
    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");

        // 3 receipts with cap-1
        store
            .append_pact_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "files",
                "read",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();

        // 1 receipt with cap-2
        store
            .append_pact_receipt(&make_receipt(
                "r-4",
                "cap-2",
                "shell",
                "bash",
                Decision::Allow,
                1003,
                None,
            ))
            .unwrap();

        // 1 denied receipt with cap-1
        store
            .append_pact_receipt(&make_receipt(
                "r-5",
                "cap-1",
                "shell",
                "bash",
                Decision::Deny {
                    reason: "policy".to_string(),
                    guard: "allow_guard".to_string(),
                },
                1004,
                Some(200),
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "test-secret-token".to_string();
    let service = spawn_trust_service(
        listen,
        &service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    TestSetup {
        dir,
        _receipt_db_path: receipt_db_path,
        _revocation_db_path: revocation_db_path,
        _authority_db_path: authority_db_path,
        _budget_db_path: budget_db_path,
        base_url,
        service_token,
        _service: service,
        client,
    }
}

// --- Tests ---

/// GET /v1/receipts/query with no filters returns all stored receipts and correct totalCount.
#[test]
fn test_receipt_query_no_filters() {
    let setup = setup_with_receipts("pact-rq-no-filters");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(
        total_count, 5,
        "all 5 inserted receipts should be in totalCount"
    );
    assert_eq!(
        receipts.len(),
        5,
        "all 5 receipts should be returned with default limit"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// GET /v1/receipts/query?capabilityId=cap-1 returns only receipts with capability_id == "cap-1".
#[test]
fn test_receipt_query_filter_capability() {
    let setup = setup_with_receipts("pact-rq-filter-cap");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("capabilityId", "cap-1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(total_count, 4, "4 receipts have cap-1");
    assert_eq!(receipts.len(), 4);

    for receipt in receipts {
        assert_eq!(
            receipt["capability_id"].as_str().expect("capability_id"),
            "cap-1",
            "all returned receipts must have capability_id == cap-1"
        );
    }

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// Two requests with cursor yield non-overlapping sequential results.
#[test]
fn test_receipt_query_cursor_pagination() {
    let setup = setup_with_receipts("pact-rq-cursor");

    // First page: limit=2
    let response1 = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "2")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send first request");

    assert_eq!(response1.status(), reqwest::StatusCode::OK);
    let body1: serde_json::Value = response1.json().expect("parse json page 1");
    let receipts1 = body1["receipts"].as_array().expect("receipts page 1");
    assert_eq!(receipts1.len(), 2, "first page should have 2 receipts");

    let next_cursor = body1["nextCursor"]
        .as_u64()
        .expect("nextCursor should be present after page 1");

    // Second page: use cursor
    let response2 = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "2"), ("cursor", &next_cursor.to_string())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send second request");

    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let body2: serde_json::Value = response2.json().expect("parse json page 2");
    let receipts2 = body2["receipts"].as_array().expect("receipts page 2");
    assert_eq!(receipts2.len(), 2, "second page should have 2 receipts");

    // The two pages must not overlap (receipts have unique ids).
    let ids1: Vec<&str> = receipts1
        .iter()
        .map(|r| r["id"].as_str().expect("receipt id"))
        .collect();
    let ids2: Vec<&str> = receipts2
        .iter()
        .map(|r| r["id"].as_str().expect("receipt id"))
        .collect();
    for id in &ids1 {
        assert!(
            !ids2.contains(id),
            "receipt {id} appeared on both page 1 and page 2"
        );
    }

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// totalCount reflects the full filtered set, not just the page size.
#[test]
fn test_receipt_query_total_count() {
    let setup = setup_with_receipts("pact-rq-total-count");

    // Fetch only 1 receipt but total should be 5.
    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .query(&[("limit", "1")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send request");

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().expect("parse json");
    let total_count = body["totalCount"].as_u64().expect("totalCount is u64");
    let receipts = body["receipts"].as_array().expect("receipts is array");

    assert_eq!(receipts.len(), 1, "only 1 receipt on this page");
    assert_eq!(total_count, 5, "totalCount should reflect full set of 5");

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// Request without Authorization header returns 401.
#[test]
fn test_receipt_query_requires_auth() {
    let setup = setup_with_receipts("pact-rq-auth");

    // No Authorization header.
    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .send()
        .expect("send request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "request without auth should return 401"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

// --- Lineage helper ---

/// Build a minimal CapabilityToken for test lineage insertion.
fn make_capability_token(
    id: &str,
    subject_keypair: &Keypair,
    issuer_keypair: &Keypair,
) -> CapabilityToken {
    let body = CapabilityTokenBody {
        id: id.to_string(),
        issuer: issuer_keypair.public_key(),
        subject: subject_keypair.public_key(),
        scope: PactScope::default(),
        issued_at: 1000,
        expires_at: 9999999999,
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, issuer_keypair).expect("sign capability token")
}

/// Pre-populate the capability_lineage table before the service starts.
fn prepopulate_lineage(db_path: &PathBuf, entries: &[(&CapabilityToken, Option<&str>)]) {
    let mut store = SqliteReceiptStore::open(db_path).expect("open receipt store for lineage");
    for (token, parent_id) in entries {
        store
            .record_capability_snapshot(token, *parent_id)
            .expect("record_capability_snapshot");
    }
}

// --- Lineage endpoint tests ---

/// GET /v1/lineage/:capability_id returns 200 with matching snapshot fields.
#[test]
fn test_lineage_get_capability_snapshot() {
    let dir = unique_dir("pact-lineage-get");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let subject_kp = Keypair::generate();
    let token = make_capability_token("cap-lineage-1", &subject_kp, &issuer_kp);
    let subject_hex = subject_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    prepopulate_lineage(&receipt_db_path, &[(&token, None)]);

    let listen = reserve_listen_addr();
    let service_token = "lineage-get-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/lineage/cap-lineage-1"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send lineage request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for lineage GET"
    );
    let body: serde_json::Value = response.json().expect("parse lineage json");
    assert_eq!(
        body["capability_id"].as_str().expect("capability_id"),
        "cap-lineage-1"
    );
    assert_eq!(
        body["subject_key"].as_str().expect("subject_key"),
        subject_hex
    );
    assert_eq!(body["issuer_key"].as_str().expect("issuer_key"), issuer_hex);
    assert_eq!(
        body["delegation_depth"].as_u64().expect("delegation_depth"),
        0
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/lineage/:capability_id/chain returns root-first delegation chain.
#[test]
fn test_lineage_get_delegation_chain() {
    let dir = unique_dir("pact-lineage-chain");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let subj_kp = Keypair::generate();

    // 3-level chain: root -> parent -> child
    let root = make_capability_token("chain-root", &subj_kp, &issuer_kp);
    let parent = make_capability_token("chain-parent", &subj_kp, &issuer_kp);
    let child = make_capability_token("chain-child", &subj_kp, &issuer_kp);

    prepopulate_lineage(
        &receipt_db_path,
        &[
            (&root, None),
            (&parent, Some("chain-root")),
            (&child, Some("chain-parent")),
        ],
    );

    let listen = reserve_listen_addr();
    let service_token = "chain-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/lineage/chain-child/chain"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send chain request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for chain GET"
    );
    let chain: Vec<serde_json::Value> = response.json().expect("parse chain json");
    assert_eq!(chain.len(), 3, "chain should have 3 entries");

    // Root-first ordering: delegation_depth 0, 1, 2
    assert_eq!(
        chain[0]["capability_id"].as_str().expect("id"),
        "chain-root"
    );
    assert_eq!(chain[0]["delegation_depth"].as_u64().expect("depth"), 0);
    assert_eq!(
        chain[1]["capability_id"].as_str().expect("id"),
        "chain-parent"
    );
    assert_eq!(chain[1]["delegation_depth"].as_u64().expect("depth"), 1);
    assert_eq!(
        chain[2]["capability_id"].as_str().expect("id"),
        "chain-child"
    );
    assert_eq!(chain[2]["delegation_depth"].as_u64().expect("depth"), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/lineage/:capability_id returns 404 for unknown capability_id.
#[test]
fn test_lineage_not_found() {
    let setup = setup_with_receipts("pact-lineage-404");

    let response = setup
        .client
        .get(format!("{}/v1/lineage/nonexistent-cap-id", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send lineage 404 request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown capability_id should return 404"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// GET /v1/lineage/:capability_id requires Authorization header.
#[test]
fn test_lineage_requires_auth() {
    let setup = setup_with_receipts("pact-lineage-auth");

    let response = setup
        .client
        .get(format!("{}/v1/lineage/any-cap-id", setup.base_url))
        .send()
        .expect("send unauthenticated lineage request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "lineage endpoint without auth should return 401"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// GET /v1/receipts/query?agentSubject=<hex> filters receipts by agent subject.
#[test]
fn test_agent_subject_filter_via_http() {
    let dir = unique_dir("pact-agent-filter");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let agent1_kp = Keypair::generate();
    let agent2_kp = Keypair::generate();
    let agent1_hex = agent1_kp.public_key().to_hex();

    // Two capability tokens, one per agent
    let cap1 = make_capability_token("cap-agent1", &agent1_kp, &issuer_kp);
    let cap2 = make_capability_token("cap-agent2", &agent2_kp, &issuer_kp);

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&cap1, None)
            .expect("record cap1");
        store
            .record_capability_snapshot(&cap2, None)
            .expect("record cap2");

        // 2 receipts for agent1, 1 for agent2
        store
            .append_pact_receipt(&make_receipt(
                "ra-1",
                "cap-agent1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "ra-2",
                "cap-agent1",
                "files",
                "read",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "ra-3",
                "cap-agent2",
                "shell",
                "bash",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "agent-filter-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/receipts/query"))
        .query(&[("agentSubject", agent1_hex.as_str())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send agent filter request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for agent filter"
    );
    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(
        receipts.len(),
        2,
        "only agent1's 2 receipts should be returned"
    );
    for r in receipts {
        assert_eq!(
            r["capability_id"].as_str().expect("capability_id"),
            "cap-agent1",
            "all returned receipts must belong to agent1"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/agents/:subject_key/receipts returns receipts for the given agent.
#[test]
fn test_agent_receipts_endpoint() {
    let dir = unique_dir("pact-agent-receipts");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let agent1_kp = Keypair::generate();
    let agent2_kp = Keypair::generate();
    let agent1_hex = agent1_kp.public_key().to_hex();

    let cap1 = make_capability_token("cap-ar-agent1", &agent1_kp, &issuer_kp);
    let cap2 = make_capability_token("cap-ar-agent2", &agent2_kp, &issuer_kp);

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&cap1, None)
            .expect("record cap1");
        store
            .record_capability_snapshot(&cap2, None)
            .expect("record cap2");

        store
            .append_pact_receipt(&make_receipt(
                "rb-1",
                "cap-ar-agent1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "rb-2",
                "cap-ar-agent1",
                "files",
                "read",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_receipt(
                "rb-3",
                "cap-ar-agent2",
                "shell",
                "bash",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "agent-receipts-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/agents/{agent1_hex}/receipts"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send agent receipts request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for agent receipts"
    );
    let body: serde_json::Value = response.json().expect("parse json");
    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(
        receipts.len(),
        2,
        "only agent1's 2 receipts should be returned"
    );
    for r in receipts {
        assert_eq!(
            r["capability_id"].as_str().expect("capability_id"),
            "cap-ar-agent1",
            "all returned receipts must belong to agent1"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/receipts/analytics returns aggregate metrics over the receipt corpus.
#[test]
fn test_receipt_analytics_endpoint() {
    let setup = setup_with_receipts("pact-receipt-analytics");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/analytics", setup.base_url))
        .query(&[("timeBucket", "day"), ("groupLimit", "10")])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send analytics request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for analytics"
    );
    let body: serde_json::Value = response.json().expect("parse analytics json");
    assert_eq!(body["summary"]["totalReceipts"].as_u64(), Some(5));
    assert_eq!(body["summary"]["allowCount"].as_u64(), Some(4));
    assert_eq!(body["summary"]["denyCount"].as_u64(), Some(1));

    let by_tool = body["byTool"].as_array().expect("byTool array");
    assert!(
        by_tool.iter().any(|row| {
            row["toolServer"].as_str() == Some("shell")
                && row["toolName"].as_str() == Some("bash")
                && row["metrics"]["totalReceipts"].as_u64() == Some(4)
        }),
        "shell/bash aggregate should be present"
    );

    let by_time = body["byTime"].as_array().expect("byTime array");
    assert_eq!(
        by_time.len(),
        1,
        "all fixture receipts fall into one day bucket"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}

/// GET /v1/reports/cost-attribution returns multi-hop delegation attribution with
/// root/leaf aggregation and lineage-complete chains.
#[test]
fn test_cost_attribution_report_endpoint() {
    let dir = unique_dir("pact-cost-attribution");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let root = make_capability_token("cap-cost-root", &root_kp, &issuer_kp);
    let child = make_capability_token("cap-cost-child", &leaf_kp, &issuer_kp);

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root");
        store
            .record_capability_snapshot(&child, Some("cap-cost-root"))
            .expect("record child");

        store
            .append_pact_receipt(&make_financial_receipt(
                "rc-cost-1",
                "cap-cost-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Allow,
                2_000,
                150,
                None,
                &root_hex,
                1,
            ))
            .unwrap();
        store
            .append_pact_receipt(&make_financial_receipt(
                "rc-cost-2",
                "cap-cost-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                2_001,
                0,
                Some(50),
                &root_hex,
                1,
            ))
            .unwrap();
    }

    let listen = reserve_listen_addr();
    let service_token = "cost-attribution-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/cost-attribution"))
        .query(&[
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("limit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send cost attribution request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for cost attribution report"
    );
    let body: serde_json::Value = response.json().expect("parse cost attribution json");
    assert_eq!(body["summary"]["matchingReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["returnedReceipts"].as_u64(), Some(2));
    assert_eq!(body["summary"]["totalCostCharged"].as_u64(), Some(150));
    assert_eq!(body["summary"]["totalAttemptedCost"].as_u64(), Some(50));
    assert_eq!(body["summary"]["lineageGapCount"].as_u64(), Some(0));

    let by_root = body["byRoot"].as_array().expect("byRoot array");
    assert_eq!(by_root.len(), 1);
    assert_eq!(
        by_root[0]["rootSubjectKey"].as_str(),
        Some(root_hex.as_str())
    );
    assert_eq!(by_root[0]["receiptCount"].as_u64(), Some(2));

    let by_leaf = body["byLeaf"].as_array().expect("byLeaf array");
    assert_eq!(by_leaf.len(), 1);
    assert_eq!(
        by_leaf[0]["rootSubjectKey"].as_str(),
        Some(root_hex.as_str())
    );
    assert_eq!(
        by_leaf[0]["leafSubjectKey"].as_str(),
        Some(leaf_hex.as_str())
    );
    assert_eq!(by_leaf[0]["totalCostCharged"].as_u64(), Some(150));
    assert_eq!(by_leaf[0]["totalAttemptedCost"].as_u64(), Some(50));

    let receipts = body["receipts"].as_array().expect("receipts array");
    assert_eq!(receipts.len(), 2);
    assert!(receipts
        .iter()
        .all(|row| row["lineageComplete"].as_bool() == Some(true)));
    assert!(receipts.iter().all(|row| row["chain"]
        .as_array()
        .map_or(false, |chain| chain.len() == 2)));

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/reports/operator composes activity, budget pressure, and compliance readiness.
#[test]
fn test_operator_report_endpoint() {
    let dir = unique_dir("pact-operator-report");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let issuer_kp = Keypair::generate();
    let root_kp = Keypair::generate();
    let leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let root_hex = root_kp.public_key().to_hex();
    let leaf_hex = leaf_kp.public_key().to_hex();
    let issuer_hex = issuer_kp.public_key().to_hex();

    let scope = PactScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-op-root".to_string(),
            issuer: issuer_kp.public_key(),
            subject: root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_000,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign root capability");
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-op-child".to_string(),
            issuer: issuer_kp.public_key(),
            subject: leaf_kp.public_key(),
            scope,
            issued_at: 1_100,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        &issuer_kp,
    )
    .expect("sign child capability");

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&root, None)
            .expect("record root lineage");
        store
            .record_capability_snapshot(&child, Some("cap-op-root"))
            .expect("record child lineage");

        let seq = store
            .append_pact_receipt_returning_seq(&make_financial_receipt(
                "rc-op-1",
                "cap-op-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Allow,
                3_000,
                850,
                None,
                &root_hex,
                1,
            ))
            .expect("append checkpointed receipt");
        store
            .append_pact_receipt(&make_financial_receipt(
                "rc-op-2",
                "cap-op-child",
                Some(&leaf_hex),
                &issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "budget".to_string(),
                    guard: "kernel".to_string(),
                },
                3_001,
                0,
                Some(100),
                &root_hex,
                1,
            ))
            .expect("append uncheckpointed receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let mut budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        budgets
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-op-child".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: 3_100,
                seq: 1,
                total_cost_charged: 850,
            })
            .expect("upsert budget usage");
    }

    let listen = reserve_listen_addr();
    let service_token = "operator-report-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[
            ("agentSubject", leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("budgetLimit", "10"),
            ("attributionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "expected 200 for operator report"
    );
    let body: serde_json::Value = response.json().expect("parse operator report json");

    assert_eq!(
        body["activity"]["summary"]["totalReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(body["activity"]["summary"]["allowCount"].as_u64(), Some(1));
    assert_eq!(body["activity"]["summary"]["denyCount"].as_u64(), Some(1));
    assert_eq!(
        body["budgetUtilization"]["summary"]["matchingGrants"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["budgetUtilization"]["summary"]["nearLimitCount"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["toolServer"].as_str(),
        Some("shell")
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["toolName"].as_str(),
        Some("bash")
    );
    assert_eq!(
        body["budgetUtilization"]["rows"][0]["remainingCostUnits"].as_u64(),
        Some(150)
    );
    assert_eq!(
        body["compliance"]["evidenceReadyReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["compliance"]["uncheckpointedReceipts"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["compliance"]["pendingSettlementReceipts"].as_u64(),
        Some(0)
    );
    assert_eq!(
        body["compliance"]["failedSettlementReceipts"].as_u64(),
        Some(0)
    );
    assert_eq!(
        body["compliance"]["directEvidenceExportSupported"].as_bool(),
        Some(false)
    );
    assert_eq!(
        body["compliance"]["childReceiptScope"].as_str(),
        Some("omitted_no_join_path")
    );
    assert!(body["compliance"]["exportScopeNote"]
        .as_str()
        .expect("export scope note")
        .contains("tool filters narrow the operator report only"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Shared evidence references appear in operator reports, the direct query endpoint, and CLI output.
#[test]
fn test_shared_evidence_reporting_surfaces() {
    let dir = unique_dir("pact-shared-evidence-report");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    let remote_issuer_kp = Keypair::generate();
    let remote_root_kp = Keypair::generate();
    let remote_delegate_kp = Keypair::generate();
    let local_issuer_kp = Keypair::generate();
    let local_root_kp = Keypair::generate();
    let local_leaf_kp = Keypair::generate();
    let checkpoint_kp = Keypair::generate();
    let remote_root_hex = remote_root_kp.public_key().to_hex();
    let remote_delegate_hex = remote_delegate_kp.public_key().to_hex();
    let remote_issuer_hex = remote_issuer_kp.public_key().to_hex();
    let _local_root_hex = local_root_kp.public_key().to_hex();
    let local_leaf_hex = local_leaf_kp.public_key().to_hex();
    let local_issuer_hex = local_issuer_kp.public_key().to_hex();

    let scope = PactScope {
        grants: vec![ToolGrant {
            server_id: "shell".to_string(),
            tool_name: "bash".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(5),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 500,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 1000,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let local_root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-local-root".to_string(),
            issuer: local_issuer_kp.public_key(),
            subject: local_root_kp.public_key(),
            scope: scope.clone(),
            issued_at: 1_500,
            expires_at: 20_000,
            delegation_chain: vec![],
        },
        &local_issuer_kp,
    )
    .expect("sign local root capability");
    let local_child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-local-child".to_string(),
            issuer: local_issuer_kp.public_key(),
            subject: local_leaf_kp.public_key(),
            scope,
            issued_at: 1_600,
            expires_at: 20_000,
            delegation_chain: vec![],
        },
        &local_issuer_kp,
    )
    .expect("sign local child capability");

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .import_federated_evidence_share(&FederatedEvidenceShareImport {
                share_id: "share-cross-org".to_string(),
                manifest_hash: "manifest-cross-org".to_string(),
                exported_at: 1_400,
                issuer: "org-remote".to_string(),
                partner: "org-local".to_string(),
                signer_public_key: remote_issuer_hex.clone(),
                require_proofs: true,
                query_json: r#"{"capabilityId":"cap-remote-root"}"#.to_string(),
                tool_receipts: vec![StoredToolReceipt {
                    seq: 1,
                    receipt: make_financial_receipt(
                        "rc-remote-1",
                        "cap-remote-delegate",
                        Some(&remote_delegate_hex),
                        &remote_issuer_hex,
                        "shell",
                        "bash",
                        Decision::Allow,
                        1_350,
                        300,
                        None,
                        &remote_root_hex,
                        1,
                    ),
                }],
                capability_lineage: vec![
                    CapabilitySnapshot {
                        capability_id: "cap-remote-root".to_string(),
                        subject_key: remote_root_hex.clone(),
                        issuer_key: remote_issuer_hex.clone(),
                        issued_at: 1_000,
                        expires_at: 20_000,
                        grants_json: serde_json::to_string(&PactScope::default())
                            .expect("serialize remote root grants"),
                        delegation_depth: 0,
                        parent_capability_id: None,
                    },
                    CapabilitySnapshot {
                        capability_id: "cap-remote-delegate".to_string(),
                        subject_key: remote_delegate_hex.clone(),
                        issuer_key: remote_issuer_hex.clone(),
                        issued_at: 1_100,
                        expires_at: 20_000,
                        grants_json: serde_json::to_string(&PactScope::default())
                            .expect("serialize remote delegate grants"),
                        delegation_depth: 1,
                        parent_capability_id: Some("cap-remote-root".to_string()),
                    },
                ],
            })
            .expect("import federated evidence share");
        store
            .record_capability_snapshot(&local_root, None)
            .expect("record local root lineage");
        store
            .record_capability_snapshot(&local_child, Some("cap-local-root"))
            .expect("record local child lineage");
        store
            .record_federated_lineage_bridge(
                "cap-local-root",
                "cap-remote-delegate",
                Some("share-cross-org"),
            )
            .expect("record remote lineage bridge");

        let seq = store
            .append_pact_receipt_returning_seq(&make_financial_receipt(
                "rc-local-1",
                "cap-local-child",
                Some(&local_leaf_hex),
                &local_issuer_hex,
                "shell",
                "bash",
                Decision::Allow,
                1_700,
                450,
                None,
                &remote_root_hex,
                3,
            ))
            .expect("append shared-evidence receipt");
        store
            .append_pact_receipt(&make_financial_receipt(
                "rc-local-2",
                "cap-local-child",
                Some(&local_leaf_hex),
                &local_issuer_hex,
                "shell",
                "bash",
                Decision::Deny {
                    reason: "policy".to_string(),
                    guard: "kernel".to_string(),
                },
                1_701,
                0,
                Some(200),
                &remote_root_hex,
                3,
            ))
            .expect("append second shared-evidence receipt");

        let bytes = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("load canonical receipt bytes")
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint =
            build_checkpoint(1, seq, seq, &bytes, &checkpoint_kp).expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    {
        let mut budgets = SqliteBudgetStore::open(&budget_db_path).expect("open budget store");
        budgets
            .upsert_usage(&BudgetUsageRecord {
                capability_id: "cap-local-child".to_string(),
                grant_index: 0,
                invocation_count: 2,
                updated_at: 1_800,
                seq: 1,
                total_cost_charged: 450,
            })
            .expect("upsert budget usage");
    }

    let listen = reserve_listen_addr();
    let service_token = "shared-evidence-token";
    let _service = spawn_trust_service(
        listen,
        service_token,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );
    let client = Client::builder().build().expect("build client");
    let base_url = format!("http://{listen}");
    wait_for_trust_service(&client, &base_url);

    let operator_response = client
        .get(format!("{base_url}/v1/reports/operator"))
        .query(&[
            ("agentSubject", local_leaf_hex.as_str()),
            ("toolServer", "shell"),
            ("toolName", "bash"),
            ("budgetLimit", "10"),
            ("attributionLimit", "10"),
        ])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send operator report request");
    assert_eq!(operator_response.status(), reqwest::StatusCode::OK);
    let operator_body: serde_json::Value = operator_response
        .json()
        .expect("parse operator report body");
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingShares"].as_u64(),
        Some(1)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingReferences"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["matchingLocalReceipts"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["summary"]["remoteLineageRecords"].as_u64(),
        Some(2)
    );
    assert_eq!(
        operator_body["sharedEvidence"]["references"]
            .as_array()
            .expect("shared evidence references")
            .len(),
        2
    );

    let shared_response = client
        .get(format!("{base_url}/v1/federation/evidence-shares"))
        .query(&[("agentSubject", local_leaf_hex.as_str())])
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {service_token}"),
        )
        .send()
        .expect("send shared evidence request");
    assert_eq!(shared_response.status(), reqwest::StatusCode::OK);
    let shared_body: serde_json::Value =
        shared_response.json().expect("parse shared evidence body");
    assert_eq!(shared_body["summary"]["matchingShares"].as_u64(), Some(1));
    assert_eq!(
        shared_body["summary"]["matchingReferences"].as_u64(),
        Some(2)
    );
    assert!(shared_body["references"]
        .as_array()
        .expect("references array")
        .iter()
        .all(|row| row["share"]["partner"].as_str() == Some("org-local")));

    let cli_output = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "trust",
            "evidence-share",
            "list",
            "--agent-subject",
            &local_leaf_hex,
            "--json",
        ])
        .output()
        .expect("run shared evidence CLI");
    assert!(
        cli_output.status.success(),
        "shared evidence CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli_body: serde_json::Value =
        serde_json::from_slice(&cli_output.stdout).expect("parse shared evidence CLI json");
    assert_eq!(cli_body["summary"]["matchingShares"].as_u64(), Some(1));
    assert_eq!(cli_body["summary"]["matchingReferences"].as_u64(), Some(2));

    let _ = std::fs::remove_dir_all(&dir);
}

/// GET /v1/receipts/query returns JSON (not HTML) even when SPA dist/ does not exist.
/// This verifies API routes take priority over the SPA catch-all.
#[test]
fn test_api_routes_not_shadowed_by_spa() {
    let setup = setup_with_receipts("pact-api-priority");

    let response = setup
        .client
        .get(format!("{}/v1/receipts/query", setup.base_url))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", setup.service_token),
        )
        .send()
        .expect("send API request");

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "API should return 200"
    );

    // The Content-Type must be application/json, not text/html.
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "API response Content-Type should be application/json, got: {content_type}"
    );

    let _ = std::fs::remove_dir_all(&setup.dir);
}
