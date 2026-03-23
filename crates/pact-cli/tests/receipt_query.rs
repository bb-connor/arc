//! Integration tests for GET /v1/receipts/query endpoint.
//!
//! Tests verify filtering, cursor pagination, total_count, and auth enforcement.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::crypto::Keypair;
use pact_core::receipt::{Decision, PactReceipt, PactReceiptBody, ToolCallAction};
use pact_kernel::SqliteReceiptStore;
use pact_kernel::ReceiptStore;
use reqwest::blocking::Client;

// --- Test helpers ---

fn unique_db_path(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

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
    for _ in 0..100 {
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

/// Common test setup: create temp dir, insert receipts, start trust service, return setup info.
struct TestSetup {
    dir: PathBuf,
    receipt_db_path: PathBuf,
    revocation_db_path: PathBuf,
    authority_db_path: PathBuf,
    budget_db_path: PathBuf,
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
        store.append_pact_receipt(&make_receipt("r-1", "cap-1", "shell", "bash", Decision::Allow, 1000, None)).unwrap();
        store.append_pact_receipt(&make_receipt("r-2", "cap-1", "shell", "bash", Decision::Allow, 1001, None)).unwrap();
        store.append_pact_receipt(&make_receipt("r-3", "cap-1", "files", "read", Decision::Allow, 1002, None)).unwrap();

        // 1 receipt with cap-2
        store.append_pact_receipt(&make_receipt("r-4", "cap-2", "shell", "bash", Decision::Allow, 1003, None)).unwrap();

        // 1 denied receipt with cap-1
        store.append_pact_receipt(&make_receipt(
            "r-5",
            "cap-1",
            "shell",
            "bash",
            Decision::Deny { reason: "policy".to_string(), guard: "allow_guard".to_string() },
            1004,
            Some(200),
        )).unwrap();
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
        receipt_db_path,
        revocation_db_path,
        authority_db_path,
        budget_db_path,
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

    assert_eq!(total_count, 5, "all 5 inserted receipts should be in totalCount");
    assert_eq!(receipts.len(), 5, "all 5 receipts should be returned with default limit");

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

    let next_cursor = body1["nextCursor"].as_u64().expect("nextCursor should be present after page 1");

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
    let ids1: Vec<&str> = receipts1.iter().map(|r| r["id"].as_str().expect("receipt id")).collect();
    let ids2: Vec<&str> = receipts2.iter().map(|r| r["id"].as_str().expect("receipt id")).collect();
    for id in &ids1 {
        assert!(!ids2.contains(id), "receipt {id} appeared on both page 1 and page 2");
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
