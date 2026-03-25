#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::capability::{MonetaryAmount, Operation, PactScope, ToolGrant};
use pact_core::crypto::Keypair;
use pact_core::receipt::{
    Decision, PactReceipt, PactReceiptBody, ReceiptAttributionMetadata, ToolCallAction,
};
use pact_kernel::{BudgetStore, CapabilityAuthority, LocalCapabilityAuthority, ReceiptStore};
use pact_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};
use reqwest::blocking::Client;

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

fn fixture_path(name: &str) -> PathBuf {
    workspace_root().join("examples/policies").join(name)
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
    policy_path: &PathBuf,
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
            "--policy",
            policy_path.to_str().expect("policy path"),
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

fn create_passport(
    receipt_db_path: &PathBuf,
    budget_db_path: &PathBuf,
    subject_hex: &str,
    passport_path: &PathBuf,
    signing_seed_path: &PathBuf,
) {
    let create_passport = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "passport",
            "create",
            "--subject-public-key",
            subject_hex,
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("signing seed path"),
        ])
        .output()
        .expect("run passport create");
    assert!(
        create_passport.status.success(),
        "pact passport create failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&create_passport.stdout),
        String::from_utf8_lossy(&create_passport.stderr)
    );
}

fn make_receipt(
    id: &str,
    capability_id: &str,
    subject_key: &str,
    issuer_key: &str,
    timestamp: u64,
) -> PactReceipt {
    let kernel_kp = Keypair::generate();
    PactReceipt::sign(
        PactReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/workspace/safe/data.txt"
            }))
            .expect("action"),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": ReceiptAttributionMetadata {
                    subject_key: subject_key.to_string(),
                    issuer_key: issuer_key.to_string(),
                    delegation_depth: 0,
                    grant_index: Some(0),
                }
            })),
            kernel_key: kernel_kp.public_key(),
        },
        &kernel_kp,
    )
    .expect("sign receipt")
}

fn seed_subject_history(
    receipt_db_path: &PathBuf,
    budget_db_path: &PathBuf,
    subject_kp: &Keypair,
) -> String {
    let authority = LocalCapabilityAuthority::new(Keypair::generate());
    let capability = authority
        .issue_capability(
            &subject_kp.public_key(),
            PactScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Read],
                    constraints: Vec::new(),
                    max_invocations: Some(10),
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 50,
                        currency: "USD".to_string(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 500,
                        currency: "USD".to_string(),
                    }),
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            300,
        )
        .expect("issue capability");

    let mut receipt_store = SqliteReceiptStore::open(receipt_db_path).expect("open receipt store");
    receipt_store
        .record_capability_snapshot(&capability, None)
        .expect("record capability snapshot");

    let subject_key = subject_kp.public_key().to_hex();
    let issuer_key = authority.authority_public_key().to_hex();
    receipt_store
        .append_pact_receipt(&make_receipt(
            "rep-1",
            &capability.id,
            &subject_key,
            &issuer_key,
            1_700_000_000,
        ))
        .expect("append first receipt");
    receipt_store
        .append_pact_receipt(&make_receipt(
            "rep-2",
            &capability.id,
            &subject_key,
            &issuer_key,
            1_700_086_500,
        ))
        .expect("append second receipt");

    let mut budget_store = SqliteBudgetStore::open(budget_db_path).expect("open budget store");
    assert!(
        budget_store
            .try_charge_cost(&capability.id, 0, Some(10), 25, Some(50), Some(500))
            .expect("charge cost"),
        "seed budget charge should succeed"
    );

    subject_key
}

#[test]
fn trust_service_exposes_local_reputation_scorecard() {
    let dir = unique_dir("pact-cli-local-reputation-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);

    let listen = reserve_listen_addr();
    let service_token = "local-reputation-service-token";
    let base_url = format!("http://{listen}");
    let _service = spawn_trust_service(
        listen,
        service_token,
        &policy_path,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .get(format!(
            "{base_url}/v1/reputation/local/{subject_hex}?since=1700080000"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .send()
        .expect("send local reputation request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "local reputation request failed: {}",
        response.text().unwrap_or_default()
    );

    let body: serde_json::Value = client
        .get(format!(
            "{base_url}/v1/reputation/local/{subject_hex}?since=1700080000"
        ))
        .header("Authorization", format!("Bearer {service_token}"))
        .send()
        .expect("send local reputation request")
        .json()
        .expect("parse local reputation response");

    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["scoringSource"], "issuance_policy");
    assert_eq!(body["probationary"], true);
    assert_eq!(body["probationaryScoreCeiling"], 0.6);
    assert_eq!(body["scorecard"]["history_depth"]["receipt_count"], 1);
    assert_eq!(
        body["scorecard"]["resource_stewardship"]["average_utilization"]["state"],
        "known"
    );
}

#[test]
fn trust_service_exposes_reputation_compare_over_http() {
    let dir = unique_dir("pact-cli-reputation-compare-direct-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let signing_seed_path = dir.join("authority-seed.txt");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);
    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &signing_seed_path,
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");

    let listen = reserve_listen_addr();
    let service_token = "local-reputation-compare-http-token";
    let base_url = format!("http://{listen}");
    let _service = spawn_trust_service(
        listen,
        service_token,
        &policy_path,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    let response = client
        .post(format!("{base_url}/v1/reputation/compare/{subject_hex}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&serde_json::json!({
            "passport": passport,
        }))
        .send()
        .expect("send reputation compare request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "reputation compare request failed: {}",
        response.text().unwrap_or_default()
    );

    let body: serde_json::Value = client
        .post(format!("{base_url}/v1/reputation/compare/{subject_hex}"))
        .header("Authorization", format!("Bearer {service_token}"))
        .json(&serde_json::json!({
            "passport": serde_json::from_slice::<serde_json::Value>(&std::fs::read(&passport_path).expect("read passport again"))
                .expect("parse passport again"),
        }))
        .send()
        .expect("send reputation compare request")
        .json()
        .expect("parse reputation compare response");

    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["subjectMatches"], true);
    assert_eq!(body["local"]["scoringSource"], "issuance_policy");
    assert_eq!(body["passportVerification"]["credentialCount"], 1);
    assert_eq!(body["sharedEvidence"]["summary"]["matchingShares"], 0);
}

#[test]
fn cli_reputation_local_reports_policy_backed_scorecard() {
    let dir = unique_dir("pact-cli-local-reputation-cli");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);

    let output = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "reputation",
            "local",
            "--subject-public-key",
            &subject_hex,
            "--policy",
            policy_path.to_str().expect("policy path"),
        ])
        .output()
        .expect("run pact reputation local");
    assert!(
        output.status.success(),
        "pact reputation local failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse reputation CLI output");
    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["scoringSource"], "issuance_policy");
    assert_eq!(body["probationary"], true);
    assert!(
        body["resolvedTier"]["name"].as_str().is_some(),
        "resolved tier should be populated"
    );
    assert_eq!(
        body["scorecard"]["resource_stewardship"]["average_utilization"]["state"],
        "known"
    );
}

#[test]
fn cli_reputation_compare_reports_drift_against_fresh_passport() {
    let dir = unique_dir("pact-cli-reputation-compare-cli");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let signing_seed_path = dir.join("authority-seed.txt");
    let verifier_policy_path = dir.join("passport-verifier.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);

    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &signing_seed_path,
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did")
        .to_string();
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    std::fs::write(
        &verifier_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write verifier policy");

    let output = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db path"),
            "--budget-db",
            budget_db_path.to_str().expect("budget db path"),
            "reputation",
            "compare",
            "--subject-public-key",
            &subject_hex,
            "--passport",
            passport_path.to_str().expect("passport path"),
            "--verifier-policy",
            verifier_policy_path.to_str().expect("verifier policy path"),
        ])
        .output()
        .expect("run pact reputation compare");
    assert!(
        output.status.success(),
        "pact reputation compare failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse reputation compare output");
    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["subjectMatches"], true);
    assert_eq!(body["passportEvaluation"]["accepted"], true);
    assert_eq!(body["credentialDrifts"][0]["policyAccepted"], true);
    assert_eq!(body["sharedEvidence"]["summary"]["matchingShares"], 0);
    assert!(
        body["credentialDrifts"][0]["metrics"]["compositeScore"]["localMinusPortable"]
            .as_f64()
            .expect("composite drift")
            .abs()
            < 1e-9
    );
}

#[test]
fn cli_reputation_compare_supports_control_service_local_view() {
    let dir = unique_dir("pact-cli-reputation-compare-http");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");
    let passport_path = dir.join("passport.json");
    let signing_seed_path = dir.join("authority-seed.txt");
    let policy_path = fixture_path("hushspec-reputation.yaml");

    let subject_kp = Keypair::generate();
    let subject_hex = seed_subject_history(&receipt_db_path, &budget_db_path, &subject_kp);

    create_passport(
        &receipt_db_path,
        &budget_db_path,
        &subject_hex,
        &passport_path,
        &signing_seed_path,
    );

    let listen = reserve_listen_addr();
    let service_token = "local-reputation-compare-service-token";
    let base_url = format!("http://{listen}");
    let _service = spawn_trust_service(
        listen,
        service_token,
        &policy_path,
        &receipt_db_path,
        &revocation_db_path,
        &authority_db_path,
        &budget_db_path,
    );

    let client = Client::builder().build().expect("build reqwest client");
    wait_for_trust_service(&client, &base_url);

    let output = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "--control-url",
            &base_url,
            "--control-token",
            service_token,
            "reputation",
            "compare",
            "--subject-public-key",
            &subject_hex,
            "--passport",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("run pact reputation compare over control service");
    assert!(
        output.status.success(),
        "pact reputation compare over control service failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let body: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse remote reputation compare output");
    assert_eq!(body["subjectKey"], subject_hex);
    assert_eq!(body["subjectMatches"], true);
    assert_eq!(body["local"]["scoringSource"], "issuance_policy");
    assert_eq!(
        body["passportVerification"]["subject"],
        format!("did:pact:{subject_hex}")
    );
    assert_eq!(body["sharedEvidence"]["summary"]["matchingShares"], 0);
}
