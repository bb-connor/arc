#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(unix)]

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};
use chio_store_sqlite::SqliteReceiptStore;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    temp: tempfile::TempDir,
    report: Value,
    client: PathBuf,
    key: Keypair,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let policy = temp.path().join("policy.yaml");
        fs::write(&policy, "kernel:\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: journal\n        tool: append_note\n        max_invocations: 2\n").unwrap();
        let client = temp.path().join("client.json");
        fs::write(&client, json!({"mcpServers": {
            "journal": {"command":"never-launch-this-server", "args":["private-argument"], "env":{"TOKEN":"private-credential"}},
            "remote": {"url":"https://example.invalid/mcp", "headers":{"Authorization":"private-credential"}}
        }}).to_string()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["mcp", "adopt", "--config"])
            .arg(&client)
            .arg("--policy")
            .arg(policy)
            .arg("--output")
            .arg(temp.path().join("adopted"))
            .args(["--server", "journal"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        fs::copy(report["config_path"].as_str().unwrap(), &client).unwrap();
        Self {
            temp,
            report,
            client,
            key: Keypair::generate(),
        }
    }

    fn path(&self, field: &str) -> &Path {
        Path::new(self.report["wrapped_servers"][0][field].as_str().unwrap())
    }

    fn status(&self, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["--format", "json", "mcp", "status", "--adoption"])
            .arg(self.temp.path().join("adopted"))
            .arg("--config")
            .arg(&self.client)
            .args(extra)
            .output()
            .unwrap()
    }

    fn receipt(&self, number: u64, server: &str, policy: &str) -> ChioReceipt {
        ChioReceipt::sign(
            ChioReceiptBody {
                id: format!("fixture-{number}"),
                timestamp: 1_780_000_000 + number,
                capability_id: "test-capability".to_owned(),
                tool_server: server.to_owned(),
                tool_name: "append_note".to_owned(),
                action: ToolCallAction::from_parameters(
                    json!({"note":"private-argument", "n":number}),
                )
                .unwrap(),
                decision: Some(if number == 2 {
                    Decision::Deny {
                        reason: "private-credential".to_owned(),
                        guard: "budget".to_owned(),
                    }
                } else {
                    Decision::Allow
                }),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: vec![],
                content_hash: chio_core::sha256_hex(b"null"),
                policy_hash: policy.to_owned(),
                evidence: vec![],
                metadata: None,
                trust_level: Default::default(),
                tenant_id: None,
                kernel_key: self.key.public_key(),
                bbs_projection_version: None,
            },
            &self.key,
        )
        .unwrap()
    }

    fn seed(&self, server: &str) {
        fs::write(
            self.path("kernel_public_key_file"),
            self.key.public_key().to_hex(),
        )
        .unwrap();
        let store = SqliteReceiptStore::open(self.path("receipt_db")).unwrap();
        for number in 0..3 {
            let receipt = self.receipt(
                number,
                server,
                self.report["policy_runtime_hash"].as_str().unwrap(),
            );
            store.append_chio_receipt_returning_seq(&receipt).unwrap();
        }
    }
}

fn parsed(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn unstarted_adoption_reports_configuration_without_creating_runtime_state() {
    let fixture = Fixture::new();
    let output = fixture.status(&["--admin-all"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parsed(&output);
    assert_eq!(report["servers"][0]["configuration"], "matches_adoption");
    assert_eq!(
        report["servers"][0]["receipts"]["status"],
        "no_recorded_activity"
    );
    assert_eq!(report["servers_outside_this_adoption"], json!(["remote"]));
    assert_eq!(report["live_client_connection_checked"], false);
    assert_eq!(report["complete_history_verified"], false);
    assert!(!fixture.path("receipt_db").exists());
    assert!(!fixture.path("session_db").exists());
    assert!(!fixture.path("kernel_public_key_file").exists());
}

#[test]
fn receipt_read_requires_explicit_operator_scope() {
    let fixture = Fixture::new();
    fs::write(fixture.path("receipt_db"), "invalid database").unwrap();
    let output = fixture.status(&[]);
    assert!(output.status.success());
    assert_eq!(
        parsed(&output)["servers"][0]["receipts"]["status"],
        "not_inspected"
    );
    assert!(!fixture.status(&["--admin-all"]).status.success());
}

#[test]
fn verifies_bounded_recent_sample_without_changing_receipts_or_exposing_parameters() {
    let fixture = Fixture::new();
    fixture.seed("journal");
    let before = fs::read(fixture.path("receipt_db")).unwrap();
    let output = fixture.status(&["--admin-all", "--limit", "2"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = parsed(&output);
    let sample = &report["servers"][0]["receipts"];
    assert_eq!(sample["status"], "verified_sample");
    assert_eq!(sample["verified"], 2);
    assert_eq!(sample["has_older_receipts"], true);
    assert_eq!(
        sample["outcomes"],
        json!({"allow":1, "deny":1, "cancelled":0, "incomplete":0})
    );
    assert_eq!(sample["recent"][0]["matches_current_policy"], true);
    assert_eq!(fs::read(fixture.path("receipt_db")).unwrap(), before);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("private-credential"));
    assert!(!text.contains("private-argument"));
}

#[test]
fn installed_entry_drift_missing_and_disabled_are_distinct_failures() {
    let fixture = Fixture::new();
    let original: Value = serde_json::from_slice(&fs::read(&fixture.client).unwrap()).unwrap();
    for state in ["changed", "missing", "disabled"] {
        let mut client = original.clone();
        match state {
            "changed" => client["mcpServers"]["journal"]["command"] = json!("bypass-kernel"),
            "missing" => {
                client["mcpServers"]
                    .as_object_mut()
                    .unwrap()
                    .remove("journal");
            }
            _ => client["mcpServers"]["journal"]["disabled"] = json!(true),
        }
        fs::write(&fixture.client, client.to_string()).unwrap();
        let output = fixture.status(&[]);
        assert!(!output.status.success(), "{state}");
        assert_eq!(parsed(&output)["servers"][0]["configuration"], state);
    }
}

#[test]
fn missing_kernel_and_invalid_policy_are_actionable_failures() {
    let fixture = Fixture::new();
    let policy = fixture.report["policy_path"].as_str().unwrap();
    fs::write(policy, "secret-value: private-credential\n").unwrap();
    let output = fixture.status(&[]);
    assert!(!output.status.success());
    assert_eq!(parsed(&output)["policy"]["status"], "unreadable_or_invalid");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-credential"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-credential"));
    let path = fixture.report["config_path"].as_str().unwrap();
    let mut config: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    config["mcpServers"]["journal"]["command"] = json!(fixture.temp.path().join("missing-chio"));
    fs::write(path, config.to_string()).unwrap();
    fs::write(&fixture.client, config.to_string()).unwrap();
    let report = parsed(&fixture.status(&[]));
    assert_eq!(report["servers"][0]["kernel_executable_available"], false);
}

#[test]
fn valid_policy_updates_are_reported_without_relabeling_old_receipts() {
    let fixture = Fixture::new();
    fixture.seed("journal");
    let path = fixture.report["policy_path"].as_str().unwrap();
    let source = fs::read_to_string(path)
        .unwrap()
        .replace("max_invocations: 2", "max_invocations: 3");
    fs::write(path, source).unwrap();
    let output = fixture.status(&["--admin-all"]);
    assert!(output.status.success());
    let report = parsed(&output);
    assert_eq!(report["policy"]["changed_since_adoption"], true);
    assert_eq!(
        report["servers"][0]["receipts"]["recent"][0]["matches_current_policy"],
        false
    );
}

#[test]
fn signer_replacement_and_wrong_server_receipts_fail_verification() {
    for wrong_server in [false, true] {
        let fixture = Fixture::new();
        fixture.seed(if wrong_server {
            "different-server"
        } else {
            "journal"
        });
        if !wrong_server {
            fs::write(
                fixture.path("kernel_public_key_file"),
                Keypair::generate().public_key().to_hex(),
            )
            .unwrap();
        }
        let output = fixture.status(&["--admin-all"]);
        assert!(!output.status.success());
        assert_eq!(
            parsed(&output)["servers"][0]["receipts"]["error"],
            if wrong_server {
                "receipt_server_mismatch"
            } else {
                "receipt_signer_mismatch"
            }
        );
    }
}

#[test]
fn tampered_and_oversized_receipts_fail_without_partial_verified_output() {
    for oversized in [false, true] {
        let fixture = Fixture::new();
        fs::write(
            fixture.path("kernel_public_key_file"),
            fixture.key.public_key().to_hex(),
        )
        .unwrap();
        let mut receipt = fixture.receipt(
            0,
            "journal",
            fixture.report["policy_runtime_hash"].as_str().unwrap(),
        );
        receipt.tool_name = "tampered-name".to_owned();
        let raw = if oversized {
            "x".repeat(1_048_577)
        } else {
            serde_json::to_string(&receipt).unwrap()
        };
        // An untrusted/corrupt database must not be mistaken for verified
        // history. Real-store valid receipt coverage is exercised above.
        let conn = rusqlite::Connection::open(fixture.path("receipt_db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE chio_tool_receipts (seq INTEGER PRIMARY KEY, raw_json TEXT);",
        )
        .unwrap();
        conn.execute("INSERT INTO chio_tool_receipts VALUES (1, ?1)", [raw])
            .unwrap();
        drop(conn);
        let output = fixture.status(&["--admin-all"]);
        assert!(!output.status.success());
        let result = parsed(&output);
        assert_eq!(
            result["servers"][0]["receipts"]["error"],
            if oversized {
                "receipt_payload_too_large"
            } else {
                "receipt_integrity_invalid"
            }
        );
        assert!(result["servers"][0]["receipts"].get("recent").is_none());
    }
}

#[test]
fn report_path_escape_and_rewritten_launch_prefix_reject() {
    let fixture = Fixture::new();
    let report_path = fixture.temp.path().join("adopted/adoption.json");
    let mut report = fixture.report.clone();
    report["wrapped_servers"][0]["receipt_db"] = json!("/tmp/unrelated-receipts.sqlite");
    fs::write(&report_path, report.to_string()).unwrap();
    assert!(!fixture.status(&["--admin-all"]).status.success());
    fs::write(report_path, fixture.report.to_string()).unwrap();
    let path = fixture.report["config_path"].as_str().unwrap();
    let mut generated: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    generated["mcpServers"]["journal"]["args"][5] = json!("wrap");
    fs::write(path, generated.to_string()).unwrap();
    fs::write(&fixture.client, generated.to_string()).unwrap();
    assert!(!fixture.status(&[]).status.success());
}

#[test]
fn advisory_receipt_cannot_be_reported_as_kernel_mediation() {
    use chio_core::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    let fixture = Fixture::new();
    let mut body = fixture
        .receipt(
            0,
            "journal",
            fixture.report["policy_runtime_hash"].as_str().unwrap(),
        )
        .body();
    body.receipt_kind = ReceiptKind::AdvisoryEvaluation;
    body.boundary_class = BoundaryClass::AdvisoryOnly;
    body.decision = None;
    body.observation_outcome = Some(ObservationOutcome::Evaluated);
    body.trust_level = TrustLevel::Advisory;
    body.tool_origin = ToolOrigin::HostExecutedUnmediated;
    body.redaction_mode = RedactionMode::Redacted;
    let receipt = ChioReceipt::sign(body, &fixture.key).unwrap();
    assert!(receipt.verify_signature().unwrap());
    fs::write(
        fixture.path("kernel_public_key_file"),
        fixture.key.public_key().to_hex(),
    )
    .unwrap();
    let store = SqliteReceiptStore::open(fixture.path("receipt_db")).unwrap();
    store.append_chio_receipt_returning_seq(&receipt).unwrap();
    drop(store);
    let output = fixture.status(&["--admin-all"]);
    assert!(!output.status.success());
    assert_eq!(
        parsed(&output)["servers"][0]["receipts"]["error"],
        "receipt_is_not_a_preventive_kernel_decision"
    );
}

#[test]
fn missing_or_symlinked_kernel_keys_are_not_treated_as_unstarted() {
    for symlink in [false, true] {
        let fixture = Fixture::new();
        fixture.seed("journal");
        let key_path = fixture.path("kernel_public_key_file");
        let alternate = fixture.temp.path().join("other.pub");
        fs::rename(key_path, &alternate).unwrap();
        if symlink {
            std::os::unix::fs::symlink(alternate, key_path).unwrap();
        }
        let output = fixture.status(&["--admin-all"]);
        assert!(!output.status.success());
        assert_eq!(
            parsed(&output)["servers"][0]["receipts"]["error"],
            "missing_or_invalid_receipt_database_or_kernel_key"
        );
    }
}

#[test]
fn disabling_durable_admission_is_a_policy_issue() {
    let fixture = Fixture::new();
    let path = fixture.report["policy_path"].as_str().unwrap();
    let policy = fs::read_to_string(path).unwrap().replace(
        "durable_admission_mode: all",
        "durable_admission_mode: off\n  allow_ephemeral_receipt_log: true\n  allow_unsafe_durable_admission_off: true",
    );
    fs::write(path, policy).unwrap();
    let output = fixture.status(&[]);
    assert!(!output.status.success());
    assert_eq!(
        parsed(&output)["policy"]["status"],
        "durable_admission_disabled"
    );
}
