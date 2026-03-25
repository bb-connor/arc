#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use pact_core::capability::{
    CapabilityToken, CapabilityTokenBody, Operation, PactScope, ToolGrant,
};
use pact_core::crypto::Keypair;
use pact_core::receipt::{Decision, PactReceipt, PactReceiptBody, ToolCallAction};
use pact_credentials::{
    build_agent_passport, issue_reputation_credential, AttestationWindow, PactCredentialEvidence,
};
use pact_did::DidPact;
use pact_kernel::build_checkpoint;
use pact_reputation::{LocalReputationScorecard, MetricValue};
use pact_store_sqlite::SqliteReceiptStore;

fn unique_path(prefix: &str, suffix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}{suffix}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn capability_with_id(id: &str, subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: PactScope {
                grants: vec![ToolGrant {
                    server_id: "filesystem".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Read],
                    constraints: vec![],
                    max_invocations: Some(20),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..PactScope::default()
            },
            issued_at: 100,
            expires_at: 100_000,
            delegation_chain: vec![],
        },
        issuer,
    )
    .expect("sign capability")
}

fn receipt_with_ts(id: &str, capability_id: &str, timestamp: u64) -> PactReceipt {
    let keypair = Keypair::generate();
    PactReceipt::sign(
        PactReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "filesystem".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/workspace/safe/readme.md"
            }))
            .expect("action"),
            decision: Decision::Allow,
            content_hash: format!("content-{id}"),
            policy_hash: "policy-passport".to_string(),
            evidence: Vec::new(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign receipt")
}

fn sample_scorecard(subject_key: &str) -> LocalReputationScorecard {
    LocalReputationScorecard {
        subject_key: subject_key.to_string(),
        computed_at: 1_710_000_000,
        boundary_pressure: pact_reputation::BoundaryPressureMetrics {
            deny_ratio: MetricValue::Known(0.1),
            policies_observed: 1,
            receipts_observed: 3,
        },
        resource_stewardship: pact_reputation::ResourceStewardshipMetrics {
            average_utilization: MetricValue::Known(0.6),
            fit_score: MetricValue::Known(0.9),
            capped_grants_observed: 1,
        },
        least_privilege: pact_reputation::LeastPrivilegeMetrics {
            score: MetricValue::Known(0.8),
            capabilities_observed: 1,
        },
        history_depth: pact_reputation::HistoryDepthMetrics {
            score: MetricValue::Known(0.7),
            receipt_count: 3,
            active_days: 3,
            first_seen: Some(1_709_900_000),
            last_seen: Some(1_710_000_000),
            span_days: 3,
            activity_ratio: MetricValue::Known(1.0),
        },
        specialization: pact_reputation::SpecializationMetrics {
            score: MetricValue::Known(0.5),
            distinct_tools: 2,
        },
        delegation_hygiene: pact_reputation::DelegationHygieneMetrics {
            score: MetricValue::Known(0.9),
            delegations_observed: 1,
            scope_reduction_rate: MetricValue::Known(1.0),
            ttl_reduction_rate: MetricValue::Known(1.0),
            budget_reduction_rate: MetricValue::Known(1.0),
        },
        reliability: pact_reputation::ReliabilityMetrics {
            score: MetricValue::Known(0.95),
            completion_rate: MetricValue::Known(1.0),
            cancellation_rate: MetricValue::Known(0.0),
            incompletion_rate: MetricValue::Known(0.0),
            receipts_observed: 3,
        },
        incident_correlation: pact_reputation::IncidentCorrelationMetrics {
            score: MetricValue::Unknown,
            incidents_observed: None,
        },
        composite_score: MetricValue::Known(0.82),
        effective_weight_sum: 0.9,
    }
}

fn sample_evidence() -> PactCredentialEvidence {
    PactCredentialEvidence {
        query: AttestationWindow {
            since: Some(1_709_900_000),
            until: 1_710_000_000,
        },
        receipt_count: 3,
        receipt_ids: vec![
            "rcpt-1".to_string(),
            "rcpt-2".to_string(),
            "rcpt-3".to_string(),
        ],
        checkpoint_roots: vec!["abc123".to_string()],
        receipt_log_urls: vec!["https://trust.example.com/v1/receipts".to_string()],
        lineage_records: 1,
        uncheckpointed_receipts: 0,
    }
}

#[test]
fn passport_create_verify_and_present_roundtrip() {
    let receipt_db_path = unique_path("passport", ".sqlite3");
    let passport_path = unique_path("passport", ".json");
    let presented_path = unique_path("passport-presented", ".json");
    let challenge_path = unique_path("passport-challenge", ".json");
    let response_path = unique_path("passport-response", ".json");
    let signing_seed_path = unique_path("passport-signing-seed", ".txt");
    let holder_seed_path = unique_path("passport-holder-seed", ".txt");
    let accept_policy_path = unique_path("passport-policy-accept", ".yaml");
    let reject_policy_path = unique_path("passport-policy-reject", ".yaml");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_with_id("cap-passport", &subject, &issuer);

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_pact_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-passport", 101))
            .expect("append receipt");
        let seq2 = store
            .append_pact_receipt_returning_seq(&receipt_with_ts("rcpt-2", "cap-passport", 102))
            .expect("append receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    let subject_public_key = subject.public_key().to_hex();
    let create = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db"),
            "passport",
            "create",
            "--subject-public-key",
            &subject_public_key,
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("seed path"),
            "--validity-days",
            "30",
            "--require-checkpoints",
            "--receipt-log-url",
            "https://trust.example.com/v1/receipts",
        ])
        .output()
        .expect("run passport create");

    assert!(
        create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let subject_did = format!("did:pact:{subject_public_key}");
    assert_eq!(passport["subject"], subject_did);
    assert_eq!(
        passport["credentials"]
            .as_array()
            .expect("credentials array")
            .len(),
        1
    );
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did")
        .to_string();
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(&holder_seed_path, format!("{}\n", subject.seed_hex())).expect("write holder seed");

    let verify = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "verify",
            "--input",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("run passport verify");

    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("passport verified"));

    fs::write(
        &accept_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\nmaxAttestationAgeDays: 30\nrequireCheckpointCoverage: true\nrequireReceiptLogUrls: true\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write accept policy");

    let evaluate_accept = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "evaluate",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--policy",
            accept_policy_path.to_str().expect("accept policy path"),
        ])
        .output()
        .expect("run passport evaluate accept");

    assert!(
        evaluate_accept.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&evaluate_accept.stdout),
        String::from_utf8_lossy(&evaluate_accept.stderr)
    );
    let accept_json: serde_json::Value =
        serde_json::from_slice(&evaluate_accept.stdout).expect("parse evaluate accept output");
    assert_eq!(accept_json["accepted"], true);
    assert_eq!(accept_json["matchedCredentialIndexes"][0], 0);

    fs::write(
        &reject_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 1000\nrequireCheckpointCoverage: true\nrequireReceiptLogUrls: true\n",
            (composite_score + 0.10).min(1.0)
        ),
    )
    .expect("write reject policy");

    let evaluate_reject = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "evaluate",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--policy",
            reject_policy_path.to_str().expect("reject policy path"),
        ])
        .output()
        .expect("run passport evaluate reject");

    assert!(
        evaluate_reject.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&evaluate_reject.stdout),
        String::from_utf8_lossy(&evaluate_reject.stderr)
    );
    let reject_json: serde_json::Value =
        serde_json::from_slice(&evaluate_reject.stdout).expect("parse evaluate reject output");
    assert_eq!(reject_json["accepted"], false);
    assert!(reject_json["credentialResults"][0]["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .any(|reason| reason
            .as_str()
            .unwrap_or_default()
            .contains("receipt_count")));

    let present = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "present",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            presented_path.to_str().expect("presented path"),
            "--issuer",
            &issuer_did,
            "--max-credentials",
            "1",
        ])
        .output()
        .expect("run passport present");

    assert!(
        present.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&present.stdout),
        String::from_utf8_lossy(&present.stderr)
    );

    let verify_presented = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "verify",
            "--input",
            presented_path.to_str().expect("presented path"),
        ])
        .output()
        .expect("run presented passport verify");

    assert!(
        verify_presented.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify_presented.stdout),
        String::from_utf8_lossy(&verify_presented.stderr)
    );

    let create_challenge = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "create",
            "--output",
            challenge_path.to_str().expect("challenge path"),
            "--verifier",
            "https://rp.example.com",
            "--ttl-secs",
            "300",
            "--issuer",
            &issuer_did,
            "--max-credentials",
            "1",
            "--policy",
            accept_policy_path.to_str().expect("accept policy path"),
        ])
        .output()
        .expect("run challenge create");

    assert!(
        create_challenge.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_challenge.stdout),
        String::from_utf8_lossy(&create_challenge.stderr)
    );

    let respond = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "respond",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--holder-seed-file",
            holder_seed_path.to_str().expect("holder seed path"),
            "--output",
            response_path.to_str().expect("response path"),
        ])
        .output()
        .expect("run challenge respond");

    assert!(
        respond.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&respond.stdout),
        String::from_utf8_lossy(&respond.stderr)
    );

    let verify_response = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "challenge",
            "verify",
            "--input",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
        ])
        .output()
        .expect("run challenge verify");

    assert!(
        verify_response.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify_response.stdout),
        String::from_utf8_lossy(&verify_response.stderr)
    );
    let response_json: serde_json::Value =
        serde_json::from_slice(&verify_response.stdout).expect("parse challenge verify output");
    assert_eq!(response_json["accepted"], true);
    assert_eq!(response_json["subject"], subject_did);
    assert_eq!(response_json["verifier"], "https://rp.example.com");
    assert_eq!(response_json["credentialCount"], 1);
    assert_eq!(response_json["policyEvaluation"]["accepted"], true);

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_file(passport_path);
    let _ = fs::remove_file(presented_path);
    let _ = fs::remove_file(challenge_path);
    let _ = fs::remove_file(response_path);
    let _ = fs::remove_file(signing_seed_path);
    let _ = fs::remove_file(holder_seed_path);
    let _ = fs::remove_file(accept_policy_path);
    let _ = fs::remove_file(reject_policy_path);
}

#[test]
fn passport_create_require_checkpoints_fails_for_uncheckpointed_receipts() {
    let receipt_db_path = unique_path("passport-no-checkpoint", ".sqlite3");
    let passport_path = unique_path("passport-no-checkpoint", ".json");
    let signing_seed_path = unique_path("passport-no-checkpoint-seed", ".txt");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_with_id("cap-passport-no-checkpoint", &subject, &issuer);

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        store
            .append_pact_receipt_returning_seq(&receipt_with_ts(
                "rcpt-uncheckpointed",
                "cap-passport-no-checkpoint",
                101,
            ))
            .expect("append receipt");
    }

    let create = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db"),
            "passport",
            "create",
            "--subject-public-key",
            &subject.public_key().to_hex(),
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("seed path"),
            "--require-checkpoints",
        ])
        .output()
        .expect("run passport create");

    assert!(
        !create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(String::from_utf8_lossy(&create.stderr).contains("uncheckpointed"));

    let _ = fs::remove_file(receipt_db_path);
    let _ = fs::remove_file(passport_path);
    let _ = fs::remove_file(signing_seed_path);
}

#[test]
fn passport_policy_reference_flow_is_replay_safe_locally() {
    let receipt_db_path = unique_path("passport-ref", ".sqlite3");
    let passport_path = unique_path("passport-ref", ".json");
    let challenge_path = unique_path("passport-ref-challenge", ".json");
    let response_path = unique_path("passport-ref-response", ".json");
    let signing_seed_path = unique_path("passport-ref-signing-seed", ".txt");
    let holder_seed_path = unique_path("passport-ref-holder-seed", ".txt");
    let verifier_seed_path = unique_path("passport-ref-verifier-seed", ".txt");
    let raw_policy_path = unique_path("passport-ref-policy", ".yaml");
    let signed_policy_path = unique_path("passport-ref-policy-doc", ".json");
    let policy_registry_path = unique_path("passport-ref-policy-registry", ".json");
    let challenge_db_path = unique_path("passport-ref-challenge-store", ".sqlite3");

    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = capability_with_id("cap-passport-ref", &subject, &issuer);

    {
        let mut store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");
        store
            .record_capability_snapshot(&capability, None)
            .expect("record capability snapshot");
        let seq1 = store
            .append_pact_receipt_returning_seq(&receipt_with_ts(
                "rcpt-ref-1",
                "cap-passport-ref",
                101,
            ))
            .expect("append receipt");
        let seq2 = store
            .append_pact_receipt_returning_seq(&receipt_with_ts(
                "rcpt-ref-2",
                "cap-passport-ref",
                102,
            ))
            .expect("append receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq1, seq2)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &issuer,
        )
        .expect("build checkpoint");
        store
            .store_checkpoint(&checkpoint)
            .expect("store checkpoint");
    }

    let subject_public_key = subject.public_key().to_hex();
    let create = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            receipt_db_path.to_str().expect("receipt db"),
            "passport",
            "create",
            "--subject-public-key",
            &subject_public_key,
            "--output",
            passport_path.to_str().expect("passport path"),
            "--signing-seed-file",
            signing_seed_path.to_str().expect("seed path"),
            "--validity-days",
            "30",
            "--require-checkpoints",
            "--receipt-log-url",
            "https://trust.example.com/v1/receipts",
        ])
        .output()
        .expect("run passport create");
    assert!(
        create.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let passport: serde_json::Value =
        serde_json::from_slice(&fs::read(&passport_path).expect("read passport"))
            .expect("parse passport");
    let issuer_did = passport["credentials"][0]["issuer"]
        .as_str()
        .expect("issuer did")
        .to_string();
    let composite_score = passport["credentials"][0]["credentialSubject"]["metrics"]
        ["composite_score"]["value"]
        .as_f64()
        .expect("composite score");
    fs::write(&holder_seed_path, format!("{}\n", subject.seed_hex())).expect("write holder seed");
    fs::write(
        &raw_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_did}\"\nminCompositeScore: {}\nminReceiptCount: 2\nminLineageRecords: 1\nrequireCheckpointCoverage: true\nrequireReceiptLogUrls: true\n",
            (composite_score - 0.01).max(0.0)
        ),
    )
    .expect("write raw verifier policy");

    let create_policy = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "policy",
            "create",
            "--output",
            signed_policy_path.to_str().expect("signed policy path"),
            "--policy-id",
            "rp-default",
            "--verifier",
            "https://rp.example.com",
            "--signing-seed-file",
            verifier_seed_path.to_str().expect("verifier seed path"),
            "--policy",
            raw_policy_path.to_str().expect("raw policy path"),
            "--expires-at",
            "1900000000",
            "--verifier-policies-file",
            policy_registry_path.to_str().expect("policy registry path"),
        ])
        .output()
        .expect("run passport policy create");
    assert!(
        create_policy.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_policy.stdout),
        String::from_utf8_lossy(&create_policy.stderr)
    );

    let create_challenge = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "create",
            "--output",
            challenge_path.to_str().expect("challenge path"),
            "--verifier",
            "https://rp.example.com",
            "--policy-id",
            "rp-default",
            "--verifier-policies-file",
            policy_registry_path.to_str().expect("policy registry path"),
            "--verifier-challenge-db",
            challenge_db_path.to_str().expect("challenge db path"),
        ])
        .output()
        .expect("run passport challenge create");
    assert!(
        create_challenge.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&create_challenge.stdout),
        String::from_utf8_lossy(&create_challenge.stderr)
    );

    let challenge: serde_json::Value =
        serde_json::from_slice(&fs::read(&challenge_path).expect("read challenge"))
            .expect("parse challenge");
    assert_eq!(challenge["policyRef"]["policyId"], "rp-default");
    assert!(challenge["challengeId"].as_str().is_some());
    assert!(challenge["policy"].is_null());

    let respond = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "respond",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--holder-seed-file",
            holder_seed_path.to_str().expect("holder seed path"),
            "--output",
            response_path.to_str().expect("response path"),
        ])
        .output()
        .expect("run challenge respond");
    assert!(
        respond.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&respond.stdout),
        String::from_utf8_lossy(&respond.stderr)
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "challenge",
            "verify",
            "--input",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--verifier-policies-file",
            policy_registry_path.to_str().expect("policy registry path"),
            "--verifier-challenge-db",
            challenge_db_path.to_str().expect("challenge db path"),
        ])
        .output()
        .expect("run challenge verify");
    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_json: serde_json::Value =
        serde_json::from_slice(&verify.stdout).expect("parse challenge verify json");
    assert_eq!(verify_json["accepted"], true);
    assert_eq!(verify_json["policyEvaluated"], true);
    assert_eq!(verify_json["policyId"], "rp-default");
    assert_eq!(verify_json["policySource"], "registry:rp-default");
    assert_eq!(verify_json["replayState"], "consumed");
    assert!(verify_json["challengeId"].as_str().is_some());

    let replay = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "challenge",
            "verify",
            "--input",
            response_path.to_str().expect("response path"),
            "--challenge",
            challenge_path.to_str().expect("challenge path"),
            "--verifier-policies-file",
            policy_registry_path.to_str().expect("policy registry path"),
            "--verifier-challenge-db",
            challenge_db_path.to_str().expect("challenge db path"),
        ])
        .output()
        .expect("run replay challenge verify");
    assert!(
        !replay.status.success(),
        "replayed challenge verification should fail\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("already been consumed"),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[test]
fn passport_cli_supports_multi_issuer_verify_evaluate_and_present() {
    let passport_path = unique_path("passport-multi-issuer", ".json");
    let presented_path = unique_path("passport-multi-issuer-presented", ".json");
    let verify_policy_path = unique_path("passport-multi-issuer-policy", ".yaml");

    let subject_public_key = Keypair::from_seed(&[7u8; 32]).public_key();
    let subject_key = subject_public_key.to_hex();
    let subject_did = DidPact::from_public_key(subject_public_key);
    let credential_a = issue_reputation_credential(
        &Keypair::from_seed(&[1u8; 32]),
        sample_scorecard(&subject_key),
        sample_evidence(),
        1_900_000_000,
        1_900_086_400,
    )
    .expect("credential a");
    let credential_b = issue_reputation_credential(
        &Keypair::from_seed(&[2u8; 32]),
        sample_scorecard(&subject_key),
        sample_evidence(),
        1_900_000_000,
        1_900_086_400,
    )
    .expect("credential b");
    let issuer_a = credential_a.unsigned.issuer.clone();
    let issuer_b = credential_b.unsigned.issuer.clone();
    let passport = build_agent_passport(
        &subject_did.to_string(),
        vec![credential_a.clone(), credential_b.clone()],
    )
    .expect("passport");
    fs::write(
        &passport_path,
        serde_json::to_vec_pretty(&passport).expect("serialize passport"),
    )
    .expect("write passport");
    fs::write(
        &verify_policy_path,
        format!(
            "issuerAllowlist:\n  - \"{issuer_a}\"\nminCompositeScore: 0.7\nminReceiptCount: 2\nminLineageRecords: 1\n"
        ),
    )
    .expect("write verifier policy");

    let verify = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "verify",
            "--input",
            passport_path.to_str().expect("passport path"),
        ])
        .output()
        .expect("run passport verify");
    assert!(
        verify.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_json: serde_json::Value =
        serde_json::from_slice(&verify.stdout).expect("parse verify output");
    assert_eq!(verify_json["issuer"], serde_json::Value::Null);
    assert_eq!(verify_json["issuerCount"], 2);
    let issuers = verify_json["issuers"].as_array().expect("issuers array");
    assert_eq!(issuers.len(), 2);
    assert!(issuers
        .iter()
        .any(|issuer| issuer == &serde_json::json!(issuer_a)));
    assert!(issuers
        .iter()
        .any(|issuer| issuer == &serde_json::json!(issuer_b)));

    let evaluate = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "--json",
            "passport",
            "evaluate",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--policy",
            verify_policy_path.to_str().expect("verify policy path"),
        ])
        .output()
        .expect("run passport evaluate");
    assert!(
        evaluate.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&evaluate.stdout),
        String::from_utf8_lossy(&evaluate.stderr)
    );
    let evaluate_json: serde_json::Value =
        serde_json::from_slice(&evaluate.stdout).expect("parse evaluate output");
    assert_eq!(evaluate_json["accepted"], true);
    assert_eq!(evaluate_json["verification"]["issuerCount"], 2);
    assert_eq!(
        evaluate_json["matchedCredentialIndexes"],
        serde_json::json!([0])
    );
    assert_eq!(
        evaluate_json["matchedIssuers"],
        serde_json::json!([issuer_a])
    );
    assert_eq!(
        evaluate_json["credentialResults"][0]["issuer"],
        evaluate_json["matchedIssuers"][0]
    );
    assert_eq!(evaluate_json["credentialResults"][0]["accepted"], true);
    assert_eq!(evaluate_json["credentialResults"][1]["issuer"], issuer_b);
    assert_eq!(evaluate_json["credentialResults"][1]["accepted"], false);

    let present = Command::new(env!("CARGO_BIN_EXE_pact"))
        .current_dir(workspace_root())
        .args([
            "passport",
            "present",
            "--input",
            passport_path.to_str().expect("passport path"),
            "--output",
            presented_path.to_str().expect("presented path"),
            "--issuer",
            &credential_b.unsigned.issuer,
            "--max-credentials",
            "1",
        ])
        .output()
        .expect("run passport present");
    assert!(
        present.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&present.stdout),
        String::from_utf8_lossy(&present.stderr)
    );
    let presented: serde_json::Value =
        serde_json::from_slice(&fs::read(&presented_path).expect("read presented passport"))
            .expect("parse presented passport");
    assert_eq!(
        presented["credentials"]
            .as_array()
            .expect("credentials")
            .len(),
        1
    );
    assert_eq!(
        presented["credentials"][0]["issuer"],
        credential_b.unsigned.issuer
    );
}
