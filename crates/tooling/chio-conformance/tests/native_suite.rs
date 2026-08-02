#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_conformance::{
    default_repo_root, load_native_scenarios_from_dir, run_native_conformance_suite,
    NativeAssertionKind, NativeConformanceRunOptions, NativeScenarioCategory, NativeScenarioResult,
    NativeStatus,
};

fn unique_dir(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}"))
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reserve_listen_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

fn wait_for_server(listen: SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(listen).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("fixture server did not start on {listen}");
}

#[test]
fn native_conformance_suite_runs_against_fixture() {
    let repo_root = default_repo_root();
    let output_dir = unique_dir("chio-native-conformance");
    fs::create_dir_all(&output_dir).expect("create output dir");

    let fixture_bin = PathBuf::from(env!("CARGO_BIN_EXE_chio-native-conformance-fixture"));
    let listen = reserve_listen_addr();
    let child = Command::new(&fixture_bin)
        .arg("--http-listen")
        .arg(listen.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fixture server");
    let _guard = ChildGuard { child };
    wait_for_server(listen);

    let options = NativeConformanceRunOptions {
        repo_root: repo_root.clone(),
        scenarios_dir: repo_root.join("tests/conformance/native/scenarios"),
        results_output: output_dir.join("results.json"),
        report_output: output_dir.join("report.md"),
        peer_label: "chio-self".to_string(),
        stdio_command: Some(fixture_bin),
        http_base_url: Some(format!("http://{listen}")),
        trace_output: Some(output_dir.join("trace.ndjson")),
        trace_negative_output: Some(output_dir.join("trace-negative.ndjson")),
        trace_monotone_negative_output: Some(output_dir.join("trace-monotone-negative.ndjson")),
        trace_attenuation_negative_output: Some(
            output_dir.join("trace-attenuation-negative.ndjson"),
        ),
        trace_freshness_negative_output: Some(output_dir.join("trace-freshness-negative.ndjson")),
        trace_observer_key_output: Some(output_dir.join("trace-key.txt")),
    };

    let summary = run_native_conformance_suite(&options).expect("run native suite");
    assert_eq!(summary.scenario_count, 10);

    let results: Vec<NativeScenarioResult> =
        serde_json::from_str(&fs::read_to_string(summary.results_output).expect("read results"))
            .expect("parse results");
    assert_eq!(results.len(), 10);
    assert!(results
        .iter()
        .all(|result| result.status == NativeStatus::Pass));

    let trace_path = summary.trace_output.expect("trace output");
    let trace_key_path = summary
        .trace_observer_key_output
        .expect("trace observer key output");
    let trace = fs::read(trace_path).expect("read trace");
    let trusted_key = chio_core::crypto::PublicKey::from_hex(
        fs::read_to_string(trace_key_path)
            .expect("read trace key")
            .trim(),
    )
    .expect("parse trace key");
    let observations = chio_trace_validate::decode_observations(&trace, &[trusted_key])
        .expect("decode native trace");
    let projection =
        chio_trace_validate::project_revocation_trace(&observations).expect("project native trace");
    assert_eq!(projection.action_coverage().revoke, 1);
    assert_eq!(projection.action_coverage().post_revocation_evaluate, 1);

    let report = fs::read_to_string(summary.report_output).expect("read report");
    assert!(report.contains("Chio Native Conformance Report"));
    assert!(report.contains("Capability Validation"));
    assert!(report.contains("Governed Transaction Enforcement"));
    assert!(report.contains("Keyring Transparency"));
    assert!(report.contains("Secret Broker Boundary"));
    assert!(report.contains("Cage Enforcement"));
    assert!(report.contains("Protocol Primitives"));
}

#[test]
fn enterprise_native_runner_executes_exactly_fifteen_behaviors() {
    let repo_root = default_repo_root();
    let output_dir = unique_dir("chio-enterprise-native-runner");
    let scenarios_dir = output_dir.join("scenarios");
    fs::create_dir_all(&scenarios_dir).expect("create enterprise scenario dir");
    for scenario in [
        "keyring-transparency.json",
        "secret-broker-boundary.json",
        "cage-enforcement.json",
        "protocol-primitives.json",
    ] {
        fs::copy(
            repo_root
                .join("tests/conformance/native/scenarios")
                .join(scenario),
            scenarios_dir.join(scenario),
        )
        .expect("copy enterprise scenario");
    }
    let results_output = output_dir.join("results.json");
    let report_output = output_dir.join("report.md");
    let status = Command::new(env!("CARGO_BIN_EXE_chio-native-conformance-runner"))
        .arg("--scenarios-dir")
        .arg(&scenarios_dir)
        .arg("--results-output")
        .arg(&results_output)
        .arg("--report-output")
        .arg(&report_output)
        .status()
        .expect("run enterprise native runner");
    assert!(status.success(), "enterprise native runner failed");

    let results: Vec<NativeScenarioResult> =
        serde_json::from_str(&fs::read_to_string(results_output).expect("read runner results"))
            .expect("parse runner results");
    assert_eq!(results.len(), 4);
    assert_eq!(
        results
            .iter()
            .map(|result| result.assertions.len())
            .sum::<usize>(),
        15
    );
    assert!(results.iter().all(|result| {
        result.status == NativeStatus::Pass
            && result
                .assertions
                .iter()
                .all(|assertion| assertion.status == NativeStatus::Pass)
    }));
}

#[test]
fn native_standards_artifacts_cover_required_categories_and_references() {
    let repo_root = default_repo_root();
    let scenarios =
        load_native_scenarios_from_dir(repo_root.join("tests/conformance/native/scenarios"))
            .expect("load scenarios");

    let categories = scenarios
        .iter()
        .map(|scenario| scenario.category)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = std::collections::BTreeSet::from([
        NativeScenarioCategory::CapabilityValidation,
        NativeScenarioCategory::DelegationAttenuation,
        NativeScenarioCategory::ReceiptIntegrity,
        NativeScenarioCategory::RevocationPropagation,
        NativeScenarioCategory::DpopVerification,
        NativeScenarioCategory::GovernedTransactionEnforcement,
        NativeScenarioCategory::KeyringTransparency,
        NativeScenarioCategory::SecretBrokerBoundary,
        NativeScenarioCategory::CageEnforcement,
        NativeScenarioCategory::ProtocolPrimitives,
    ]);
    assert_eq!(categories, expected);

    for category in [
        NativeScenarioCategory::KeyringTransparency,
        NativeScenarioCategory::SecretBrokerBoundary,
        NativeScenarioCategory::CageEnforcement,
        NativeScenarioCategory::ProtocolPrimitives,
    ] {
        assert_eq!(
            scenarios
                .iter()
                .filter(|scenario| scenario.category == category)
                .count(),
            1,
            "enterprise native category {category:?} must contain exactly one scenario"
        );
    }

    // Keep all 15 atomic enterprise behaviors exact. A missing assertion,
    // grouped replacement, renamed kind, or reordered contract fails here.
    let required = std::collections::BTreeMap::from([
        (
            "keyring-transparency",
            vec![
                (
                    "key_log_signature_separation",
                    NativeAssertionKind::KeyLogSignatureSeparation,
                ),
                (
                    "key_log_contiguous_sync_applies",
                    NativeAssertionKind::KeyLogContiguousSyncApplies,
                ),
                (
                    "key_log_omitted_noncontiguous_gap_rejected",
                    NativeAssertionKind::KeyLogOmittedNoncontiguousGapRejected,
                ),
                (
                    "key_log_witness_conflict_rejected",
                    NativeAssertionKind::KeyLogWitnessConflictRejected,
                ),
            ],
        ),
        (
            "secret-broker-boundary",
            vec![
                (
                    "broker_proof_complete_request_binding",
                    NativeAssertionKind::BrokerProofCompleteRequestBinding,
                ),
                (
                    "broker_nonce_replay_refused",
                    NativeAssertionKind::BrokerNonceReplayRefused,
                ),
                (
                    "broker_combined_quota_no_double_charge",
                    NativeAssertionKind::BrokerCombinedQuotaNoDoubleCharge,
                ),
                (
                    "broker_encrypted_credential_custody",
                    NativeAssertionKind::BrokerEncryptedCredentialCustody,
                ),
            ],
        ),
        (
            "cage-enforcement",
            vec![
                (
                    "cage_plan_target_fd_identity_bound",
                    NativeAssertionKind::CagePlanTargetFdIdentityBound,
                ),
                (
                    "cage_prepared_mutation_rejected",
                    NativeAssertionKind::CagePreparedMutationRejected,
                ),
                (
                    "cage_exec_transition_mutation_rejected",
                    NativeAssertionKind::CageExecTransitionMutationRejected,
                ),
                (
                    "cage_enforcement_evidence_mutation_rejected",
                    NativeAssertionKind::CageEnforcementEvidenceMutationRejected,
                ),
            ],
        ),
        (
            "protocol-primitives",
            vec![
                (
                    "protocol_aggregate_multi_key_atomic_exhaustion",
                    NativeAssertionKind::ProtocolAggregateMultiKeyAtomicExhaustion,
                ),
                (
                    "protocol_threshold_distinct_signers_required",
                    NativeAssertionKind::ProtocolThresholdDistinctSignersRequired,
                ),
                (
                    "protocol_threshold_approval_replay_refused",
                    NativeAssertionKind::ProtocolThresholdApprovalReplayRefused,
                ),
            ],
        ),
    ]);
    assert_eq!(required.values().map(Vec::len).sum::<usize>(), 15);
    for (scenario_id, expected) in required {
        let scenario = scenarios
            .iter()
            .find(|scenario| scenario.id == scenario_id)
            .expect("required enterprise scenario");
        let actual = scenario
            .assertions
            .iter()
            .map(|assertion| (assertion.name.as_str(), assertion.kind))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "exact behavior inventory changed");
    }

    let draft = fs::read_to_string(repo_root.join("spec/ietf/draft-chio-protocol-00.md"))
        .expect("read internet draft");
    assert!(draft.contains("Intended status: Standards Track"));
    assert!(draft.contains("Security Considerations"));

    let matrix =
        fs::read_to_string(repo_root.join("docs/standards/CHIO_PROTOCOL_ALIGNMENT_MATRIX.md"))
            .expect("read alignment matrix");
    for needle in [
        "GNAP", "SCITT", "RATS", "RFC 9449", "W3C VC", "OID4VCI", "OID4VP", "RFC 8785",
    ] {
        assert!(
            matrix.contains(needle),
            "missing standards mapping for {needle}"
        );
    }
}
