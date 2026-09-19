//! Disposable proof-room bundles used by the CLI contract tests.
use super::*;

pub(crate) fn copy_proof_room_bundle_to_temp() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = proof_room_bundle_fixture();
    let bundle = tempdir.path().join("proof-room-bundle");
    copy_dir_all(&source, &bundle).test_expect("copy proof room bundle");
    (tempdir, bundle)
}

pub(crate) fn build_minimal_passport_proof_room_bundle() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source = workspace_root().join("fixtures/proof-room/minimal-passport/valid");
    let bundle = tempdir.path().join("minimal-passport-proof-room-bundle");
    std::fs::create_dir_all(bundle.join("roots")).test_expect("create roots dir");
    std::fs::create_dir_all(bundle.join("verifier")).test_expect("create verifier dir");
    std::fs::create_dir_all(bundle.join("artifacts/authority")).test_expect("create authority dir");
    std::fs::create_dir_all(bundle.join("ui/proof-room-static")).test_expect("create ui dir");

    for file in [
        "transaction-passport.json",
        "evidence-graph.json",
        "claim-set.json",
        "verifier-policy.json",
    ] {
        std::fs::copy(source.join(file), bundle.join("roots").join(file))
            .test_expect("copy root artifact");
    }
    for file in [
        "capability-proof.json",
        "guard-decision.json",
        "kernel-receipt.json",
        "policy.json",
        "request-digest.json",
        "response-digest.json",
        "trust-root.json",
    ] {
        std::fs::copy(source.join(file), bundle.join(file)).test_expect("copy evidence artifact");
    }

    let passport_path = source.join("transaction-passport.json");
    let verify_output = chio(&["proof", "verify", utf8_path(&passport_path).as_str()]);
    assert_success(&verify_output);
    let verifier_report: serde_json::Value =
        serde_json::from_slice(&verify_output.stdout).test_expect("verifier report parses");
    let verifier_report_path = bundle.join("verifier/report.json");
    write_json(&verifier_report_path, &verifier_report);

    let verifier_report_ref = artifact_ref(
        &bundle,
        "verifier/report.json",
        "chio.transaction.verifier-report.v1",
    );
    let ui_report = serde_json::json!({
        "schema": "chio.proof-room.verifier-report.v1",
        "id": "proof-room-verifier-report-minimal-passport-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "verdict": "verified",
        "bundle_id": "proof-room-minimal-passport-valid",
        "fixture_id": "minimal-passport-valid",
        "source_verifier_report_ref": verifier_report_ref,
        "ui_verdict_source": "verifier_report_ref",
        "rendered_claims": [
            {
                "claim_id": "claim.transaction.passport_root_verified",
                "source": "verifier/report.json",
                "verdict": "verified"
            },
            {
                "claim_id": "claim.proof_room.verifier_report_bound",
                "source": "verifier/report.json",
                "verdict": "verified"
            }
        ]
    });
    let ui_report_path = bundle.join("ui/proof-room-static/load-report.json");
    write_json(&ui_report_path, &ui_report);
    write_json(
        &bundle.join("artifacts/authority/trust-roots.json"),
        &proof_room_trust_roots_for_seed(TEST_SIGNATURE_SEED),
    );

    let manifest = serde_json::json!({
        "schema": "chio.proof-room.bundle.v1",
        "bundle_id": "proof-room-minimal-passport-valid",
        "fixture_id": "minimal-passport-valid",
        "stage": "stage-0",
        "created_at": "2026-06-10T00:00:00Z",
        "source_commit": "fixture-static",
        "source_branch": "main",
        "source_command": "chio proof verify roots/transaction-passport.json",
        "chio_version": "0.1.0",
        "schema_versions": {
            "proof_room_bundle": "chio.proof-room.bundle.v1",
            "proof_room_verifier_report": "chio.proof-room.verifier-report.v1",
            "transaction_passport": "chio.transaction-passport.v1",
            "transaction_evidence_graph": "chio.transaction.evidence-graph.v1",
            "transaction_claim_set": "chio.transaction.claim-set.v1",
            "transaction_verifier_policy": "chio.transaction.verifier-policy.v1",
            "transaction_verifier_report": "chio.transaction.verifier-report.v1"
        },
        "hash_algorithm": "sha256",
        "transaction_passport_ref": artifact_ref(&bundle, "roots/transaction-passport.json", "chio.transaction-passport.v1"),
        "evidence_graph_ref": artifact_ref(&bundle, "roots/evidence-graph.json", "chio.transaction.evidence-graph.v1"),
        "verifier_report_ref": artifact_ref(&bundle, "verifier/report.json", "chio.transaction.verifier-report.v1"),
        "proof_room_verifier_report_ref": artifact_ref(&bundle, "ui/proof-room-static/load-report.json", "chio.proof-room.verifier-report.v1"),
        "artifacts": [
            artifact(&bundle, "roots/transaction-passport.json", "chio.transaction-passport.v1", "transaction-root", "transaction-passport"),
            artifact(&bundle, "roots/evidence-graph.json", "chio.transaction.evidence-graph.v1", "transaction-root", "evidence-graph"),
            artifact(&bundle, "roots/claim-set.json", "chio.transaction.claim-set.v1", "transaction-root", "claim-set"),
            artifact(&bundle, "roots/verifier-policy.json", "chio.transaction.verifier-policy.v1", "transaction-policy", "verifier-policy"),
            artifact(&bundle, "verifier/report.json", "chio.transaction.verifier-report.v1", "verifier-output", "verifier-report"),
            artifact(&bundle, "ui/proof-room-static/load-report.json", "chio.proof-room.verifier-report.v1", "proof-room-display", "proof-room-report"),
            artifact(&bundle, "capability-proof.json", "chio.capability.proof.v1", "transaction-root", "capability-proof"),
            artifact(&bundle, "guard-decision.json", "chio.guard.decision.v1", "transaction-root", "guard-decision"),
            artifact(&bundle, "kernel-receipt.json", "chio.receipt.v1", "receipt", "receipt"),
            artifact(&bundle, "policy.json", "chio.policy.bundle.v1", "transaction-policy", "policy"),
            artifact(&bundle, "request-digest.json", "chio.request.digest.v1", "transaction-root", "request-digest"),
            artifact(&bundle, "response-digest.json", "chio.response.digest.v1", "transaction-root", "response-digest"),
            artifact(&bundle, "trust-root.json", "chio.trust.root.v1", "transaction-root", "trust-root"),
            artifact(&bundle, "artifacts/authority/trust-roots.json", "chio.proof.first-run.trust-roots.v1", "proof-room-authority", "trust-roots")
        ],
        "claims": [
            {
                "claim_id": "claim.transaction.passport_root_verified",
                "required_artifacts": [
                    "roots/transaction-passport.json",
                    "roots/evidence-graph.json",
                    "roots/claim-set.json",
                    "roots/verifier-policy.json",
                    "verifier/report.json"
                ],
                "checker": "chio proof verify roots/transaction-passport.json",
                "result": "verified",
                "proof_level": "deterministic-verifier-report",
                "caveat": "",
                "source_refs": ["verifier/report.json"]
            },
            {
                "claim_id": "claim.proof_room.verifier_report_bound",
                "required_artifacts": [
                    "verifier/report.json",
                    "ui/proof-room-static/load-report.json"
                ],
                "checker": "chio proof serve --dry-run",
                "result": "verified",
                "proof_level": "hash-bound-display-report",
                "caveat": "The UI report is a consumer of verifier output, not a proof source.",
                "source_refs": ["ui/proof-room-static/load-report.json"]
            }
        ],
        "receipt_coverage": [
            {
                "category": "runtime_terminal_allow",
                "status": "covered",
                "artifact_path": "kernel-receipt.json",
                "terminal_status": "allowed_executed"
            }
        ],
        "negative_cases": [],
        "advisory_artifacts": [],
        "excluded_artifacts": [],
        "signature": {
            "kind": "detached-dsse",
            "signature_ref": "bundle-signature.dsse.json"
        }
    });
    write_json(&bundle.join("manifest.json"), &manifest);

    let mut signature = serde_json::json!({
        "payloadType": "application/vnd.chio.proof-room.bundle.v1+json",
        "payloadRef": artifact_ref(&bundle, "manifest.json", "chio.proof-room.bundle.v1"),
        "signatures": [
            {
                "keyid": "",
                "sig": ""
            }
        ]
    });
    sign_bundle_signature(&bundle, &mut signature);
    write_json(&bundle.join("bundle-signature.dsse.json"), &signature);

    (tempdir, bundle)
}
