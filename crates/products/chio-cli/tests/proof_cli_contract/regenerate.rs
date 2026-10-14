use super::support::*;
use chio_test_support::prelude::*;

fn single_fixture_root(fixture_id: &str, relative_path: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().test_expect("fixture root tempdir");
    let source = workspace_root()
        .join("fixtures/proof-room")
        .join(relative_path);
    copy_dir_all(&source, &root.path().join(relative_path)).test_expect("copy fixture");
    let catalog = serde_json::json!({
        "schema": "chio.proof-room.fixture-root-catalog.v1",
        "fixtures": [{
            "id": fixture_id,
            "kind": "negative-disclosure-crypto-context",
            "path": format!("fixtures/proof-room/{relative_path}"),
            "description": "Single-fixture regeneration root"
        }]
    });
    std::fs::write(
        root.path().join("catalog.json"),
        serde_json::to_vec_pretty(&catalog).test_expect("catalog serializes"),
    )
    .test_expect("write catalog");
    root
}

#[test]
fn proof_fixture_regenerate_check_accepts_committed_fixtures() {
    let root = single_fixture_root("crypto-context-stale-key", "crypto-context/stale-key");
    let root_arg = utf8_path(root.path());

    let output = chio(&[
        "proof",
        "fixture",
        "regenerate",
        "--root",
        root_arg.as_str(),
        "--check",
        "--json",
    ]);

    assert_success(&output);
    let report: serde_json::Value =
        serde_json::from_str(&stdout(output)).test_expect("regenerate report parses");
    assert_eq!(report["schema"], "chio.proof.fixture-regenerate-report.v1");
    assert_eq!(report["passes"], 1);
    assert_eq!(report["changed"], serde_json::json!([]));
}

#[test]
fn proof_fixture_regenerate_restores_a_stale_fixture() {
    let root = single_fixture_root("crypto-context-stale-key", "crypto-context/stale-key");
    let root_arg = utf8_path(root.path());
    let report_path = root
        .path()
        .join("crypto-context/stale-key/verifier-report.json");
    let committed = std::fs::read(&report_path).test_expect("read committed report");
    std::fs::write(&report_path, b"{}\n").test_expect("stale the report");

    let check = chio(&[
        "proof",
        "fixture",
        "regenerate",
        "--root",
        root_arg.as_str(),
        "--check",
    ]);
    assert_failure(&check, "proof fixtures are stale");
    assert_eq!(
        std::fs::read(&report_path).test_expect("read stale report"),
        b"{}\n",
        "--check must not write"
    );

    let regenerate = chio(&[
        "proof",
        "fixture",
        "regenerate",
        "--root",
        root_arg.as_str(),
    ]);
    assert_success(&regenerate);
    assert_eq!(
        std::fs::read(&report_path).test_expect("read regenerated report"),
        committed
    );
}
