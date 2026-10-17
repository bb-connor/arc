use super::support::*;
use chio_test_support::prelude::*;

#[test]
fn proof_verify_rejects_retired_v2_bbs_projection_manifest_schema() {
    let tempdir = tempfile::tempdir().test_expect("tempdir");
    let source =
        workspace_root().join("fixtures/proof-room/disclosure-lineage/valid-lineage-ledger");
    let bundle_dir = tempdir.path().join("disclosure-lineage");
    copy_dir_all(&source, &bundle_dir);
    add_valid_disclosure_selective_disclosure_proof(&bundle_dir);

    let retired_schema = "chio.bbs-projection.manifest.v2";
    let manifest_path = bundle_dir.join("bbs-projection-manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).test_expect("read manifest"))
            .test_expect("parse manifest");
    manifest["schema"] = serde_json::json!(retired_schema);
    write_json(&manifest_path, &manifest);
    let manifest_digest =
        chio_core::sha256_hex(&std::fs::read(&manifest_path).test_expect("read manifest"));

    let evidence_graph_path = bundle_dir.join("evidence-graph.json");
    let mut evidence_graph: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&evidence_graph_path).test_expect("read evidence graph"),
    )
    .test_expect("parse evidence graph");
    let node = evidence_graph["nodes"]
        .as_array_mut()
        .test_expect("evidence graph nodes")
        .iter_mut()
        .find(|node| {
            node.get("role").and_then(serde_json::Value::as_str) == Some("bbs-projection-manifest")
        })
        .test_expect("projection manifest node");
    node["schema"] = serde_json::json!(retired_schema);
    node["sha256"] = serde_json::json!(manifest_digest);
    let evidence_graph_bytes =
        serde_json::to_vec(&evidence_graph).test_expect("serialize evidence graph");
    std::fs::write(&evidence_graph_path, &evidence_graph_bytes).test_expect("write evidence graph");
    set_passport_digest(
        &bundle_dir,
        "evidence_graph_sha256",
        chio_core::sha256_hex(&evidence_graph_bytes),
    );

    let output = chio_with_transaction_fixture_roots()
        .arg("proof")
        .arg("verify")
        .arg(bundle_dir.join("transaction-passport.json"))
        .arg("--require")
        .arg("disclosure")
        .output()
        .test_expect("chio command runs");

    assert!(
        !output.status.success(),
        "retired v2 projection manifest unexpectedly verified\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).test_expect("stderr is utf8");
    assert!(stderr.contains(
        "proof verify: unsupported disclosure lineage artifact schema for bbs-projection-manifest.json: chio.bbs-projection.manifest.v2"
    ));
}
