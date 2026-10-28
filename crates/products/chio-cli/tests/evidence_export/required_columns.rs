use super::*;

const REQUIRED_COLUMN_UNVERIFIED: &str = "urn:chio:error:attest:bundle-required-column-unverified";
const FEATURE_UNSUPPORTED: &str = "urn:chio:error:attest:bundle-feature-unsupported";
const CAPABILITY: &str = "cap-required-columns";

fn trust_requiring(columns: &[&str]) -> PathBuf {
    let path = trust_file(&[fixture_keypair().public_key().to_hex()], None);
    let mut trust = read_json(&path);
    trust["required_columns"] = serde_json::json!(columns);
    fs::write(&path, serde_json::to_vec(&trust).test_unwrap()).test_unwrap();
    path
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).test_unwrap()).test_unwrap()
}

fn assert_refused(output: &std::process::Output, exit: i32, urn: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{stderr}");
    assert!(stderr.contains(urn), "{stderr}");
}

/// A checkpointed two-receipt package that carries a signed federation policy.
fn federated_package(directory: &Path) -> PathBuf {
    let db = directory.join("source.sqlite3");
    let output = directory.join("package");
    let policy = directory.join("federation-policy.json");
    let policy_seed = directory.join("federation-policy.seed");
    let issuer = fixture_keypair();
    let store = SqliteReceiptStore::open(&db).test_unwrap();
    let capability = capability_with_id(CAPABILITY, &Keypair::generate(), &issuer);
    store
        .record_capability_snapshot(&capability, None)
        .test_unwrap();
    for timestamp in [100, 101] {
        store
            .append_chio_receipt(&receipt_with_keypair(
                &format!("required-columns-{timestamp}"),
                CAPABILITY,
                timestamp,
                None,
                &issuer,
            ))
            .test_unwrap();
    }
    let receipts = store.receipts_canonical_bytes_range(1, 2).test_unwrap();
    let canonical = receipts
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect::<Vec<_>>();
    let checkpoint = build_checkpoint(1, 1, 2, &canonical, &issuer).test_unwrap();
    store.store_checkpoint(&checkpoint).test_unwrap();
    create_federation_policy(
        &policy,
        &policy_seed,
        "org-alpha",
        "org-beta",
        CAPABILITY,
        4_102_444_800,
    );
    let export = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("--receipt-db")
        .arg(&db)
        .args(["evidence", "export", "--admin-all", "--output"])
        .arg(&output)
        .arg("--kernel-seed-file")
        .arg(fixture_seed_file(&db))
        .arg("--federation-policy")
        .arg(&policy)
        .output()
        .test_unwrap();
    assert!(
        export.status.success(),
        "{}",
        String::from_utf8_lossy(&export.stderr)
    );
    output
}

fn verify(package: &Path, trust: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["--json", "evidence", "verify", "--input"])
        .arg(package)
        .arg("--trust")
        .arg(trust)
        .output()
        .test_unwrap()
}

#[test]
fn package_cli_import_refuses_unverified_required_columns() {
    let directory = tempfile::tempdir().test_unwrap();
    let package = federated_package(directory.path());
    let imported = directory.path().join("imported.sqlite3");
    let import = |trust: &Path| {
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .arg("--json")
            .arg("--receipt-db")
            .arg(&imported)
            .args(["evidence", "import", "--input"])
            .arg(&package)
            .arg("--trust")
            .arg(trust)
            .output()
            .test_unwrap()
    };
    let share = || {
        imported.exists().then(|| {
            SqliteReceiptStore::open(&imported)
                .test_unwrap()
                .get_federated_share_for_capability(CAPABILITY)
                .test_unwrap()
        })
    };

    let identity_root = trust_requiring(&["identity_root"]);
    assert_refused(
        &verify(&package, &identity_root),
        10,
        REQUIRED_COLUMN_UNVERIFIED,
    );
    assert_refused(&import(&identity_root), 10, REQUIRED_COLUMN_UNVERIFIED);
    assert!(share().flatten().is_none());

    assert_refused(
        &import(&trust_requiring(&["decision", "settlement"])),
        50,
        FEATURE_UNSUPPORTED,
    );
    assert!(share().flatten().is_none());

    let accepted = import(&trust_requiring(&["decision"]));
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let (stored, _) = share().flatten().test_unwrap();
    assert_eq!(stored.tool_receipts, 2);
}

#[test]
fn package_cli_verify_refuses_a_settlement_requirement() {
    let directory = tempfile::tempdir().test_unwrap();
    let settlement = trust_requiring(&["settlement"]);
    let package = federated_package(directory.path());
    assert_refused(&verify(&package, &settlement), 50, FEATURE_UNSUPPORTED);
}

#[test]
fn package_cli_verify_refuses_a_settlement_requirement_for_an_empty_package() {
    let directory = tempfile::tempdir().test_unwrap();
    let settlement = trust_requiring(&["settlement"]);
    let empty_db = directory.path().join("empty.sqlite3");
    SqliteReceiptStore::open(&empty_db).test_unwrap();
    let empty = directory.path().join("empty-package");
    export_fixture_package(&empty_db, &empty);
    let accepted = verify(&empty, &fixture_trust_file());
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&accepted.stdout).test_unwrap();
    assert_eq!(report["toolReceipts"], 0);
    assert_refused(&verify(&empty, &settlement), 50, FEATURE_UNSUPPORTED);
}

fn read_lines(path: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .test_unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).test_unwrap())
        .collect()
}

/// The remote import request for the exported package directory `output`.
fn remote_import_request(output: &Path) -> serde_json::Value {
    let manifest = read_json(&output.join("manifest.json"));
    let lines = |name: &str| read_lines(&output.join(name));
    serde_json::json!({
        "package": {
            "envelope": read_json(&output.join("export-envelope.json")),
            "bundle": {
                "query": read_json(&output.join("query.json")),
                "toolReceipts": lines("receipts.ndjson"),
                "childReceipts": lines("child-receipts.ndjson"),
                "childReceiptScope": manifest["childReceiptScope"],
                "checkpoints": lines("checkpoints.ndjson"),
                "capabilityLineage": lines("capability-lineage.ndjson"),
                "inclusionProofs": lines("inclusion-proofs.ndjson"),
                "uncheckpointedReceipts": lines("uncheckpointed-receipts.ndjson"),
                "retention": read_json(&output.join("retention.json"))
            },
            "transparency": {
                "publications": lines("checkpoint-publications.ndjson"),
                "witnesses": lines("checkpoint-witnesses.ndjson"),
                "consistency_proofs": lines("checkpoint-consistency-proofs.ndjson"),
                "equivocations": lines("checkpoint-equivocations.ndjson")
            },
            "federationPolicy": read_json(&output.join("federation-policy.json")),
            "manifest": manifest
        },
        "trust": {
            "schema": "chio.verifier-trust.v1",
            "kernel_keys": [fixture_keypair().public_key().to_hex()],
            "exchange_keys": [],
            "root_policy_keys": [],
        }
    })
}

/// Remote imports refuse a trust file whose required columns the package does
/// not verify, before forwarding or storing anything.
pub(super) fn verify_remote_required_columns(
    client: &Client,
    base_url: &str,
    token: &str,
    output: &Path,
    db: &Path,
) {
    let endpoint = format!("{base_url}/v1/evidence/import");
    let request = remote_import_request(output);
    let store = SqliteReceiptStore::open(db).test_unwrap();
    let refused = |columns: &[&str], error: &str| {
        let mut request = request.clone();
        request["trust"]["required_columns"] = serde_json::json!(columns);
        let response = client
            .post(&endpoint)
            .bearer_auth(token)
            .json(&request)
            .send()
            .test_unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        let body: serde_json::Value = response.json().test_unwrap();
        assert_eq!(body, serde_json::json!({ "error": error }));
        assert!(store
            .get_federated_share_for_capability("cap-remote-federated")
            .test_unwrap()
            .is_none());
    };
    refused(
        &["decision", "identity_root"],
        &format!(
            "{REQUIRED_COLUMN_UNVERIFIED} [attest:error]: a column the trust file requires is \
             not verified for every receipt (Inspect the report to see which column and \
             receipt fell short of verified.)"
        ),
    );
    refused(
        &["settlement"],
        &format!(
            "{FEATURE_UNSUPPORTED} [attest:error]: this verifier cannot verify the settlement \
             column (Use a verifier that supports the feature, or remove it from the trust file \
             requirements.)"
        ),
    );
}
