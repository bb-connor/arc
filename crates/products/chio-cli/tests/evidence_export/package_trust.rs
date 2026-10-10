use super::*;

struct Fixture {
    _directory: tempfile::TempDir,
    db: PathBuf,
    seed: PathBuf,
    package: PathBuf,
    signer: Keypair,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().test_unwrap();
        let db = directory.path().join("receipts.sqlite3");
        let seed = directory.path().join("kernel.seed");
        let package = directory.path().join("package");
        let signer = chio_control_plane::load_or_create_authority_keypair(&seed).test_unwrap();
        let store = SqliteReceiptStore::open(&db).test_unwrap();
        for timestamp in [100, 101] {
            store
                .append_chio_receipt(&receipt_with_keypair(
                    &format!("package-trust-{timestamp}"),
                    "cap-package-trust",
                    timestamp,
                    None,
                    &signer,
                ))
                .test_unwrap();
        }
        let receipts = store.receipts_canonical_bytes_range(1, 2).test_unwrap();
        let checkpoint = build_checkpoint(
            1,
            1,
            2,
            &receipts
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &signer,
        )
        .test_unwrap();
        store.store_checkpoint(&checkpoint).test_unwrap();
        Self {
            _directory: directory,
            db,
            seed,
            package,
            signer,
        }
    }

    fn export(&self) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["--receipt-db"])
            .arg(&self.db)
            .args(["evidence", "export", "--admin-all", "--output"])
            .arg(&self.package)
            .arg("--kernel-seed-file")
            .arg(&self.seed)
            .output()
            .test_unwrap()
    }

    fn verify(&self, key: &str) -> std::process::Output {
        self.verify_with_anchor(key, None)
    }

    fn verify_with_anchor(&self, key: &str, anchor: Option<&Path>) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
        command
            .args(["--json", "evidence", "verify", "--input"])
            .arg(&self.package)
            .args(["--trusted-kernel-pubkey", key]);
        if let Some(anchor) = anchor {
            command.arg("--trusted-anchor-file").arg(anchor);
        }
        command.output().test_unwrap()
    }
}

fn require_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn package_cli_requires_trust_before_reading_input() {
    let directory = tempfile::tempdir().test_unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["evidence", "verify", "--input"])
        .arg(directory.path().join("missing"))
        .output()
        .test_unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--trusted-kernel-pubkey"));
}

#[test]
fn package_cli_requires_signing_custody_before_export_effects() {
    let fixture = Fixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("--receipt-db")
        .arg(&fixture.db)
        .args(["evidence", "export", "--admin-all", "--output"])
        .arg(&fixture.package)
        .output()
        .test_unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--kernel-seed-file"));
    assert!(!fixture.package.exists());
}

#[test]
fn package_cli_pins_signer_and_rejects_omission_with_rewritten_manifest() {
    let fixture = Fixture::new();
    require_success(&fixture.export());
    require_success(&fixture.verify(&fixture.signer.public_key().to_hex()));
    let wrong = fixture.verify(&Keypair::generate().public_key().to_hex());
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("trusted"));

    let receipts_path = fixture.package.join("receipts.ndjson");
    let receipts = fs::read_to_string(&receipts_path).test_unwrap();
    let remaining = format!("{}\n", receipts.lines().next().test_unwrap());
    fs::write(&receipts_path, &remaining).test_unwrap();
    let manifest_path = fixture.package.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_unwrap()).test_unwrap();
    manifest["counts"]["toolReceipts"] = 1.into();
    for file in manifest["files"].as_array_mut().test_unwrap() {
        if file["path"] == "receipts.ndjson" {
            file["sha256"] = sha256_hex(remaining.as_bytes()).into();
            file["bytes"] = remaining.len().into();
        }
    }
    fs::write(&manifest_path, serde_json::to_vec(&manifest).test_unwrap()).test_unwrap();
    let tampered = fixture.verify(&fixture.signer.public_key().to_hex());
    assert!(!tampered.status.success());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("manifest"));
}

#[test]
fn package_cli_requires_exact_external_anchor_binding() {
    use chio_core::receipt::checkpoint::*;
    let fixture = Fixture::new();
    let store = SqliteReceiptStore::open(&fixture.db).test_unwrap();
    let checkpoint = store.load_checkpoint_by_seq(1).test_unwrap().test_unwrap();
    let binding = CheckpointPublicationTrustAnchorBinding {
        publication_identity: CheckpointPublicationIdentity::new(
            CheckpointPublicationIdentityKind::LocalLog,
            chio_kernel::checkpoint::checkpoint_log_id(&checkpoint),
        ),
        trust_anchor_identity: CheckpointTrustAnchorIdentity::new(
            CheckpointTrustAnchorIdentityKind::OperatorRoot,
            "operator-root-1",
        ),
        trust_anchor_ref: "external-witness-1".to_owned(),
        signer_cert_ref: "kernel-certificate-1".to_owned(),
        publication_profile_version: "operator-pinned.v1".to_owned(),
    };
    store
        .record_checkpoint_publication_trust_anchor_binding(1, &binding)
        .test_unwrap();
    let anchor = fixture._directory.path().join("trusted-anchor.json");
    fs::write(&anchor, serde_json::to_vec(&binding).test_unwrap()).test_unwrap();
    require_success(&fixture.export());

    let key = fixture.signer.public_key().to_hex();
    let unanchored = fixture.verify(&key);
    require_success(&unanchored);
    let report: serde_json::Value = serde_json::from_slice(&unanchored.stdout).test_unwrap();
    assert_eq!(
        report["claimBoundary"]["publicationState"],
        "transparency_preview"
    );

    let anchored = fixture.verify_with_anchor(&key, Some(&anchor));
    require_success(&anchored);
    let report: serde_json::Value = serde_json::from_slice(&anchored.stdout).test_unwrap();
    assert_eq!(
        report["claimBoundary"]["publicationState"],
        "trust_anchored"
    );

    let mut wrong = binding;
    wrong.signer_cert_ref = "another-certificate".to_owned();
    fs::write(&anchor, serde_json::to_vec(&wrong).test_unwrap()).test_unwrap();
    let rejected = fixture.verify_with_anchor(&key, Some(&anchor));
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("anchor"));
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).test_unwrap()).test_unwrap()
}

fn read_lines(path: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .test_unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).test_unwrap())
        .collect()
}

pub(super) fn verify_remote_import_boundary(
    client: &Client,
    base_url: &str,
    token: &str,
    output: &Path,
    db: &Path,
) {
    use serde_json::json;
    let manifest = read_json(&output.join("manifest.json"));
    let package = json!({
        "envelope": read_json(&output.join("export-envelope.json")),
        "bundle": {
            "query": read_json(&output.join("query.json")),
            "toolReceipts": read_lines(&output.join("receipts.ndjson")),
            "childReceipts": read_lines(&output.join("child-receipts.ndjson")),
            "childReceiptScope": manifest["childReceiptScope"],
            "checkpoints": read_lines(&output.join("checkpoints.ndjson")),
            "capabilityLineage": read_lines(&output.join("capability-lineage.ndjson")),
            "inclusionProofs": read_lines(&output.join("inclusion-proofs.ndjson")),
            "uncheckpointedReceipts": read_lines(&output.join("uncheckpointed-receipts.ndjson")),
            "retention": read_json(&output.join("retention.json"))
        },
        "transparency": {
            "publications": read_lines(&output.join("checkpoint-publications.ndjson")),
            "witnesses": read_lines(&output.join("checkpoint-witnesses.ndjson")),
            "consistency_proofs": read_lines(&output.join("checkpoint-consistency-proofs.ndjson")),
            "equivocations": read_lines(&output.join("checkpoint-equivocations.ndjson"))
        },
        "federationPolicy": read_json(&output.join("federation-policy.json")),
        "manifest": manifest
    });
    let policy = chio_control_plane::evidence_export::EvidenceVerificationPolicy::new(
        vec![fixture_keypair().public_key()],
        None,
    )
    .test_unwrap();
    let request = json!({"package": package, "verification": policy});
    let _: chio_control_plane::evidence_export::RemoteEvidenceImportRequest =
        serde_json::from_value(request.clone()).test_unwrap();
    let endpoint = format!("{base_url}/v1/evidence/import");
    let response = client.post(&endpoint).json(&request).send().test_unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "{}",
        response.text().test_unwrap()
    );

    let response = client
        .post(&endpoint)
        .bearer_auth(token)
        .json(&json!({"package": request["package"]}))
        .send()
        .test_unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.text().test_unwrap().contains("verification"));

    let mut forged = request.clone();
    forged["package"]["bundle"]["toolReceipts"] = json!([]);
    let response = client
        .post(&endpoint)
        .bearer_auth(token)
        .json(&forged)
        .send()
        .test_unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.text().test_unwrap().contains("payload"));

    let mut wrong_trust = request.clone();
    wrong_trust["verification"] = serde_json::to_value(
        chio_control_plane::evidence_export::EvidenceVerificationPolicy::new(
            vec![Keypair::generate().public_key()],
            None,
        )
        .test_unwrap(),
    )
    .test_unwrap();
    let response = client
        .post(&endpoint)
        .bearer_auth(token)
        .json(&wrong_trust)
        .send()
        .test_unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.text().test_unwrap().contains("trusted kernel key"));

    let store = SqliteReceiptStore::open(db).test_unwrap();
    assert!(store
        .get_federated_share_for_capability("cap-remote-federated")
        .test_unwrap()
        .is_none());
    let import = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--json",
            "--control-url",
            base_url,
            "--control-token",
            token,
            "evidence",
            "import",
            "--trusted-kernel-pubkey",
            &fixture_keypair().public_key().to_hex(),
            "--input",
        ])
        .arg(output)
        .output()
        .test_unwrap();
    require_success(&import);
    let imported: serde_json::Value = serde_json::from_slice(&import.stdout).test_unwrap();
    assert_eq!(imported["issuer"], "org-alpha");
    let (share, _) = store
        .get_federated_share_for_capability("cap-remote-federated")
        .test_unwrap()
        .test_unwrap();
    assert_eq!(share.tool_receipts, 2);
    assert_eq!(
        store
            .receipts_canonical_bytes_range(1, 2)
            .test_unwrap()
            .len(),
        2
    );
}
