use super::*;

pub(super) fn write_mercury_bundle_manifest(path: &Path) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&sample_mercury_bundle_manifest()).expect("bundle manifest"),
    )
    .expect("write bundle manifest");
}

fn export_signed_proof_package(prefix: &str) -> (PathBuf, Vec<PathBuf>) {
    let receipt_db_path = unique_path(&format!("{prefix}-db"), ".sqlite3");
    let output_dir = unique_path(&format!("{prefix}-export"), "");
    let bundle_manifest_path = unique_path(&format!("{prefix}-bundle"), ".json");
    let proof_package_path = unique_path(&format!("{prefix}-proof-package"), ".json");
    let issuer = Keypair::from_seed(&[58; 32]);
    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open store");
        let seq = store
            .append_chio_receipt_returning_seq(&mercury_receipt_with_ts(
                "rcpt-mercury-dup",
                "cap-mercury-dup",
                100,
                &issuer,
            ))
            .expect("append mercury receipt");
        let canonical = store
            .receipts_canonical_bytes_range(seq, seq)
            .expect("canonical bytes");
        let checkpoint = build_checkpoint(
            1,
            seq,
            seq,
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
    export_fixture_package(&receipt_db_path, &output_dir);
    write_mercury_bundle_manifest(&bundle_manifest_path);
    let proof_export = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("proof")
        .arg("export")
        .arg("--trusted-kernel-pubkey")
        .arg(issuer.public_key().to_hex())
        .arg("--input")
        .arg(&output_dir)
        .arg("--output")
        .arg(&proof_package_path)
        .arg("--bundle-manifest")
        .arg(&bundle_manifest_path)
        .output()
        .expect("run mercury proof export");
    assert!(
        proof_export.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&proof_export.stderr)
    );
    let cleanup = vec![
        receipt_db_path,
        output_dir,
        bundle_manifest_path,
        proof_package_path.clone(),
    ];
    (proof_package_path, cleanup)
}

fn first_signed_receipt(value: &serde_json::Value) -> Option<&serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => {
            if ["action", "kernel_key", "signature"]
                .iter()
                .all(|key| map.contains_key(*key))
            {
                return Some(value);
            }
            map.values().find_map(first_signed_receipt)
        }
        serde_json::Value::Array(items) => items.iter().find_map(first_signed_receipt),
        _ => None,
    }
}

fn mercury_verify_succeeds(text: &str, label: &str) -> bool {
    let path = unique_path(&format!("chio-mercury-{label}"), ".json");
    fs::write(&path, text).expect("write package variant");
    let verify = Command::new(env!("CARGO_BIN_EXE_mercury"))
        .current_dir(workspace_root())
        .arg("--json")
        .arg("verify")
        .arg("--input")
        .arg(&path)
        .output()
        .expect("run mercury verify");
    let _ = fs::remove_file(path);
    verify.status.success()
}

#[test]
fn mercury_verify_rejects_duplicate_keys_in_signed_proof_package_bytes() {
    let (proof_package_path, cleanup) = export_signed_proof_package("chio-mercury-dup");
    let package: serde_json::Value =
        serde_json::from_slice(&fs::read(&proof_package_path).expect("read proof package"))
            .expect("proof package json");
    let compact = serde_json::to_string(&package).expect("compact package");
    assert!(mercury_verify_succeeds(&compact, "dup-original"));

    let receipt = first_signed_receipt(&package).expect("package embeds a signed receipt");
    let receipt_text = serde_json::to_string(receipt).expect("compact receipt");
    assert!(compact.contains(&receipt_text));
    let parameter = receipt["action"]["parameters"]
        .as_object()
        .and_then(|parameters| parameters.keys().next())
        .expect("receipt has a parameter")
        .clone();

    let mut tampered = receipt.clone();
    tampered["action"]["parameters"][&parameter] = serde_json::json!("forged");
    let tampered_text = serde_json::to_string(&tampered).expect("tampered receipt");
    assert!(
        !mercury_verify_succeeds(
            &compact.replacen(&receipt_text, &tampered_text, 1),
            "dup-tampered"
        ),
        "the chosen receipt parameter must be covered by the receipt signature"
    );

    let anchor = r#""parameters":{"#;
    let forged_receipt =
        receipt_text.replacen(anchor, &format!(r#"{anchor}"{parameter}":"forged","#), 1);
    let nested = compact.replacen(&receipt_text, &forged_receipt, 1);
    let top_level = compact.replacen('{', r#"{"schema":"forged","#, 1);
    for (label, forged) in [("nested", nested), ("top-level", top_level)] {
        let collapsed: serde_json::Value = serde_json::from_str(&forged).expect("forged json");
        assert_eq!(collapsed, package, "{label} duplicate collapses last-wins");
        assert!(
            !mercury_verify_succeeds(&forged, &format!("dup-{label}")),
            "mercury verify accepted a {label} duplicate key"
        );
    }

    for path in cleanup {
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir_all(&path);
    }
}
