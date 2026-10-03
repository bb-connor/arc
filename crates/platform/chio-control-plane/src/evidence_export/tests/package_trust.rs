use super::*;

#[test]
fn package_rejects_receipt_checkpoint_signer_substitution() {
    let mut bundle = sample_bundle();
    let bytes = canonical_json_bytes(&bundle.tool_receipts[0].receipt).test_unwrap();
    bundle.checkpoints[0] = build_checkpoint(1, 1, 1, &[bytes], &Keypair::generate()).test_unwrap();
    assert_ne!(
        bundle.tool_receipts[0].receipt.kernel_key,
        bundle.checkpoints[0].body.kernel_key
    );
    let receipts = verify_tool_receipts(&bundle.tool_receipts).test_unwrap();
    let checkpoints = verify_checkpoints(&bundle.checkpoints).test_unwrap();
    let error = verify_inclusion_proofs(&receipts, &checkpoints, &bundle.inclusion_proofs, 0)
        .test_unwrap_err();
    assert!(error.to_string().contains("signer"), "{error}");
}

#[test]
fn package_rejects_unsigned_manifest() {
    let directory = tempfile::tempdir().test_unwrap();
    let output = directory.path().join("package");
    let mut bundle = sample_bundle();
    bundle.query.read_boundary = Some(ReceiptReadBoundary::AdminAll);
    bundle.child_receipt_scope = EvidenceChildReceiptScope::FullQueryWindow;
    write_evidence_package(&output, bundle, None, None, None, &package_keypair()).test_unwrap();
    fs::remove_file(output.join("export-envelope.json")).test_unwrap();
    let error = load_verified_evidence_package(&output, &package_policy()).test_unwrap_err();
    assert!(error.to_string().contains("envelope"), "{error}");
}

fn fixture() -> (tempfile::TempDir, EvidenceImportPackage) {
    let directory = tempfile::tempdir().test_unwrap();
    let mut bundle = sample_bundle();
    bundle.query.read_boundary = Some(ReceiptReadBoundary::AdminAll);
    bundle.child_receipt_scope = EvidenceChildReceiptScope::FullQueryWindow;
    write_evidence_package(
        directory.path(),
        bundle,
        None,
        None,
        None,
        &package_keypair(),
    )
    .test_unwrap();
    let package = load_verified_evidence_package(directory.path(), &package_policy()).test_unwrap();
    (directory, package)
}

#[test]
fn package_rejects_fresh_key_even_when_every_signature_is_valid() {
    let (directory, _) = fixture();
    let policy =
        EvidenceVerificationPolicy::new(vec![Keypair::generate().public_key()], None).test_unwrap();
    let error = load_verified_evidence_package(directory.path(), &policy).test_unwrap_err();
    assert!(error.to_string().contains("trusted kernel key"));
}

#[test]
fn package_remote_payload_cannot_differ_from_signed_files() {
    let (_directory, mut package) = fixture();
    package.bundle.retention.oldest_live_receipt_timestamp = Some(999);
    let error = validate_import_package_data(&package, &package_policy()).test_unwrap_err();
    assert!(error.to_string().contains("payload"), "{error}");
}

#[test]
fn package_signed_manifest_cannot_omit_consumed_files() {
    let (_directory, mut package) = fixture();
    package
        .manifest
        .files
        .retain(|file| file.path != "receipts.ndjson");
    package.envelope = envelope::sign(
        &package.manifest,
        &package.bundle,
        package.transparency.as_ref(),
        None,
        &package_keypair(),
    )
    .test_unwrap();
    let error = validate_import_package_data(&package, &package_policy()).test_unwrap_err();
    assert!(error.to_string().contains("every package file"), "{error}");
}

#[test]
fn package_rejects_foreign_receipt_even_when_manifest_signer_is_trusted() {
    let (_directory, mut package) = fixture();
    package.bundle.tool_receipts[0].receipt = sample_receipt();
    package.envelope = envelope::sign(
        &package.manifest,
        &package.bundle,
        package.transparency.as_ref(),
        None,
        &package_keypair(),
    )
    .test_unwrap();
    let error = validate_import_package_data(&package, &package_policy()).test_unwrap_err();
    assert!(error.to_string().contains("trusted kernel key"), "{error}");
}

#[test]
fn package_rejects_manifest_rewrite_without_a_new_signature() {
    let (directory, mut package) = fixture();
    package.manifest.exported_at += 1;
    fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec(&package.manifest).test_unwrap(),
    )
    .test_unwrap();
    let error =
        load_verified_evidence_package(directory.path(), &package_policy()).test_unwrap_err();
    assert!(error.to_string().contains("manifest"), "{error}");
}

#[test]
fn package_accepts_explicit_rotation_keys_and_preserves_uncheckpointed_observations() {
    use chio_core::receipt::kinds::{
        BoundaryClass, ObservationOutcome, ReceiptKind, ToolOrigin, TrustLevel,
    };
    let directory = tempfile::tempdir().test_unwrap();
    let signer = Keypair::generate();
    let mut bundle = sample_bundle();
    bundle.query = EvidenceExportQuery::admin_all();
    bundle.child_receipt_scope = EvidenceChildReceiptScope::FullQueryWindow;
    let mut body = bundle.tool_receipts[0].receipt.body();
    body.decision = None;
    body.receipt_kind = ReceiptKind::AdvisoryEvaluation;
    body.boundary_class = BoundaryClass::AdvisoryOnly;
    body.observation_outcome = Some(ObservationOutcome::Observed);
    body.trust_level = TrustLevel::Advisory;
    body.tool_origin = ToolOrigin::HostExecutedUnmediated;
    bundle.tool_receipts[0].receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    bundle.checkpoints.clear();
    bundle.inclusion_proofs.clear();
    bundle.uncheckpointed_receipts = vec![chio_kernel::EvidenceUncheckpointedReceipt {
        seq: 1,
        receipt_id: bundle.tool_receipts[0].receipt.id.clone(),
    }];
    write_evidence_package(directory.path(), bundle, None, None, None, &signer).test_unwrap();
    let policy = EvidenceVerificationPolicy::new(
        vec![signer.public_key(), package_keypair().public_key()],
        None,
    )
    .test_unwrap();
    let verified = load_verified_evidence_package(directory.path(), &policy).test_unwrap();
    assert_eq!(verified.bundle.uncheckpointed_receipts.len(), 1);
    assert_eq!(verified.manifest.receipt_semantics.authorized, 0);
    assert_eq!(verified.manifest.counts.uncheckpointed_receipts, 1);
    assert!(!verified
        .manifest
        .claim_boundary
        .test_unwrap()
        .is_trust_anchored());
}

#[test]
fn package_rejects_weak_trusted_key_and_empty_trust_set() {
    let weak =
        PublicKey::from_hex("0100000000000000000000000000000000000000000000000000000000000000")
            .test_unwrap();
    let error = EvidenceVerificationPolicy::new(vec![weak], None).test_unwrap_err();
    assert!(error.to_string().contains("weak Ed25519"));
    let error = EvidenceVerificationPolicy::new(Vec::new(), None).test_unwrap_err();
    assert!(error.to_string().contains("trusted kernel keys"));
}

#[test]
fn package_envelope_wire_shape_and_domain_are_pinned() {
    let (_directory, mut package) = fixture();
    let wire = serde_json::to_value(&package.envelope).test_unwrap();
    assert_eq!(wire["body"]["schema"], "chio.evidence_export_commitment.v1");
    let fields = wire
        .as_object()
        .test_unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(fields, BTreeSet::from(["body", "signature", "signerKey"]));
    let mut body = wire["body"].clone();
    let fields = body
        .as_object()
        .test_unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fields,
        BTreeSet::from(["manifestSha256", "payloadSha256", "schema"])
    );
    body["schema"] = "chio.other_commitment.v1".into();
    package.envelope = chio_core::receipt::lineage::SignedExportEnvelope::sign(
        serde_json::from_value::<envelope::ExportCommitment>(body).test_unwrap(),
        &package_keypair(),
    )
    .test_unwrap();
    let error = validate_import_package_data(&package, &package_policy()).test_unwrap_err();
    assert!(error.to_string().contains("schema"), "{error}");
}

#[test]
fn package_rejects_duplicate_inventory_and_oversized_file_commitment() {
    let (_directory, package) = fixture();
    let mut duplicate = package.manifest.clone();
    duplicate.files.push(duplicate.files[0].clone());
    let error = package_io::verify_inventory(&duplicate).test_unwrap_err();
    assert!(error.to_string().contains("exactly once"), "{error}");

    let mut oversized = package.manifest;
    oversized.files[0].bytes = crate::integer::count(package_io::MAX_FILE_BYTES) + 1;
    let error = package_io::verify_inventory(&oversized).test_unwrap_err();
    assert!(error.to_string().contains("byte limit"), "{error}");
}

#[test]
fn package_rejects_duplicate_manifest_fields() {
    let (directory, package) = fixture();
    let mut manifest = serde_json::to_string(&package.manifest).test_unwrap();
    manifest.insert_str(1, "\"schema\":\"chio.evidence_export_manifest.v1\",");
    fs::write(directory.path().join("manifest.json"), manifest).test_unwrap();
    let error =
        load_verified_evidence_package(directory.path(), &package_policy()).test_unwrap_err();
    match error {
        CliError::SignedJson(source) => {
            assert_eq!(
                source.code(),
                "urn:chio:error:attest:signed-json-invalid-input"
            );
        }
        other => panic!("expected original signed JSON rejection, got {other:?}"),
    }
}

#[test]
fn package_reader_rejects_non_regular_and_oversized_inputs() {
    let directory = tempfile::tempdir().test_unwrap();
    fs::create_dir(directory.path().join("directory.json")).test_unwrap();
    let error = package_io::read_bytes(directory.path(), "directory.json").test_unwrap_err();
    assert!(error.to_string().contains("regular file"), "{error}");
    let file = fs::File::create(directory.path().join("large.json")).test_unwrap();
    file.set_len(crate::integer::count(package_io::MAX_FILE_BYTES) + 1)
        .test_unwrap();
    let error = package_io::read_bytes(directory.path(), "large.json").test_unwrap_err();
    assert!(error.to_string().contains("byte limit"), "{error}");
}

#[cfg(unix)]
#[test]
fn package_reader_rejects_leaf_and_parent_symlinks_and_fifo() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().test_unwrap();
    let outside = tempfile::tempdir().test_unwrap();
    fs::write(outside.path().join("file.json"), b"{}").test_unwrap();
    symlink(
        outside.path().join("file.json"),
        directory.path().join("leaf.json"),
    )
    .test_unwrap();
    symlink(outside.path(), directory.path().join("parent")).test_unwrap();
    for name in [
        "leaf.json",
        "parent/file.json",
        "../file.json",
        "/file.json",
    ] {
        match package_io::read_bytes(directory.path(), name) {
            Err(_) => {}
            Ok(bytes) => panic!("untrusted path {name} was followed: {bytes:?}"),
        }
    }
    rustix::fs::mknodat(
        rustix::fs::CWD,
        directory.path().join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .test_unwrap();
    let error = package_io::read_bytes(directory.path(), "fifo").test_unwrap_err();
    assert!(error.to_string().contains("regular file"), "{error}");
}
