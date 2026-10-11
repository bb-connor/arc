use super::*;

#[test]
fn rejects_uppercase_sha256_digest() {
    let mut report = valid_report();
    report.static_proof_package_sha256 = "A".repeat(64);

    let error = match validate_runtime_proof_parity_report(&report) {
        Ok(()) => panic!("uppercase sha256 digest unexpectedly verified"),
        Err(error) => error,
    };

    assert_eq!(
        error.code(),
        "runtime_proof_parity_invalid_static_package_hash"
    );
}

#[test]
fn rejects_accepted_package_hash_drift() {
    let mut report = valid_report();
    report.runtime_proof_package_sha256 = "c".repeat(64);

    let error = match validate_runtime_proof_parity_report(&report) {
        Ok(()) => panic!("accepted package hash drift unexpectedly verified"),
        Err(error) => error,
    };

    assert_eq!(
        error.code(),
        "runtime_proof_parity_accepted_package_hash_drift"
    );
}

#[test]
fn accepts_valid_runtime_proof_regeneration_artifacts() {
    let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions::default());

    match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
        Ok(()) => {}
        Err(error) => panic!("valid runtime proof regeneration artifacts failed: {error}"),
    }
}

#[test]
fn rejects_workflow_step_evidence_source_record_mismatch() {
    let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
        workflow_step_record_index: Some(1),
        ..RegenerationArtifactOptions::default()
    });

    let error =
        match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
            Ok(()) => panic!("workflow step evidence source record mismatch verified"),
            Err(error) => error,
        };

    assert_eq!(
        error.code(),
        "runtime_proof_regeneration_workflow_step_evidence_mismatch"
    );
}

#[test]
fn rejects_source_record_missing_binding_hash_field() {
    let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
        omit_source_record_hash_field: Some("toolReceiptSha256"),
        ..RegenerationArtifactOptions::default()
    });

    let error =
        match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
            Ok(()) => {
                panic!("source record missing a binding hash field unexpectedly verified")
            }
            Err(error) => error,
        };

    // The shared crate must DENY a missing/empty binding hash rather than
    // silently skip it (fail closed), matching the strict proof-room path.
    assert_eq!(
        error.code(),
        "runtime_proof_regeneration_source_record_hash_missing"
    );
}

#[test]
fn rejects_accepted_regeneration_report_failure_code() {
    let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
        proof_report_failure_code: Some("runtime_regeneration_failed"),
        ..RegenerationArtifactOptions::default()
    });

    let error =
        match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
            Ok(()) => {
                panic!("accepted regeneration report with failure code unexpectedly verified")
            }
            Err(error) => error,
        };

    assert_eq!(
        error.code(),
        "runtime_proof_regeneration_unexpected_failure_code"
    );
}

#[test]
fn rejects_accepted_workflow_report_failure_code() {
    let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
        workflow_report_failure_code: Some("runtime_workflow_failed"),
        ..RegenerationArtifactOptions::default()
    });

    let error =
        match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
            Ok(()) => {
                panic!("accepted workflow report with failure code unexpectedly verified")
            }
            Err(error) => error,
        };

    assert_eq!(error.code(), "runtime_workflow_unexpected_failure_code");
}

#[test]
fn rejects_regeneration_artifacts_with_mismatched_run_id() {
    let artifacts = runtime_regeneration_artifacts(RegenerationArtifactOptions {
        proof_input_run_id: "runtime-loopback-other",
        ..RegenerationArtifactOptions::default()
    });

    let error =
        match validate_runtime_proof_regeneration_artifacts(artifacts.as_runtime_artifacts()) {
            Ok(()) => panic!("mismatched regeneration run ids unexpectedly verified"),
            Err(error) => error,
        };

    assert_eq!(error.code(), "runtime_proof_regeneration_run_id_mismatch");
}

fn valid_report() -> RuntimeProofParityReport {
    RuntimeProofParityReport {
        schema: CHIO_RUNTIME_PROOF_PARITY_REPORT_SCHEMA.to_string(),
        run_id: "runtime-proof-parity-valid".to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: 1_800_000_000_000,
        static_proof_package_sha256: "a".repeat(64),
        runtime_proof_package_sha256: "a".repeat(64),
        static_verifier_report_sha256: "b".repeat(64),
        runtime_verifier_report_sha256: "b".repeat(64),
        compared_fields: vec!["verified_claims".to_string()],
        mismatches: Vec::new(),
    }
}

#[derive(Clone, Copy)]
struct RegenerationArtifactOptions<'a> {
    proof_report_run_id: &'a str,
    proof_input_run_id: &'a str,
    manifest_run_id: &'a str,
    workflow_report_run_id: &'a str,
    proof_report_failure_code: Option<&'a str>,
    workflow_report_failure_code: Option<&'a str>,
    workflow_step_record_index: Option<u64>,
    omit_source_record_hash_field: Option<&'a str>,
}

impl Default for RegenerationArtifactOptions<'_> {
    fn default() -> Self {
        Self {
            proof_report_run_id: "runtime-loopback-1",
            proof_input_run_id: "runtime-loopback-1",
            manifest_run_id: "runtime-loopback-1",
            workflow_report_run_id: "runtime-loopback-1",
            proof_report_failure_code: None,
            workflow_report_failure_code: None,
            workflow_step_record_index: Some(0),
            omit_source_record_hash_field: None,
        }
    }
}

struct TestRegenerationArtifacts {
    proof_regeneration_report: Vec<u8>,
    proof_regeneration_input: Vec<u8>,
    evidence_manifest: Vec<u8>,
    workflow_run_report: Vec<u8>,
    proof_package: Vec<u8>,
    verifier_report: Vec<u8>,
    workflow_receipt: Vec<u8>,
}

impl TestRegenerationArtifacts {
    fn as_runtime_artifacts(&self) -> RuntimeProofRegenerationArtifacts<'_> {
        RuntimeProofRegenerationArtifacts {
            proof_regeneration_report: &self.proof_regeneration_report,
            proof_regeneration_input: &self.proof_regeneration_input,
            evidence_manifest: &self.evidence_manifest,
            workflow_run_report: &self.workflow_run_report,
            proof_package: &self.proof_package,
            verifier_report: &self.verifier_report,
            workflow_receipt: &self.workflow_receipt,
        }
    }
}

fn runtime_regeneration_artifacts(
    options: RegenerationArtifactOptions<'_>,
) -> TestRegenerationArtifacts {
    let proof_package = serde_json::json!({
        "schema": "test.runtime-proof-package.v1",
        "id": "runtime-proof-package-1"
    });
    let verifier_report = serde_json::json!({
        "schema": "test.runtime-verifier-report.v1",
        "verdict": "verified"
    });
    let workflow_receipt = serde_json::json!({
        "schema": "test.runtime-workflow-receipt.v1",
        "receiptId": "runtime-workflow-receipt-1"
    });
    let proof_package_bytes = json_bytes(&proof_package);
    let verifier_report_bytes = json_bytes(&verifier_report);
    let workflow_receipt_bytes = json_bytes(&workflow_receipt);
    let proof_package_sha256 = test_canonical_value_sha256(&proof_package);
    let verifier_report_sha256 = test_canonical_value_sha256(&verifier_report);
    let workflow_receipt_sha256 = test_canonical_value_sha256(&workflow_receipt);
    let mut source_record = serde_json::json!({
        "stepIndex": 0,
        "admissionReportSha256": "1".repeat(64),
        "toolReceiptSha256": "2".repeat(64),
        "bilateralDsseSha256": "3".repeat(64),
        "workflowStepSha256": "4".repeat(64)
    });
    if let Some(field) = options.omit_source_record_hash_field {
        if let Some(object) = source_record.as_object_mut() {
            object.remove(field);
        }
    }
    let mut proof_report = serde_json::json!({
        "schema": CHIO_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA,
        "runId": options.proof_report_run_id,
        "accepted": true,
        "proofPackageSha256": proof_package_sha256,
        "verifierReportSha256": verifier_report_sha256,
        "workflowReceiptSha256": workflow_receipt_sha256,
        "sourceRecords": [source_record.clone()]
    });
    if let Some(failure_code) = options.proof_report_failure_code {
        proof_report["failureCode"] = Value::String(failure_code.to_string());
    }
    let proof_report_bytes = json_bytes(&proof_report);
    let proof_report_sha256 = test_canonical_value_sha256(&proof_report);
    let mut workflow_report = serde_json::json!({
        "schema": CHIO_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA,
        "runId": options.workflow_report_run_id,
        "accepted": true,
        "proofRegenerationReportSha256": proof_report_sha256
    });
    if let Some(step_index) = options.workflow_step_record_index {
        workflow_report["stepEvidence"] = serde_json::json!([{
            "stepIndex": step_index,
            "admissionReportSha256": "1".repeat(64),
            "toolReceiptSha256": "2".repeat(64),
            "bilateralDsseSha256": "3".repeat(64),
            "workflowStepSha256": "4".repeat(64)
        }]);
    }
    if let Some(failure_code) = options.workflow_report_failure_code {
        workflow_report["failureCode"] = Value::String(failure_code.to_string());
    }
    let workflow_report_bytes = json_bytes(&workflow_report);
    let workflow_report_sha256 = test_canonical_value_sha256(&workflow_report);
    let manifest = serde_json::json!({
        "schema": CHIO_RUNTIME_EVIDENCE_MANIFEST_SCHEMA,
        "runId": options.manifest_run_id,
        "workflowRunReportSha256": workflow_report_sha256,
        "proofRegenerationReportSha256": proof_report_sha256,
        "entries": [
            manifest_entry("proof_package", "runtime-proof-package.json", &proof_package_bytes),
            manifest_entry("verifier_report", "runtime-verifier-report.json", &verifier_report_bytes),
            manifest_entry("workflow_receipt", "runtime-workflow-receipt.json", &workflow_receipt_bytes),
            manifest_entry("proof_regeneration_report", "proof-regeneration-report.json", &proof_report_bytes),
            manifest_entry("runtime_run_report", "runtime-workflow-run-report.json", &workflow_report_bytes)
        ]
    });
    let evidence_manifest = json_bytes(&manifest);
    let manifest_sha256 = test_canonical_value_sha256(&manifest);
    let proof_input = serde_json::json!({
        "schema": CHIO_RUNTIME_PROOF_REGENERATION_INPUT_SCHEMA,
        "runId": options.proof_input_run_id,
        "evidenceManifestSha256": manifest_sha256,
        "workflowRunReportSha256": workflow_report_sha256,
        "sourceRecords": [source_record]
    });

    TestRegenerationArtifacts {
        proof_regeneration_report: proof_report_bytes,
        proof_regeneration_input: json_bytes(&proof_input),
        evidence_manifest,
        workflow_run_report: workflow_report_bytes,
        proof_package: proof_package_bytes,
        verifier_report: verifier_report_bytes,
        workflow_receipt: workflow_receipt_bytes,
    }
}

fn manifest_entry(role: &str, path: &str, bytes: &[u8]) -> Value {
    serde_json::json!({
        "role": role,
        "path": path,
        "sha256": chio_core_types::crypto::sha256_hex(bytes),
        "byteCount": bytes.len()
    })
}

fn json_bytes(value: &Value) -> Vec<u8> {
    match serde_json::to_vec(value) {
        Ok(bytes) => bytes,
        Err(error) => panic!("test JSON serialization failed: {error}"),
    }
}

fn test_canonical_value_sha256(value: &Value) -> String {
    match canonical_value_sha256(value) {
        Ok(hash) => hash,
        Err(error) => panic!("test canonical hash failed: {error}"),
    }
}
