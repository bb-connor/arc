use chio_attest_buyer::runtime_evidence_manifest_from_json;

#[test]
fn runtime_evidence_manifest_from_json_rejects_manifest_without_artifacts() {
    let json = r#"{
        "schema": "chio.runtime.evidence-manifest.v1",
        "runId": "runtime-run:empty-manifest",
        "generatedAtUnixMs": 1766000000000,
        "workflowRunReportSha256": "1111111111111111111111111111111111111111111111111111111111111111",
        "proofRegenerationReportSha256": "2222222222222222222222222222222222222222222222222222222222222222",
        "entries": []
    }"#;

    let error = match runtime_evidence_manifest_from_json(json) {
        Ok(manifest) => panic!("empty runtime evidence manifest must be rejected: {manifest:?}"),
        Err(error) => error,
    };

    assert_eq!(error.code(), "runtime_evidence_manifest_missing_entries");
}

#[test]
fn buyer_readers_reject_original_duplicates_without_exposing_payloads() {
    let raw = r#"{"schema":"secret-sentinel","schema":"replacement"}"#;
    for result in [
        runtime_evidence_manifest_from_json(raw).map(|_| ()),
        chio_attest_buyer::buyer_attestation_packet_from_json(raw).map(|_| ()),
        chio_attest_buyer::buyer_attestation_review_package_from_json(raw).map(|_| ()),
    ] {
        let error = match result {
            Ok(_) => panic!("ambiguous import rejected"),
            Err(error) => error,
        };
        assert!(!format!("{error} {error:?}").contains("secret-sentinel"));
        assert!(std::error::Error::source(&error).is_some());
    }
}
