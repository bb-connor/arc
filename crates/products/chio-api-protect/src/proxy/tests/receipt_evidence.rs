use super::*;

#[tokio::test]
async fn submitted_observation_verifies_without_authorizing_execution() {
    let state = test_state(Vec::new(), "http://127.0.0.1:1".into());
    let request = with_authenticated_control_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/receipts")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "job_name": "import", "namespace": "operator", "job_uid": "reported-1",
                    "outcome": "succeeded", "steps": []
                })
                .to_string(),
            ))
            .test_unwrap(),
    );
    let response = build_app(state.clone())
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let receipt = state.receipt_log.lock().await.receipts[0].clone();
    let request = Request::builder()
        .method("POST")
        .uri("/chio/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&receipt).test_unwrap()))
        .test_unwrap();
    let response = build_app(state).oneshot(request).await.test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .test_unwrap();
    let verification: VerifyReceiptResponse = serde_json::from_slice(&bytes).test_unwrap();
    assert!(
        !verification.authorized,
        "a submitted observation cannot authorize execution"
    );
    assert!(verification.signature_valid && verification.signer_trusted && verification.ok);
    assert_eq!(verification.receipt_kind, "advisory_evaluation");
    assert_eq!(verification.trust_level, "advisory");
    assert_eq!(verification.result, "observed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evidence_sink_rejects_duplicate_http_receipt_and_exports_original() {
    use chio_kernel::EvidenceExportQuery;
    let directory = tempfile::tempdir().test_unwrap();
    let database = directory.path().join("receipts.db");
    let canonical = chio_store_sqlite::SqliteReceiptStore::open(&database).test_unwrap();
    let _approval = SqliteApprovalStore::open_colocated_with_receipt_store(&database).test_unwrap();
    let state =
        test_state_with_receipt_db(Vec::new(), "http://127.0.0.1:1".into(), database.to_str());
    let receipt = build_manual_receipt(
        &state,
        "request-1".into(),
        "/denied".into(),
        HttpMethod::Post,
        "caller".into(),
        None,
        Verdict::deny("policy", "test"),
        403,
        100,
        chio_core_types::sha256_hex(b"request"),
        None,
        None,
        "test",
    )
    .test_unwrap();
    record_receipt(&state, &receipt).await.test_unwrap();
    let duplicate = record_receipt(&state, &receipt).await.test_unwrap_err();
    assert!(duplicate.to_string().contains("duplicate"));
    let bundle = canonical
        .build_evidence_export_bundle(&EvidenceExportQuery {
            read_boundary: Some(chio_kernel::ReceiptReadBoundary::AdminAll),
            ..Default::default()
        })
        .test_unwrap();
    assert_eq!(bundle.tool_receipts.len(), 1);
    let raw = rusqlite::Connection::open(&database).test_unwrap();
    assert!(raw
        .execute("UPDATE chio_tool_receipts SET raw_json = '{}'", [])
        .is_err());
    assert!(raw.execute("DELETE FROM chio_tool_receipts", []).is_err());
    assert_eq!(
        canonical
            .query_receipts(&chio_kernel::ReceiptQuery::default().local_operator_admin())
            .test_unwrap()
            .total_count,
        1
    );
    assert_eq!(
        bundle.tool_receipts[0]
            .receipt
            .metadata
            .as_ref()
            .test_unwrap()["chio_http_receipt_v1"]["id"],
        receipt.id
    );
}

#[tokio::test]
async fn native_redelivery_recognizes_identical_authenticated_retained_evidence() {
    let directory = tempfile::tempdir().test_unwrap();
    let database = directory.path().join("receipts.db");
    let archive = directory.path().join("archive.db");
    let canonical = chio_store_sqlite::SqliteReceiptStore::open(&database).test_unwrap();
    let _approval = SqliteApprovalStore::open_colocated_with_receipt_store(&database).test_unwrap();
    let state =
        test_state_with_receipt_db(Vec::new(), "http://127.0.0.1:1".into(), database.to_str());
    let receipt = build_manual_receipt(
        &state,
        "old-replay".into(),
        "/denied".into(),
        HttpMethod::Post,
        "caller".into(),
        None,
        Verdict::deny("policy", "test"),
        403,
        100,
        chio_core_types::sha256_hex(b"request"),
        None,
        None,
        "test",
    )
    .test_unwrap()
    .to_chio_receipt_with_keypair(&state.signer_keypair)
    .test_unwrap();
    record_kernel_receipt(&state, &receipt).await.test_unwrap();
    let bytes = canonical.receipts_canonical_bytes_range(1, 1).test_unwrap();
    let checkpoint = chio_kernel::checkpoint::build_checkpoint(
        1,
        1,
        1,
        &bytes
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>(),
        &state.signer_keypair,
    )
    .test_unwrap();
    canonical.store_checkpoint(&checkpoint).test_unwrap();
    canonical
        .archive_receipts_before(101, archive.to_str().test_unwrap())
        .test_unwrap();
    record_kernel_receipt(&state, &receipt).await.test_unwrap();
    assert_eq!(
        canonical
            .query_receipts(&chio_kernel::ReceiptQuery::default().local_operator_admin())
            .test_unwrap()
            .total_count,
        1
    );
    assert!(matches!(
        record_tool_receipt(&state, &receipt).await,
        Err(ProtectError::EvidenceStore(_))
    ));
    let mut altered = receipt.clone();
    altered.metadata = Some(serde_json::json!({"different": true}));
    assert!(matches!(
        record_kernel_receipt(&state, &altered).await,
        Err(ProtectError::EvidenceStore(_))
    ));
    std::fs::rename(&archive, archive.with_extension("missing")).test_unwrap();
    assert!(matches!(
        record_kernel_receipt(&state, &receipt).await,
        Err(ProtectError::EvidenceStore(_))
    ));
}
