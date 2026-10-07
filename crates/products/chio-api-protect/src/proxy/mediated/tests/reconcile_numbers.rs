use super::*;
use chio_core_types::canonical::UntrustedJsonError;
use chio_core_types::error::Error as CoreError;
use chio_core_types::receipt::authoritative_spend::{
    BudgetAuthorityReceiptRef, PresentedNonceView,
};
use chio_kernel::budget_store::{BudgetHoldDispositionView, BudgetMutationKind};

async fn post_original_json(state: Arc<ProxyState>, uri: &str, body: String) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if uri == "/v1/reconcile" {
        builder = builder.header("authorization", format!("Bearer {MEDIATED_CONTROL_TOKEN}"));
    }
    let request = with_loopback_peer(builder.body(Body::from(body)).test_unwrap());
    build_app(state).oneshot(request).await.test_unwrap()
}

async fn response_json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .test_unwrap();
    serde_json::from_slice(&bytes).test_unwrap()
}

fn reconcile_json(nonce: &str, arguments: &str) -> String {
    format!(
        r#"{{"execution_nonce":{nonce},"arguments":{arguments},"realized_cost":{{"units":30,"currency":"USD"}}}}"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_original_decimal_arguments_settles_only_the_signed_hold() {
    let signer = Keypair::generate();
    let signer_pub = signer.public_key();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let issuer = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let capability =
        issue_cost_bearing_capability(&issuer, &agent, "cost-srv", "compute", 100, 300, "USD");
    let cap_id = capability.id.clone();
    let capability_json = serde_json::to_string(&capability).test_unwrap();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let original_arguments = r#"{"confidence":0.50,"invoice":"inv-decimal"}"#;
    let evaluate_json = format!(
        r#"{{"capability":{capability_json},"tool_server":"cost-srv","tool_name":"compute","request_id":"original-decimal","parameters":{original_arguments}}}"#
    );
    let response = post_original_json(Arc::clone(&state), "/v1/evaluate", evaluate_json).await;
    assert_eq!(response.status(), StatusCode::OK);
    let authorized = response_json(response).await;
    assert_eq!(authorized["status"], "reserved", "{authorized}");
    let nonce: SignedExecutionNonce =
        serde_json::from_value(authorized["execution_nonce"].clone()).test_unwrap();
    assert!(nonce.verify_signed_by(&signer_pub));
    assert_eq!(nonce.nonce.bound_to.capability_id, cap_id);
    assert_eq!(nonce.nonce.bound_to.request_id, "original-decimal");
    let hold_id = nonce.reserved_hold_id().test_unwrap();
    let nonce_json = serde_json::to_string(&nonce).test_unwrap();

    // A second open hold makes settling the wrong reservation observable.
    let (status, neighbor) = post_evaluate(
        Arc::clone(&state),
        &serde_json::json!({
            "capability": capability, "tool_server": "cost-srv", "tool_name": "compute",
            "request_id": "neighbor-decimal", "parameters": { "invoice": "inv-neighbor" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(neighbor["status"], "reserved", "{neighbor}");
    let neighbor_nonce: SignedExecutionNonce =
        serde_json::from_value(neighbor["execution_nonce"].clone()).test_unwrap();
    let neighbor_hold_id = neighbor_nonce.reserved_hold_id().test_unwrap();
    assert_ne!(hold_id, neighbor_hold_id);
    let target_before = budget.get_budget_hold(hold_id).test_unwrap().test_unwrap();
    let neighbor_before = budget
        .get_budget_hold(neighbor_hold_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(target_before.disposition, BudgetHoldDispositionView::Open);
    assert_eq!(target_before.capability_id, cap_id);
    assert_eq!(target_before.grant_index, 0);
    assert_eq!(target_before.authorized_exposure_units, 100);
    assert_eq!(target_before.remaining_exposure_units, 100);
    let usage_before = budget.get_usage(&cap_id, 0).test_unwrap().test_unwrap();
    assert_eq!(usage_before.total_cost_exposed, 200);
    assert_eq!(usage_before.total_cost_realized_spend, 0);
    let receipt_count_before = state.tool_receipt_log.lock().await.receipts.len();

    // Preserve the exact original decimal lexeme across the real HTTP routes.
    let reconcile_body = reconcile_json(&nonce_json, original_arguments);
    let response =
        post_original_json(Arc::clone(&state), "/v1/reconcile", reconcile_body.clone()).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "evaluate accepted 0.50; reconcile must accept the same original arguments"
    );
    let reconciled = response_json(response).await;
    assert_eq!(reconciled["status"], "reconciled", "{reconciled}");
    let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).test_unwrap();
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce),
        Ok(())
    );
    let lineage = BudgetAuthorityReceiptRef::from_receipt(&receipt).test_unwrap();
    assert_eq!(lineage.hold_id, hold_id);
    assert_eq!(lineage.capability_id, cap_id);
    assert_eq!(lineage.grant_index, 0);
    assert_eq!(lineage.exposed_units, 100);
    assert_eq!(lineage.realized_units, 30);
    assert_eq!(
        lineage.execution_nonce_id.as_deref(),
        Some(nonce.nonce_id())
    );
    let target_after = budget.get_budget_hold(hold_id).test_unwrap().test_unwrap();
    assert_eq!(
        target_after.disposition,
        BudgetHoldDispositionView::Reconciled
    );
    assert_eq!(target_after.remaining_exposure_units, 0);
    assert_eq!(
        budget.get_budget_hold(neighbor_hold_id).test_unwrap(),
        Some(neighbor_before.clone())
    );
    let usage_after = budget.get_usage(&cap_id, 0).test_unwrap().test_unwrap();
    assert_eq!(usage_after.total_cost_exposed, 100);
    assert_eq!(usage_after.total_cost_realized_spend, 30);
    assert_eq!(usage_after.committed_cost_units().test_unwrap(), 130);
    let events_after = budget
        .list_mutation_events(100, Some(&cap_id), Some(0))
        .test_unwrap();
    let settlements: Vec<_> = events_after
        .iter()
        .filter(|event| event.kind == BudgetMutationKind::ReconcileSpend)
        .collect();
    assert_eq!(settlements.len(), 1);
    let settlement = settlements.first().test_unwrap();
    assert_eq!(settlement.hold_id.as_deref(), Some(hold_id));
    assert_eq!(settlement.exposure_units, 100);
    assert_eq!(settlement.realized_spend_units, 30);
    assert_eq!(
        state.tool_receipt_log.lock().await.receipts.len(),
        receipt_count_before + 1
    );

    let response = post_original_json(Arc::clone(&state), "/v1/reconcile", reconcile_body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let replay = response_json(response).await;
    assert_eq!(replay["error"], "chio_reconcile_rejected");
    assert_eq!(replay["message"], "internal error: reconcile-by-nonce rejected the nonce: execution nonce has already been consumed");
    assert!(replay.get("receipt").is_none());
    assert_eq!(
        budget.get_budget_hold(hold_id).test_unwrap(),
        Some(target_after)
    );
    assert_eq!(
        budget.get_budget_hold(neighbor_hold_id).test_unwrap(),
        Some(neighbor_before)
    );
    assert_eq!(
        budget.get_usage(&cap_id, 0).test_unwrap(),
        Some(usage_after)
    );
    assert_eq!(
        budget
            .list_mutation_events(100, Some(&cap_id), Some(0))
            .test_unwrap(),
        events_after
    );
    assert_eq!(
        state.tool_receipt_log.lock().await.receipts.len(),
        receipt_count_before + 1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_rejects_original_duplicates_and_signed_nonce_aliases_before_settlement() {
    let signer = Keypair::generate();
    let signer_pub = signer.public_key();
    let agent = Keypair::generate();
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
    let issuer = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let capability =
        issue_cost_bearing_capability(&issuer, &agent, "cost-srv", "compute", 100, 300, "USD");
    let cap_id = capability.id.clone();
    let state = mediated_test_state(signer, Arc::clone(&budget), Vec::new());
    let (status, authorized) = post_evaluate(
        Arc::clone(&state),
        &serde_json::json!({
            "capability": capability, "tool_server": "cost-srv", "tool_name": "compute",
            "request_id": "strict-decimal", "parameters": { "confidence": 0.5, "invoice": "inv-strict" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(authorized["status"], "reserved", "{authorized}");
    let nonce: SignedExecutionNonce =
        serde_json::from_value(authorized["execution_nonce"].clone()).test_unwrap();
    assert!(nonce.verify_signed_by(&signer_pub));
    let hold_id = nonce.reserved_hold_id().test_unwrap();
    let nonce_json = serde_json::to_string(&nonce).test_unwrap();
    let hold_before = budget.get_budget_hold(hold_id).test_unwrap().test_unwrap();
    assert_eq!(hold_before.disposition, BudgetHoldDispositionView::Open);
    let usage_before = budget.get_usage(&cap_id, 0).test_unwrap().test_unwrap();
    assert_eq!(usage_before.total_cost_exposed, 100);
    assert_eq!(usage_before.total_cost_realized_spend, 0);
    let events_before = budget
        .list_mutation_events(100, Some(&cap_id), Some(0))
        .test_unwrap();
    let receipt_count_before = state.tool_receipt_log.lock().await.receipts.len();

    // Canonical argument spelling isolates the strict controls from the
    // ordinary unsigned decimal regression above.
    let canonical_arguments = r#"{"confidence":0.5,"invoice":"inv-strict"}"#;
    let issued_at_field = format!("\"issued_at\":{}", nonce.nonce.issued_at);
    assert_eq!(nonce_json.matches(&issued_at_field).count(), 1);
    let aliased_issued_at = format!("{}.00", nonce.nonce.issued_at);
    let aliased_nonce = nonce_json.replacen(
        &issued_at_field,
        &format!("\"issued_at\":{aliased_issued_at}"),
        1,
    );
    for (body, duplicate_key) in [
        (
            reconcile_json(
                &nonce_json,
                r#"{"confidence":0.5,"confidence":0.5,"invoice":"inv-strict"}"#,
            ),
            Some("confidence"),
        ),
        (
            format!(
                r#"{{"execution_nonce":{nonce_json},"arguments":{canonical_arguments},"arguments":{canonical_arguments},"realized_cost":{{"units":30,"currency":"USD"}}}}"#
            ),
            Some("arguments"),
        ),
        (reconcile_json(&aliased_nonce, canonical_arguments), None),
    ] {
        let response = post_original_json(Arc::clone(&state), "/v1/reconcile", body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error = response
            .extensions()
            .get::<Arc<UntrustedJsonError>>()
            .test_unwrap();
        match (duplicate_key, error.as_ref()) {
            (Some(key), UntrustedJsonError::SignedInput(CoreError::Json(source))) => {
                assert!(source.is_data());
                assert_eq!(
                    source.to_string(),
                    format!(
                        "duplicate object key: {key:?} at line {} column {}",
                        source.line(),
                        source.column()
                    )
                );
            }
            (None, UntrustedJsonError::SignedInput(CoreError::CanonicalJson(source))) => {
                assert_eq!(
                    source,
                    &format!(
                        "number token {aliased_issued_at} loses precision or changes representation"
                    )
                );
            }
            _ => panic!("unexpected original-input rejection phase: {error:?}"),
        }
        let rejected = response_json(response).await;
        assert_eq!(rejected["error"], "chio_bad_request");
        assert_eq!(
            rejected["message"],
            "urn:chio:error:attest:signed-json-invalid-input"
        );
        assert!(rejected.get("receipt").is_none());
        assert_eq!(
            budget.get_budget_hold(hold_id).test_unwrap(),
            Some(hold_before.clone())
        );
        assert_eq!(
            budget.get_usage(&cap_id, 0).test_unwrap(),
            Some(usage_before.clone())
        );
        assert_eq!(
            budget
                .list_mutation_events(100, Some(&cap_id), Some(0))
                .test_unwrap(),
            events_before
        );
        assert_eq!(
            state.tool_receipt_log.lock().await.receipts.len(),
            receipt_count_before
        );
    }

    // Every invalid input left the real nonce usable for exactly one settlement.
    let response = post_original_json(
        Arc::clone(&state),
        "/v1/reconcile",
        reconcile_json(&nonce_json, canonical_arguments),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let reconciled = response_json(response).await;
    assert_eq!(reconciled["status"], "reconciled", "{reconciled}");
    let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).test_unwrap();
    assert_eq!(
        is_authoritative_spend_receipt(&receipt, &[signer_pub], &nonce),
        Ok(())
    );
    let hold_after = budget.get_budget_hold(hold_id).test_unwrap().test_unwrap();
    assert_eq!(
        hold_after.disposition,
        BudgetHoldDispositionView::Reconciled
    );
    assert_eq!(hold_after.remaining_exposure_units, 0);
    let usage_after = budget.get_usage(&cap_id, 0).test_unwrap().test_unwrap();
    assert_eq!(usage_after.total_cost_exposed, 0);
    assert_eq!(usage_after.total_cost_realized_spend, 30);
    let events = budget
        .list_mutation_events(100, Some(&cap_id), Some(0))
        .test_unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == BudgetMutationKind::ReconcileSpend)
            .count(),
        1
    );
    assert_eq!(
        state.tool_receipt_log.lock().await.receipts.len(),
        receipt_count_before + 1
    );
}
