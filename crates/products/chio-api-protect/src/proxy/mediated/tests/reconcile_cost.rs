use super::*;

const ARGUMENTS: &str = r#"{"invoice":"inv-cost"}"#;
const CANONICAL_COST: &str = r#"{"units":30,"currency":"USD"}"#;

struct CostReportFixture {
    state: Arc<ProxyState>,
    budget: Arc<dyn BudgetStore>,
    nonce: SignedExecutionNonce,
    signer_pub: PublicKey,
}

async fn reserve_cost_report() -> CostReportFixture {
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
            "request_id": "cost-report", "parameters": { "invoice": "inv-cost" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(authorized["status"], "reserved", "{authorized}");
    let nonce: SignedExecutionNonce =
        serde_json::from_value(authorized["execution_nonce"].clone()).test_unwrap();
    assert!(nonce.verify_signed_by(&signer_pub));
    assert_eq!(nonce.nonce.bound_to.capability_id, cap_id);
    CostReportFixture {
        state,
        budget,
        nonce,
        signer_pub,
    }
}

fn cost_body(nonce: &str, arguments: &str, cost: &str) -> String {
    format!(r#"{{"execution_nonce":{nonce},"arguments":{arguments},"realized_cost":{cost}}}"#)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_accepts_original_decimal_breakdown_and_settles_the_signed_hold() {
    for (units, expected_spend) in [("30", 30), ("18446744073709551615", 100)] {
        let fixture = reserve_cost_report().await;
        let cap_id = &fixture.nonce.nonce.bound_to.capability_id;
        let hold_id = fixture.nonce.reserved_hold_id().test_unwrap();
        let hold_before = fixture
            .budget
            .get_budget_hold(hold_id)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(hold_before.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(hold_before.authorized_exposure_units, 100);
        let receipt_count = fixture.state.tool_receipt_log.lock().await.receipts.len();
        let nonce_json = serde_json::to_string(&fixture.nonce).test_unwrap();
        let cost = format!(
            r#"{{"units":{units},"currency":"USD","breakdown":{{"input_rate":1e-05,"cache_ratio":0.50}}}}"#
        );
        let body = cost_body(&nonce_json, ARGUMENTS, &cost);
        let response =
            post_original_json(Arc::clone(&fixture.state), "/v1/reconcile", body.clone()).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "unsigned breakdown accepts original 1e-05 and 0.50, units={units}"
        );
        let reconciled = response_json(response).await;
        assert_eq!(reconciled["status"], "reconciled", "{reconciled}");
        let receipt: ChioReceipt =
            serde_json::from_value(reconciled["receipt"].clone()).test_unwrap();
        assert_eq!(
            is_authoritative_spend_receipt(
                &receipt,
                std::slice::from_ref(&fixture.signer_pub),
                &fixture.nonce
            ),
            Ok(())
        );
        let financial = receipt.financial_metadata().test_unwrap();
        assert_eq!(financial.cost_charged, expected_spend);
        assert_eq!(financial.currency, "USD");
        assert_eq!(
            financial.cost_breakdown,
            Some(serde_json::json!({"input_rate": 0.00001, "cache_ratio": 0.5}))
        );
        let lineage = BudgetAuthorityReceiptRef::from_receipt(&receipt).test_unwrap();
        assert_eq!(lineage.hold_id, hold_id);
        assert_eq!(lineage.capability_id, *cap_id);
        assert_eq!(lineage.exposed_units, 100);
        assert_eq!(lineage.realized_units, expected_spend);
        assert_eq!(
            lineage.execution_nonce_id.as_deref(),
            Some(fixture.nonce.nonce_id())
        );
        let hold_after = fixture
            .budget
            .get_budget_hold(hold_id)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(
            hold_after.disposition,
            BudgetHoldDispositionView::Reconciled
        );
        assert_eq!(hold_after.remaining_exposure_units, 0);
        let usage_after = fixture
            .budget
            .get_usage(cap_id, 0)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(usage_after.total_cost_exposed, 0);
        assert_eq!(usage_after.total_cost_realized_spend, expected_spend);
        let events_after = fixture
            .budget
            .list_mutation_events(100, Some(cap_id), Some(0))
            .test_unwrap();
        let settlements: Vec<_> = events_after
            .iter()
            .filter(|event| event.kind == BudgetMutationKind::ReconcileSpend)
            .collect();
        assert_eq!(settlements.len(), 1);
        let settlement = settlements.first().test_unwrap();
        assert_eq!(settlement.hold_id.as_deref(), Some(hold_id));
        assert_eq!(settlement.realized_spend_units, expected_spend);
        assert_eq!(
            fixture.state.tool_receipt_log.lock().await.receipts.len(),
            receipt_count + 1
        );

        let response = post_original_json(Arc::clone(&fixture.state), "/v1/reconcile", body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let replay = response_json(response).await;
        assert_eq!(replay["error"], "chio_reconcile_rejected");
        assert_eq!(replay["message"], "internal error: reconcile-by-nonce rejected the nonce: execution nonce has already been consumed");
        assert!(replay.get("receipt").is_none());
        assert_eq!(
            fixture.budget.get_budget_hold(hold_id).test_unwrap(),
            Some(hold_after)
        );
        assert_eq!(
            fixture.budget.get_usage(cap_id, 0).test_unwrap(),
            Some(usage_after)
        );
        assert_eq!(
            fixture
                .budget
                .list_mutation_events(100, Some(cap_id), Some(0))
                .test_unwrap(),
            events_after
        );
        assert_eq!(
            fixture.state.tool_receipt_log.lock().await.receipts.len(),
            receipt_count + 1
        );
    }
}

enum Rejection<'a> {
    Shape(&'a str),
    Duplicate(&'a str),
    SignedNumber,
    Kernel(&'a str),
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_cost_document_validation_preserves_authority_and_budget() {
    let fixture = reserve_cost_report().await;
    let cap_id = &fixture.nonce.nonce.bound_to.capability_id;
    let hold_id = fixture.nonce.reserved_hold_id().test_unwrap();
    let nonce_json = serde_json::to_string(&fixture.nonce).test_unwrap();
    let hold_before = fixture
        .budget
        .get_budget_hold(hold_id)
        .test_unwrap()
        .test_unwrap();
    let usage_before = fixture
        .budget
        .get_usage(cap_id, 0)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(usage_before.total_cost_exposed, 100);
    assert_eq!(usage_before.total_cost_realized_spend, 0);
    let events_before = fixture
        .budget
        .list_mutation_events(100, Some(cap_id), Some(0))
        .test_unwrap();
    let receipt_count = fixture.state.tool_receipt_log.lock().await.receipts.len();
    let issued_at_field = format!("\"issued_at\":{}", fixture.nonce.nonce.issued_at);
    assert_eq!(nonce_json.matches(&issued_at_field).count(), 1);
    let aliased_issued_at = format!("{}.00", fixture.nonce.nonce.issued_at);
    let aliased_nonce = nonce_json.replacen(
        &issued_at_field,
        &format!("\"issued_at\":{aliased_issued_at}"),
        1,
    );
    let mut forged_nonce = fixture.nonce.clone();
    forged_nonce.nonce.nonce_id.push('x');
    let forged_nonce_json = serde_json::to_string(&forged_nonce).test_unwrap();
    for (body, rejection) in [
        (cost_body(&nonce_json, ARGUMENTS, r#"{"units":0.50,"currency":"USD"}"#), Rejection::Shape("invalid type: floating point `0.5`, expected u64")),
        (cost_body(&nonce_json, ARGUMENTS, r#"{"units":30,"currency":1}"#), Rejection::Shape("invalid type: integer `1`, expected a string")),
        (cost_body(&nonce_json, ARGUMENTS, r#"{"units":30,"currency":"EUR"}"#), Rejection::Kernel("internal error: reconcile-by-nonce realized currency `EUR` does not match the reserved grant currency `USD`")),
        (cost_body(&nonce_json, ARGUMENTS, r#"{"units":30,"currency":"USD","breakdown":{"cache_ratio":0.5,"cache_ratio":0.5}}"#), Rejection::Duplicate("cache_ratio")),
        (cost_body(&nonce_json, ARGUMENTS, r#"{"units":30,"units":30,"currency":"USD"}"#), Rejection::Duplicate("units")),
        (format!(r#"{{"execution_nonce":{nonce_json},"arguments":{ARGUMENTS},"realized_cost":{CANONICAL_COST},"realized_cost":{CANONICAL_COST}}}"#), Rejection::Duplicate("realized_cost")),
        (cost_body(&aliased_nonce, ARGUMENTS, CANONICAL_COST), Rejection::SignedNumber),
        (cost_body(&forged_nonce_json, ARGUMENTS, CANONICAL_COST), Rejection::Kernel("internal error: reconcile-by-nonce rejected the nonce: execution nonce signature is invalid")),
        (cost_body(&nonce_json, r#"{"invoice":"replaced"}"#, CANONICAL_COST), Rejection::Kernel("internal error: reconcile-by-nonce arguments do not match the nonce parameter binding")),
    ] {
        let response = post_original_json(Arc::clone(&fixture.state), "/v1/reconcile", body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let diagnostic = response.extensions().get::<Arc<UntrustedJsonError>>();
        let (expected_error, expected_message) = match rejection {
            Rejection::Shape(message) => {
                let UntrustedJsonError::Decode(source) = diagnostic.test_unwrap().as_ref() else { panic!("cost shape rejected at wrong phase"); };
                assert!(source.is_data());
                assert_eq!(source.to_string(), message);
                ("chio_bad_request", "urn:chio:error:attest:signed-json-invalid-shape")
            }
            Rejection::Duplicate(key) => {
                let UntrustedJsonError::SignedInput(CoreError::Json(source)) = diagnostic.test_unwrap().as_ref() else { panic!("cost duplicate rejected at wrong phase"); };
                assert!(source.is_data());
                assert_eq!(source.to_string(), format!("duplicate object key: {key:?} at line {} column {}", source.line(), source.column()));
                ("chio_bad_request", "urn:chio:error:attest:signed-json-invalid-input")
            }
            Rejection::SignedNumber => {
                let UntrustedJsonError::SignedInput(CoreError::CanonicalJson(source)) = diagnostic.test_unwrap().as_ref() else { panic!("nonce alias rejected at wrong phase"); };
                assert_eq!(source, &format!("number token {aliased_issued_at} loses precision or changes representation"));
                ("chio_bad_request", "urn:chio:error:attest:signed-json-invalid-input")
            }
            Rejection::Kernel(message) => {
                assert!(diagnostic.is_none());
                ("chio_reconcile_rejected", message)
            }
        };
        let rejected = response_json(response).await;
        assert_eq!(rejected["error"], expected_error);
        assert_eq!(rejected["message"], expected_message);
        assert!(rejected.get("receipt").is_none());
        assert_eq!(fixture.budget.get_budget_hold(hold_id).test_unwrap(), Some(hold_before.clone()));
        assert_eq!(fixture.budget.get_usage(cap_id, 0).test_unwrap(), Some(usage_before.clone()));
        assert_eq!(fixture.budget.list_mutation_events(100, Some(cap_id), Some(0)).test_unwrap(), events_before);
        assert_eq!(fixture.state.tool_receipt_log.lock().await.receipts.len(), receipt_count);
    }

    // A valid report must still settle the same nonce after all rejections.
    let response = post_original_json(
        Arc::clone(&fixture.state),
        "/v1/reconcile",
        cost_body(&nonce_json, ARGUMENTS, CANONICAL_COST),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let reconciled = response_json(response).await;
    assert_eq!(reconciled["status"], "reconciled", "{reconciled}");
    let receipt: ChioReceipt = serde_json::from_value(reconciled["receipt"].clone()).test_unwrap();
    assert_eq!(
        is_authoritative_spend_receipt(
            &receipt,
            std::slice::from_ref(&fixture.signer_pub),
            &fixture.nonce
        ),
        Ok(())
    );
    let hold_after = fixture
        .budget
        .get_budget_hold(hold_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        hold_after.disposition,
        BudgetHoldDispositionView::Reconciled
    );
    assert_eq!(hold_after.remaining_exposure_units, 0);
    let usage_after = fixture
        .budget
        .get_usage(cap_id, 0)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(usage_after.total_cost_exposed, 0);
    assert_eq!(usage_after.total_cost_realized_spend, 30);
    let events = fixture
        .budget
        .list_mutation_events(100, Some(cap_id), Some(0))
        .test_unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == BudgetMutationKind::ReconcileSpend)
            .count(),
        1
    );
    assert_eq!(
        fixture.state.tool_receipt_log.lock().await.receipts.len(),
        receipt_count + 1
    );
}
