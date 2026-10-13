use super::*;

const ARGUMENTS: &str = r#"{"invoice":"inv-cost"}"#;

struct CostReportFixture {
    _directory: tempfile::TempDir,
    state: Arc<ProxyState>,
    budget: Arc<dyn BudgetStore>,
    nonce: SignedExecutionNonce,
    hold_id: String,
    signer_pub: PublicKey,
    caller: CallerExecutorFixture,
}

async fn reserve_cost_report() -> CostReportFixture {
    let signer = Keypair::generate();
    let signer_pub = signer.public_key();
    let agent = Keypair::generate();
    let directory = tempfile::tempdir().test_unwrap();
    let durable = durable_admission_stores(directory.path());
    let budget = Arc::clone(&durable.budget_store);
    let issuer = issuing_kernel(&signer, Arc::clone(&budget), &[]);
    let capability =
        issue_cost_bearing_capability(&issuer, &agent, "cost-srv", "compute", 100, 300, "USD");
    let cap_id = capability.id.clone();
    let state = mediated_test_state(signer, durable, Vec::new());
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
    let hold_id = authorized["receipt"]["metadata"]["budget_authority"]["hold_id"]
        .as_str()
        .test_unwrap()
        .to_owned();
    CostReportFixture {
        _directory: directory,
        state,
        budget,
        nonce,
        hold_id,
        signer_pub,
        caller: CallerExecutorFixture::new(),
    }
}

fn replace_report_fragment(body: &serde_json::Value, original: &str, replacement: &str) -> String {
    let report = serde_json::to_string(&body["report"]).test_unwrap();
    assert_eq!(report.matches(original).count(), 1);
    let report = report.replacen(original, replacement, 1);
    let authorization = &body["authorization"];
    format!(
        r#"{{"protocol":"chio.caller-delivery.v1","authorization":{authorization},"report":{report}}}"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_cost_reports_capture_authorized_debit_and_replay_receipts() {
    for (units, currency, pricing_failure) in [
        (100, "USD", None),
        ((1_u64 << 53) - 1, "USD", Some("authorization_exceeded")),
        (100, "EUR", Some("conversion_unavailable")),
    ] {
        let fixture = reserve_cost_report().await;
        let cap_id = &fixture.nonce.nonce.bound_to.capability_id;
        let hold_id = fixture.hold_id.as_str();
        let hold_before = fixture
            .budget
            .get_budget_hold(hold_id)
            .test_unwrap()
            .test_unwrap();
        assert_eq!(hold_before.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(hold_before.authorized_exposure_units, 100);
        let receipt_count = fixture.state.tool_receipt_log.lock().await.receipts.len();
        let breakdown = serde_json::json!({"input_rate": 0.00001, "cache_ratio": 0.5});
        let body = fixture
            .caller
            .report_request(
                Arc::clone(&fixture.state),
                &serde_json::to_value(&fixture.nonce).test_unwrap(),
                &serde_json::from_str(ARGUMENTS).test_unwrap(),
                ToolInvocationCost {
                    units,
                    currency: currency.to_owned(),
                    breakdown: Some(breakdown.clone()),
                },
            )
            .await;
        let (status, reconciled) = post_caller_report(Arc::clone(&fixture.state), &body).await;
        assert_eq!(status, StatusCode::OK, "{reconciled}");
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
        assert_eq!(financial.cost_charged, 100);
        assert_eq!(financial.currency, "USD");
        let payment = &financial.cost_breakdown.as_ref().test_unwrap()["payment"];
        assert_eq!(payment["preauthorized_units"], 100);
        assert_eq!(payment["recorded_units"], 100);
        assert_eq!(payment["budget_exposure_units"], 100);
        assert_eq!(
            payment["reported_cost"],
            serde_json::json!({"units": units, "currency": currency})
        );
        assert_eq!(
            payment["pricing_failure"],
            serde_json::json!(pricing_failure)
        );
        assert_eq!(
            reconciled["receipt"]["metadata"]["financial"]["settlement_status"],
            if pricing_failure.is_some() {
                "failed"
            } else {
                "settled"
            }
        );
        assert_eq!(reconciled["output"]["cost_breakdown"], breakdown);
        let lineage = BudgetAuthorityReceiptRef::from_receipt(&receipt).test_unwrap();
        assert_eq!(lineage.hold_id, hold_id);
        assert_eq!(lineage.capability_id, *cap_id);
        assert_eq!(lineage.exposed_units, 100);
        assert_eq!(lineage.realized_units, 100);
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
        assert_eq!(usage_after.total_cost_realized_spend, 100);
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
        assert_eq!(settlement.realized_spend_units, 100);
        assert_eq!(
            fixture.state.tool_receipt_log.lock().await.receipts.len(),
            receipt_count
        );

        let (status, replay) = post_caller_report(Arc::clone(&fixture.state), &body).await;
        assert_eq!(status, StatusCode::OK, "{replay}");
        assert_eq!(replay, reconciled);
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
            receipt_count
        );
    }
}

enum Rejection<'a> {
    Shape(&'a str),
    Duplicate(&'a str),
    SignedNumber(&'a str),
    Authentication,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_cost_report_validation_preserves_authority_and_budget() {
    let fixture = reserve_cost_report().await;
    let cap_id = &fixture.nonce.nonce.bound_to.capability_id;
    let hold_id = fixture.hold_id.as_str();
    let body = fixture
        .caller
        .report_request(
            Arc::clone(&fixture.state),
            &serde_json::to_value(&fixture.nonce).test_unwrap(),
            &serde_json::from_str(ARGUMENTS).test_unwrap(),
            ToolInvocationCost {
                units: 100,
                currency: "USD".to_owned(),
                breakdown: Some(serde_json::json!({"input_rate": 0.00001, "cache_ratio": 0.5})),
            },
        )
        .await;
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
    let completed_at = body["report"]["report"]["completed_at_unix_ms"]
        .as_u64()
        .test_unwrap();
    let completed_at_field = format!("\"completed_at_unix_ms\":{completed_at}");
    let aliased_completed_at = format!("{completed_at}.00");
    let realized_cost = format!(
        "\"realized_cost\":{}",
        body["report"]["report"]["realized_cost"]
    );
    for (rejected_body, rejection) in [
        (
            replace_report_fragment(&body, r#""units":100"#, r#""units":0.5"#),
            Rejection::Shape("invalid type: floating point `0.5`, expected u64"),
        ),
        (
            replace_report_fragment(&body, r#""currency":"USD""#, r#""currency":1"#),
            Rejection::Shape("invalid type: integer `1`, expected a string"),
        ),
        (
            replace_report_fragment(&body, r#""units":100"#, r#""units":100.00"#),
            Rejection::SignedNumber("100.00"),
        ),
        (
            replace_report_fragment(&body, r#""cache_ratio":0.5"#, r#""cache_ratio":0.50"#),
            Rejection::SignedNumber("0.50"),
        ),
        (
            replace_report_fragment(&body, r#""input_rate":0.00001"#, r#""input_rate":1e-05"#),
            Rejection::SignedNumber("1e-05"),
        ),
        (
            replace_report_fragment(
                &body,
                &completed_at_field,
                &format!("\"completed_at_unix_ms\":{aliased_completed_at}"),
            ),
            Rejection::SignedNumber(&aliased_completed_at),
        ),
        (
            replace_report_fragment(
                &body,
                r#""cache_ratio":0.5"#,
                r#""cache_ratio":0.5,"cache_ratio":0.5"#,
            ),
            Rejection::Duplicate("cache_ratio"),
        ),
        (
            replace_report_fragment(&body, r#""units":100"#, r#""units":100,"units":100"#),
            Rejection::Duplicate("units"),
        ),
        (
            replace_report_fragment(
                &body,
                &realized_cost,
                &format!("{realized_cost},{realized_cost}"),
            ),
            Rejection::Duplicate("realized_cost"),
        ),
        (
            replace_report_fragment(&body, r#""currency":"USD""#, r#""currency":"EUR""#),
            Rejection::Authentication,
        ),
        (
            replace_report_fragment(&body, r#""units":100"#, r#""units":101"#),
            Rejection::Authentication,
        ),
        (
            replace_report_fragment(&body, r#""units":100"#, r#""units":18446744073709551615"#),
            Rejection::Authentication,
        ),
        (
            replace_report_fragment(&body, r#""returned":true"#, r#""returned":false"#),
            Rejection::Authentication,
        ),
    ] {
        let response = post_original_json(
            Arc::clone(&fixture.state),
            "/v1/caller/report",
            rejected_body,
        )
        .await;
        let expected_status = match rejection {
            Rejection::Authentication => StatusCode::CONFLICT,
            _ => StatusCode::BAD_REQUEST,
        };
        assert_eq!(response.status(), expected_status);
        let diagnostic = response.extensions().get::<Arc<UntrustedJsonError>>();
        let (expected_error, expected_message) = match rejection {
            Rejection::Shape(message) => {
                let UntrustedJsonError::Decode(source) = diagnostic.test_unwrap().as_ref() else {
                    panic!("cost shape rejected at wrong phase");
                };
                assert!(source.is_data());
                assert_eq!(source.to_string(), message);
                (
                    "chio_bad_request",
                    "urn:chio:error:attest:signed-json-invalid-shape",
                )
            }
            Rejection::Duplicate(key) => {
                let UntrustedJsonError::SignedInput(CoreError::CanonicalJson(source)) =
                    diagnostic.test_unwrap().as_ref()
                else {
                    panic!("cost duplicate rejected at wrong phase");
                };
                let (message, _) = source.rsplit_once(" at line ").test_unwrap();
                assert_eq!(message, format!("duplicate object key: {key:?}"));
                (
                    "chio_bad_request",
                    "urn:chio:error:attest:signed-json-invalid-input",
                )
            }
            Rejection::SignedNumber(token) => {
                let UntrustedJsonError::SignedInput(CoreError::CanonicalJson(source)) =
                    diagnostic.test_unwrap().as_ref()
                else {
                    panic!("signed number alias rejected at wrong phase");
                };
                assert_eq!(
                    source,
                    &format!("number token {token} loses precision or changes representation")
                );
                (
                    "chio_bad_request",
                    "urn:chio:error:attest:signed-json-invalid-input",
                )
            }
            Rejection::Authentication => {
                assert!(diagnostic.is_none());
                (
                    "chio_caller_delivery_rejected",
                    "original committed caller delivery could not be authenticated or finalized",
                )
            }
        };
        let rejected = response_json(response).await;
        assert_eq!(rejected["error"], expected_error);
        assert_eq!(rejected["message"], expected_message);
        assert!(rejected.get("receipt").is_none());
        assert_eq!(
            fixture.budget.get_budget_hold(hold_id).test_unwrap(),
            Some(hold_before.clone())
        );
        assert_eq!(
            fixture.budget.get_usage(cap_id, 0).test_unwrap(),
            Some(usage_before.clone())
        );
        assert_eq!(
            fixture
                .budget
                .list_mutation_events(100, Some(cap_id), Some(0))
                .test_unwrap(),
            events_before
        );
        assert_eq!(
            fixture.state.tool_receipt_log.lock().await.receipts.len(),
            receipt_count
        );
    }

    let (status, reconciled) = post_caller_report(Arc::clone(&fixture.state), &body).await;
    assert_eq!(status, StatusCode::OK, "{reconciled}");
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
    assert_eq!(usage_after.total_cost_realized_spend, 100);
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
        receipt_count
    );
}
