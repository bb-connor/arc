use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_producer_numbers_reach_evaluation_and_a_signed_receipt() {
    let state = test_state(
        vec![RouteEntry {
            pattern: "/pets".into(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".into()),
            policy: PolicyDecision::DenyByDefault,
        }],
        "http://127.0.0.1:1".into(),
    );
    for (index, number) in ["21.0", "0.0", "0.50", "1e-05", "9007199254740993"]
        .iter()
        .enumerate()
    {
        let mut request = ChioHttpRequest::new(
            format!("numeric-{index}"),
            HttpMethod::Post,
            "/pets".into(),
            "/pets".into(),
            chio_http_core::CallerIdentity::anonymous(),
        );
        request.arguments = Some(serde_json::json!({"number":"PRODUCER_NUMBER"}));
        let body = serde_json::to_string(&request)
            .test_unwrap()
            .replace("\"PRODUCER_NUMBER\"", number);
        let request = Request::builder()
            .method("POST")
            .uri("/chio/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .test_unwrap();
        let response = sidecar_evaluate_handler(State(state.clone()), request).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "producer number {number}"
        );
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .test_unwrap();
        let evaluation: EvaluateResponse = serde_json::from_slice(&bytes).test_unwrap();
        assert!(evaluation.verdict.is_denied());
        assert!(evaluation.receipt.verify_signature().test_unwrap());
    }
}
