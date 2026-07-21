#[test]
fn sign_transport_deny_receipt_signs_final_scope_deny() {
    let authority = authority();
    let verdict = Verdict::deny_with_status(
        "request body exceeds limit",
        "chio_tower_request_body_limit_guard",
        413,
    );
    let receipt = authority
        .sign_transport_deny_receipt(TransportDenyInput {
            request_id: "req-transport-deny",
            route_pattern: "/upload",
            method: HttpMethod::Post,
            caller_identity_hash: "caller-hash",
            content_hash: None,
            verdict,
        })
        .test_unwrap();

    assert!(receipt.verify_signature().test_unwrap());
    assert!(receipt.is_denied());
    assert_eq!(receipt.response_status, 413);
    assert_eq!(receipt.request_id, "req-transport-deny");
    assert_eq!(receipt.route_pattern, "/upload");
    assert_eq!(receipt.caller_identity_hash, "caller-hash");
    assert!(receipt.capability_id.is_none());
    assert!(receipt.evidence.is_empty());
    assert_eq!(receipt.content_hash, "");
    assert_eq!(
        http_status_scope(receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
    assert!(
        metadata_string(receipt.metadata.as_ref(), CHIO_KERNEL_RECEIPT_ID_KEY).is_none(),
        "transport deny must not claim a kernel receipt id"
    );
}

#[test]
fn policy_deny_is_not_recorded_as_a_dispatch_failure() {
    // A normal policy/capability deny is an expected fail-closed decision. It is
    // tracked by the guard-verdict metrics and must NOT increment
    // chio_dispatch_failure_total, or one ordinary rejected request would page
    // the P0 fail-open/dispatch-failure alert.
    let query = HashMap::new();
    let denied = authority()
        .evaluate(HttpAuthorityInput {
            request_id: "req-deny-no-page".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();
    assert!(denied.verdict.is_denied());

    // No code path produces the "denied" outcome, so the paging counter never
    // carries a deny series regardless of how many requests are rejected.
    let mut body = String::new();
    chio_metrics_spec::runtime::families::DISPATCH_FAILURE.render(&mut body);
    assert!(
        !body.contains("outcome=\"denied\""),
        "a policy deny must not appear on the dispatch-failure paging metric: {body}"
    );

    // The deny is still observable via the guard-verdict metric.
    assert!(
        crate::metrics::guard_evaluations_total(crate::metrics::GUARD_OUTCOME_DENY) >= 1,
        "a deny must be tracked by the guard-verdict metric"
    );
}

#[test]
fn sign_transport_deny_receipt_rejects_non_deny_verdict() {
    let authority = authority();
    let err = authority
        .sign_transport_deny_receipt(TransportDenyInput {
            request_id: "req-transport-allow",
            route_pattern: "/pets",
            method: HttpMethod::Get,
            caller_identity_hash: "caller-hash",
            content_hash: Some("abc"),
            verdict: Verdict::Allow,
        })
        .test_unwrap_err();
    assert!(matches!(err, HttpAuthorityError::Kernel(_)));
    assert!(err
        .to_string()
        .contains("sign_transport_deny_receipt requires a Deny verdict"));
}
