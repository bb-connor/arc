#[test]
fn expired_request_and_approval_mode_mismatch_fail_before_commit() {
    let harness = Harness::new();
    let expired_plan = plan(
        harness.now_unix_ms,
        &harness.identity,
        ResponseApprovalRequirement::Automatic,
        true,
    );
    let expired = raw_request(
        expired_plan,
        harness.identity.clone(),
        ActiveResponseExecutionApproval::Automatic,
    );
    assert!(matches!(
        require_error(harness.executor.execute_source(&expired)),
        ActiveResponseExecutorError::RejectedBeforeCommit(_)
    ));

    let mut wrong_automatic = harness.automatic_request();
    wrong_automatic.approval = ActiveResponseExecutionApproval::Governed {
        admission_operation_id: "admission-operation-42".to_string(),
        admission_operation_version: 3,
        approval_set_hash: digest_hex(&digest(44)),
    };
    assert!(matches!(
        require_error(harness.executor.execute_source(&wrong_automatic)),
        ActiveResponseExecutorError::RejectedBeforeCommit(_)
    ));

    let mut wrong_governed = harness.governed_request();
    wrong_governed.approval = ActiveResponseExecutionApproval::Automatic;
    assert!(matches!(
        require_error(harness.executor.execute_source(&wrong_governed)),
        ActiveResponseExecutorError::RejectedBeforeCommit(_)
    ));
}

#[test]
fn malformed_hash_record_and_authority_mismatch_fail_closed() {
    let harness = Harness::new();
    let mut zero_dispatch = harness.automatic_request();
    zero_dispatch.dispatch_id =
        record_id(&format!("active_response_dispatch_{}", "0".repeat(64)));
    assert!(matches!(
        require_error(harness.executor.execute_source(&zero_dispatch)),
        ActiveResponseExecutorError::RejectedBeforeCommit(_)
    ));

    let mut malformed_hash = harness.automatic_request();
    malformed_hash.governed_intent_hash = "ABCDEF".to_string();
    assert!(matches!(
        require_error(harness.executor.execute_source(&malformed_hash)),
        ActiveResponseExecutorError::RejectedBeforeCommit(_)
    ));

    let mut malformed_record = harness.governed_request();
    malformed_record.approval = ActiveResponseExecutionApproval::Governed {
        admission_operation_id: " invalid-operation".to_string(),
        admission_operation_version: 3,
        approval_set_hash: digest_hex(&digest(44)),
    };
    assert!(matches!(
        require_error(harness.executor.execute_source(&malformed_record)),
        ActiveResponseExecutorError::RejectedBeforeCommit(_)
    ));

    let mut wrong_authority = harness.automatic_request();
    wrong_authority.executor_authority = identity(8);
    assert!(matches!(
        require_error(harness.executor.execute_source(&wrong_authority)),
        ActiveResponseExecutorError::RejectedBeforeCommit(_)
    ));
}

#[test]
fn ambiguous_effect_port_error_reports_unknown_and_remains_retryable() {
    let harness = Harness::new();
    let request = harness.automatic_request();
    harness.effects.set_mode(EffectMode::Unavailable);

    let error = require_error(harness.executor.execute_source(&request));
    assert!(matches!(
        error,
        ActiveResponseExecutorError::OutcomeUnknown(_)
    ));
    harness.effects.set_mode(EffectMode::Normal);
    let evidence = require_success(
        harness.executor.execute_source(&request),
        "retry ambiguous effect outcome",
    );
    assert!(evidence.recovered());
}

#[test]
fn rejects_oversized_execution_lease() {
    assert!(matches!(
        validate_lease_duration(MAX_ACTIVE_RESPONSE_LEASE_DURATION_MS + 1),
        Err(DurableActiveResponseExecutorConfigError::LeaseDurationTooLong { .. })
    ));
}
