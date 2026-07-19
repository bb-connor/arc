use super::*;

#[test]
fn durable_terminal_receipt_uses_the_admitted_tenant() {
    let request_id = "durable-tenant-receipt";
    let (kernel, request, store, invocations) = durable_admission_fixture(request_id);
    let session_id = kernel
        .open_session(
            request.capability.subject.to_hex(),
            vec![request.capability.clone()],
        )
        .expect("tenant session");
    kernel
        .set_session_auth_context(
            &session_id,
            oauth_auth_with_enterprise_tenant("tenant-durable"),
        )
        .expect("tenant authentication");
    kernel
        .activate_session(&session_id)
        .expect("active tenant session");

    let response = kernel
        .evaluate_tool_call_sync_with_session_context(&request, None, None, Some(&session_id))
        .expect("tenant-scoped durable dispatch");
    assert_eq!(
        response.receipt.tenant_id.as_deref(),
        Some("tenant-durable")
    );
    assert!(response.receipt.verify_signature().expect("signed receipt"));
    assert_eq!(
        store
            .operation()
            .binding()
            .to_persisted()
            .authenticated_tenant_id
            .as_str(),
        "tenant-durable"
    );

    let replay = kernel
        .evaluate_tool_call_sync_with_session_context(&request, None, None, Some(&session_id))
        .expect("tenant-scoped durable replay");
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.receipt.tenant_id.as_deref(), Some("tenant-durable"));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn startup_recovery_rejects_a_changed_post_return_plan() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-startup-post-hook-change");
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "first",
    }));
    store.fail_next_evaluation_begin();
    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );

    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), admission_test_fence())
        .expect("qualified admission store");
    recovered_kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "second",
    }));

    let error = recovered_kernel
        .reconcile_recoverable_admissions()
        .expect_err("changed recovery plan must fail closed");
    assert!(error
        .to_string()
        .contains("recovered post-return plan does not match durable admission"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
