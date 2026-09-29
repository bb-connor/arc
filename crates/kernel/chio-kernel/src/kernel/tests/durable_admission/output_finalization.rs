use super::*;

#[test]
fn durable_post_invocation_identity_binds_transformed_output_and_replay() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-versioned-post-hook");
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "filtered",
    }));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("versioned post hook dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({"replacement": "filtered"})
        ))
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(store.outcome_versions(), (Some(4), Some(2)));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("versioned post hook replay");
    assert_eq!(replay.output, response.output);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_redaction_cannot_upgrade_incomplete_transport_and_replay_is_exactly_once() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-incomplete-redacted-stream");
    kernel.register_tool_server(Box::new(DurableIncompleteStreamServer {
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "filtered-partial",
    }));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable incomplete stream finalization");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({"replacement": "filtered-partial"})
        ))
    );
    assert_eq!(
        response.reason.as_deref(),
        Some("transport ended after the side effect")
    );
    assert_eq!(
        response.receipt.decision,
        Some(chio_core::receipt::decision::Decision::Incomplete {
            reason: "transport ended after the side effect".to_owned(),
        })
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("durable incomplete stream replay");
    assert_eq!(replay.output, response.output);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.terminal_state, response.terminal_state);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_redaction_recovery_uses_the_recorded_stream_limits() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-redaction-stream-limit-snapshot");
    kernel.config.memory_budget.max_stream_chunks = 1;
    kernel.add_post_invocation_hook(Box::new(StableStreamRedactingPostInvocationHook));
    store.fail_next_evaluation_begin();

    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    recovered_config.memory_budget.max_stream_chunks = 2;
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), admission_test_fence())
        .expect("qualified admission store");
    recovered_kernel.add_post_invocation_hook(Box::new(StableStreamRedactingPostInvocationHook));
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let recovered = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect("recover redacted stream with recorded limits");
    assert_eq!(recovered.verdict, Verdict::Deny);
    assert!(recovered
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("max chunk count of 1")));
    let Some(ToolCallOutput::Stream(stream)) = recovered.output else {
        panic!("expected retained redacted stream");
    };
    assert_eq!(stream.chunk_count(), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_post_invocation_identity_change_cannot_replace_recovered_finalization() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-post-hook-identity-change");
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
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    // Recovery runs under a rotated store lease, exactly as a restarted process
    // takes over: the crashed operation's recovery lease belongs to the prior
    // owner, so the sweep sees it as recoverable rather than actively leased.
    let rotated_fence = StoreMutationFence {
        store_uuid: admission_test_fence().store_uuid,
        lease_id: "test-admission-lease-2".to_owned(),
        owner_epoch: 2,
    };
    store.rotate_fence(rotated_fence.clone());
    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), rotated_fence)
        .expect("qualified admission store");
    recovered_kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "second",
    }));
    recovered_kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));

    let error = recovered_kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("identity substitution must fail closed");
    assert!(error
        .to_string()
        .contains("recovered post-return plan does not match durable admission"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
