// Two public requests, one original operation, no legacy nonce or capture hook.
use super::*;

mod expiry {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_nonce_expiry_tests.rs"
    ));
}

pub(in crate::security::adapters::tests::native_flow::support) fn configure(
    fixture: &mut Fixture,
    egress: bool,
) -> TestResult<Arc<AtomicUsize>> {
    let legacy = install_nonce(fixture, ExecutionNonceConfig::default().nonce_ttl_secs);
    // Combined participant histories take longer to verify in debug builds.
    // Expiry tests still exercise the real, shorter signed nonce deadline.
    let mut config = flow_config();
    config.fence_ttl_ms = 60_000;
    fixture.kernel.set_security_pre_dispatch_hook(Arc::new(
        NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(egress, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            config,
        )?
        .with_captured_lifecycle(),
    ));
    Ok(legacy)
}

pub(in crate::security::adapters::tests::native_flow::support) fn install_nonce(
    fixture: &mut Fixture,
    nonce_ttl_secs: u64,
) -> Arc<AtomicUsize> {
    let legacy = Arc::new(AtomicUsize::new(0));
    fixture.kernel.set_execution_nonce_store(
        ExecutionNonceConfig {
            require_nonce: true,
            nonce_ttl_secs,
            ..ExecutionNonceConfig::default()
        },
        Box::new(NoLegacyNonce(legacy.clone())),
    );
    legacy
}

pub(in crate::security::adapters::tests::native_flow::support) fn issue(
    fixture: &mut Fixture,
) -> TestResult<chio_kernel::admission_operation::AdmissionOperationId> {
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    fixture.request.execution_nonce = Some(*response.execution_nonce.ok_or("issued nonce")?);
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("original nonce operation")?;
    // Resolve mutable state afresh through the authority, not the preflight's
    // historical acknowledgement. The dispatch writer checks it independently.
    let context = fixture.context.as_v1();
    let key = FlowStateKey {
        tenant_id: context.tenant_id().clone(),
        principal_id: context.principal_id().clone(),
        session_id: context.session_id().clone(),
        lineage_id: context.lineage_root_id().clone(),
        isolation_epoch_id: context.isolation_epoch_id().clone(),
    };
    let observed = store.observe_native_security_flow(&fixture.binding, &key, &fence, now_ms()?)?;
    fixture.context = SecurityInvocationContext::v1(
        context.clone().with_flow_state_generation(
            observed
                .stored_context_generation()
                .ok_or("preflight did not retain flow state")?,
        ),
    );
    Ok(operation.binding().operation_id().clone())
}

#[test]
fn native_nonce_executes_once_and_replays_its_receipt_for_local_and_egress() -> TestResult {
    for combined in [false, true] {
        for asynchronous in [false, true] {
            for egress in [false, true] {
                let mut fixture = if combined {
                    Fixture::combined_native_credentials()?
                } else {
                    super::super::super::public_fixture()?
                };
                let legacy = configure(&mut fixture, egress)?;
                let operation_id = issue(&mut fixture)?;
                let response = if asynchronous {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(fixture.kernel.evaluate_tool_call_with_security_context(
                            &fixture.request,
                            &fixture.context,
                        ))?
                } else {
                    fixture
                        .kernel
                        .evaluate_tool_call_blocking_with_security_context(
                            &fixture.request,
                            &fixture.context,
                        )?
                };
                assert_eq!(
                    response.verdict,
                    Verdict::Allow,
                    "combined={combined} async={asynchronous} egress={egress}: {:?}",
                    response.reason
                );
                assert!(
                    matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
                );
                assert!(response.receipt.verify_signature()?);
                assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
                assert_eq!(legacy.load(Ordering::SeqCst), 0);
                let replay = fixture
                    .kernel
                    .evaluate_tool_call_blocking_with_security_context(
                        &fixture.request,
                        &fixture.context,
                    )?;
                assert_eq!(
                    chio_core::canonical_json_bytes(&replay.receipt)?,
                    chio_core::canonical_json_bytes(&response.receipt)?
                );
                assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
                let store = fixture.authority.admission_operation_store();
                let fence = fixture.authority.mutation_fence();
                let (operation, _) = store
                    .load_unambiguous_retained_tool_request(
                        &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
                        &fence,
                        now_ms()?,
                    )?
                    .ok_or("completed original nonce operation")?;
                assert_eq!(operation.binding().operation_id(), &operation_id);
                assert_eq!(operation.state(), AdmissionOperationState::Completed);
                assert!(operation.execution_nonce_id().is_some());
                assert!(operation.execution_nonce_issuance_digest().is_some());
                assert!(operation.native_dispatch_ledger_digest().is_some());
                if combined {
                    assert!(operation.runtime_participant_ledger_digest().is_some());
                    assert!(operation.governed_approval_ledger_digest().is_some());
                    assert!(operation.dpop_replay_ledger_digest().is_some());
                }
                assert!(store
                    .load_native_security_input_join(&operation_id, &fence, now_ms()?)?
                    .ok_or("input operation")?
                    .1
                    .is_some());
                assert!(store
                    .load_native_security_output_join(&operation_id, &fence, now_ms()?)?
                    .ok_or("output operation")?
                    .1
                    .is_some());
            }
        }
    }
    Ok(())
}

#[test]
fn native_nonce_mutations_and_missing_credentials_never_reach_the_connector() -> TestResult {
    for mutation in [
        "arguments",
        "request",
        "nonce",
        "flow_generation",
        "dpop",
        "approval",
    ] {
        let mut fixture = if matches!(mutation, "dpop" | "approval") {
            Fixture::combined_native_credentials()?
        } else {
            super::super::super::public_fixture()?
        };
        let stale_context = fixture.context.clone();
        let legacy = configure(&mut fixture, true)?;
        let original = issue(&mut fixture)?;
        match mutation {
            "arguments" => fixture.request.arguments = serde_json::json!({"changed": true}),
            "request" => fixture.request.request_id.push_str("-substituted"),
            "nonce" => fixture
                .request
                .execution_nonce
                .as_mut()
                .ok_or("issued nonce")?
                .nonce
                .nonce_id
                .push_str("-substituted"),
            "flow_generation" => fixture.context = stale_context,
            "dpop" => fixture.request.dpop_proof = None,
            "approval" => fixture.request.approval_token = None,
            _ => unreachable!(),
        }
        let result = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context);
        if let Ok(response) = result {
            assert_eq!(
                response.verdict,
                Verdict::Deny,
                "mutation={mutation}: {:?}",
                response.reason
            );
            assert!(response.output.is_none());
            assert!(response.receipt.verify_signature()?);
        }
        assert_eq!(
            fixture.invocations.load(Ordering::SeqCst),
            0,
            "mutation={mutation}"
        );
        assert_eq!(legacy.load(Ordering::SeqCst), 0);
        let (operation, _) = fixture
            .authority
            .admission_operation_store()
            .load_retained_tool_request(&original, &fixture.authority.mutation_fence(), now_ms()?)?
            .ok_or("original denied operation")?;
        assert!(operation.dispatch_commit().is_none(), "mutation={mutation}");
    }
    Ok(())
}

#[test]
fn native_nonce_omission_cannot_reopen_an_issued_preflight_or_dispatch() -> TestResult {
    let mut fixture = super::super::super::public_fixture()?;
    let legacy = configure(&mut fixture, false)?;
    let original = issue(&mut fixture)?;
    fixture
        .request
        .execution_nonce
        .take()
        .ok_or("issued nonce")?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(response.execution_nonce.is_none());
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.load(Ordering::SeqCst), 0);
    let (operation, _) = fixture
        .authority
        .admission_operation_store()
        .load_retained_tool_request(&original, &fixture.authority.mutation_fence(), now_ms()?)?
        .ok_or("original preflight operation")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.execution_nonce_id().is_none());
    assert!(operation.dispatch_commit().is_none());
    Ok(())
}
