use super::*;

#[path = "federation_context/evidence.rs"]
mod evidence;
#[path = "federation_context/recovery_isolation.rs"]
mod recovery_isolation;
#[path = "federation_context/refusal.rs"]
mod refusal;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct RejectNewRuntimeAdmission(Arc<AtomicU64>);

impl RuntimeAdmissionHook for RejectNewRuntimeAdmission {
    fn name(&self) -> &str {
        "no-new-admission-during-recovery"
    }
    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::deny(
            "fresh admission is deliberately unavailable",
            None,
        ))
    }
}

struct Fixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    store: Arc<TestAdmissionOperationStore>,
    invocations: Arc<AtomicU64>,
    origin_keypair: Keypair,
}

fn fixture(request_id: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let (mut kernel, mut request, store, invocations) = durable_admission_fixture(request_id);
    kernel.set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))?;
    kernel.set_federation_local_kernel_id("kernel.org-b");
    let origin_keypair = Keypair::generate();
    let trust = KernelTrustExchange::new("kernel.org-b", kernel.config.keypair.clone())
        .with_trusted_peer("kernel.org-a", origin_keypair.public_key());
    let peer = handshake_and_pin(
        &trust,
        "kernel.org-a",
        &origin_keypair,
        current_unix_timestamp_ms() / 1_000,
    );
    let mut kernel = kernel.with_federation_peers(vec![peer]);
    kernel.set_runtime_admission_hook(Arc::new(TreatyDsseAdmissionHook::new(
        origin_keypair.clone(),
        kernel.config.keypair.clone(),
    )));
    kernel.set_federation_cosigner(Arc::new(CountingRejectingCosigner {
        calls: Arc::new(AtomicU64::new(0)),
    }));
    request.federated_origin_kernel_id = Some("kernel.org-a".into());
    Ok(Fixture {
        kernel,
        request,
        store,
        invocations,
        origin_keypair,
    })
}

fn completed_fixture(request_id: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let fixture = fixture(request_id)?;
    let result = fixture.kernel.evaluate_tool_call_blocking(&fixture.request);
    assert!(
        matches!(result, Err(KernelError::Internal(reason)) if reason.contains("bilateral co-sign failed"))
    );
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(fixture)
}

fn recovered_kernel(fixture: &Fixture) -> Result<(ChioKernel, Arc<AtomicU64>), KernelError> {
    let mut config = make_config();
    config.keypair = fixture.kernel.config.keypair.clone();
    config.policy_hash = fixture.kernel.config.policy_hash.clone();
    let mut kernel = make_kernel(config);
    kernel.set_federation_local_kernel_id("kernel.org-b");
    kernel.set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))?;
    kernel.set_durable_admission_store(
        fixture.store.clone(),
        fixture.store.clone(),
        admission_test_fence(),
    )?;
    kernel.set_budget_store_handle(fixture.store.budget_store());
    let admissions = Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(Arc::new(RejectNewRuntimeAdmission(admissions.clone())));
    kernel.set_federation_cosigner(Arc::new(InProcessCoSigner::new(
        "kernel.org-a",
        fixture.origin_keypair.clone(),
        kernel.config.keypair.public_key(),
    )));
    // No tool registration and no current peer pins. Historical finalization
    // must use the retained qualified outcome, not dispatch or fresh defaults.
    Ok((kernel, admissions))
}

fn recover(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
) -> Result<ToolCallResponse, KernelError> {
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
    let mut admission = kernel
        .begin_durable_tool_admission(request, &matching, current_unix_timestamp_ms())
        .map_err(|failure| *failure.error)?
        .ok_or_else(|| KernelError::DurableAdmission("missing test admission".into()))?;
    kernel
        .recover_durable_tool_admission(&mut admission, request)?
        .ok_or_else(|| KernelError::DurableAdmission("missing recovered response".into()))
}

#[test]
fn retained_federation_context_recovers_without_live_peer_or_new_runtime_admission() -> TestResult {
    let fixture = completed_fixture("retained-federation-restart")?;
    let (kernel, admissions) = recovered_kernel(&fixture)?;
    let response = recover(&kernel, &fixture.request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert!(kernel
        .federation_dsse_envelope(&response.receipt.id)
        .is_some());
    assert!(response.receipt.verify_integrity_embedded_key()?);
    let repeated = recover(&kernel, &fixture.request)?;
    assert_same_receipt(&response.receipt, &repeated.receipt);
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn retained_federation_context_is_private_and_bound_to_the_committed_outcome() -> TestResult {
    let fixture = completed_fixture("retained-federation-private")?;
    let state = fixture.store.state.lock().map_err(|_| "test lock")?;
    let raw = state.raw_outcome.as_ref().ok_or("missing raw")?.clone();
    let retained: serde_json::Value =
        serde_json::from_str(raw.federation_context_json().ok_or("missing context")?)?;
    assert_eq!(retained["schema"], "chio.frozen-federation-admission.v1");
    assert_eq!(
        retained["treaty_evidence"]["envelope"]["signatures"]
            .as_array()
            .ok_or("signatures")?
            .len(),
        2
    );
    let receipt = serde_json::to_string(state.receipt.as_ref().ok_or("missing receipt")?)?;
    assert!(!receipt.contains("treaty_evidence"));
    assert!(!receipt.contains("federation_context_json"));
    for debug in [format!("{raw:?}"), format!("{:?}", raw.to_persisted())] {
        assert!(debug.contains("operation_id"));
        assert!(!debug.contains("treaty_evidence"));
        assert!(!debug.contains("admission_report_sha256"));
        assert!(!debug.contains("request_canonical_json"));
        assert!(!debug.contains("output"));
    }
    drop(state);
    for schema in [
        "chio.raw-invocation-outcome-with-federation-context.v1",
        "chio.raw-invocation-outcome-with-request.v1",
    ] {
        let mut malformed = raw.to_persisted();
        malformed.schema = schema.into();
        assert_eq!(
            RawInvocationOutcomeV1::from_persisted(malformed),
            Err(crate::tool_outcome::ToolOutcomeError::Invalid("raw.schema"))
        );
    }

    // Recovery requires the exact committed blob before federation co-signing.
    let mut missing = raw.to_persisted();
    missing.federation_context_json = None;
    fixture
        .store
        .state
        .lock()
        .map_err(|_| "test lock")?
        .raw_outcome = Some(RawInvocationOutcomeV1::from_persisted(missing)?);
    let (kernel, admissions) = recovered_kernel(&fixture)?;
    assert!(matches!(
        recover(&kernel, &fixture.request),
        Err(KernelError::DurableAdmission(message))
            if message == "binding mismatch: outcome.raw_invocation_blob"
    ));
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn security_release_requirement_and_federation_survive_canonical_roundtrip() -> TestResult {
    let fixture = completed_fixture("federation-release-schema")?;
    let state = fixture.store.state.lock().map_err(|_| "test lock")?;
    let original = state.raw_outcome.as_ref().ok_or("raw outcome")?;
    let federation = original
        .federation_context_json()
        .ok_or("federation")?
        .to_owned();
    let mut persisted = original.to_persisted();
    let context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        chio_security_types::ports::TenantId::new("codec-tenant")?,
        chio_security_types::ports::SessionId::new("codec-session")?,
        chio_security_types::PrincipalId::new(fixture.request.agent_id.clone())?,
        chio_security_types::ports::IsolationEpochId::new("codec-epoch")?,
        chio_security_types::ports::LineageId::new(fixture.request.capability.id.clone())?,
        1,
    ));
    let binding =
        crate::admission_operation::NativeSecurityDispatchRequestBindingV1::from_live_request(
            &fixture.request,
            &context,
        )?;
    let original_binding = crate::tool_outcome::OriginalSecurityDispatchBindingV1::new(&binding)?;
    persisted.security_invocation_context = Some(context);
    for required in [false, true] {
        let mut candidate = persisted.clone();
        candidate.security_release_required = required;
        candidate.original_security_dispatch_binding =
            required.then(|| Box::new(original_binding.clone()));
        let raw = RawInvocationOutcomeV1::from_persisted(candidate)?;
        let blob = raw.canonical_blob()?;
        let decoded = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())?;
        assert_eq!(decoded.requires_security_release()?, required);
        assert_eq!(decoded.federation_context_json(), Some(federation.as_str()));
        assert_eq!(
            decoded.receipt_signing_identity(),
            original.receipt_signing_identity()
        );
        assert_eq!(decoded, raw);
    }
    persisted.security_release_required = true;
    assert_eq!(
        RawInvocationOutcomeV1::from_persisted(persisted),
        Err(crate::tool_outcome::ToolOutcomeError::Binding(
            "raw.original_security_dispatch_binding"
        ))
    );
    Ok(())
}

#[test]
fn retained_federation_context_tampering_fails_the_committed_outcome_binding() -> TestResult {
    let fixture = completed_fixture("retained-federation-tamper")?;
    {
        let mut state = fixture.store.state.lock().map_err(|_| "test lock")?;
        let mut raw = state
            .raw_outcome
            .as_ref()
            .ok_or("missing raw")?
            .to_persisted();
        let mut context: serde_json::Value =
            serde_json::from_str(raw.federation_context_json.as_deref().ok_or("context")?)?;
        context["treaty_evidence"]["admission"]["admission_report_sha256"] =
            serde_json::json!("a".repeat(64));
        raw.federation_context_json = Some(String::from_utf8(canonical_json_bytes(&context)?)?);
        state.raw_outcome = Some(RawInvocationOutcomeV1::from_persisted(raw)?);
    }
    let (kernel, admissions) = recovered_kernel(&fixture)?;
    let result = recover(&kernel, &fixture.request);
    assert!(result
        .as_ref()
        .is_err_and(|error| error.to_string().contains("outcome.raw_invocation_blob")));
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn retained_federation_context_does_not_bypass_public_replay_revocation() -> TestResult {
    let fixture = completed_fixture("retained-federation-revoked")?;
    fixture
        .kernel
        .revoke_capability(&fixture.request.capability.id)?;
    let original = fixture.store.operation();
    let receipts = fixture.kernel.receipt_log().len();
    let error = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)
        .expect_err("revoked replay must not release output or create a terminal");
    assert!(
        matches!(error, KernelError::DurableAdmission(ref reason)
        if reason == "request identity is already owned by a durable operation"),
        "{error:?}"
    );
    assert_eq!(fixture.kernel.receipt_log().len(), receipts);
    assert_eq!(fixture.store.operation(), original);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::Completed
    );
    Ok(())
}

#[test]
fn retained_federation_context_rejects_wrong_treaty_pin_before_dispatch() -> TestResult {
    assert_wrong_treaty_pin_is_compensated(false)
}

#[test]
fn nested_retained_federation_context_rejection_compensates_before_dispatch() -> TestResult {
    assert_wrong_treaty_pin_is_compensated(true)
}

fn assert_wrong_treaty_pin_is_compensated(nested: bool) -> TestResult {
    let mut fixture = fixture("retained-federation-wrong-pin")?;
    fixture
        .kernel
        .set_runtime_admission_hook(Arc::new(TreatyDsseAdmissionHook::new(
            Keypair::generate(),
            fixture.kernel.config.keypair.clone(),
        )));
    let result = if nested {
        let session = fixture
            .kernel
            .open_session("federation-parent".into(), Vec::new())?;
        fixture.kernel.activate_session(&session)?;
        let parent = make_operation_context(&session, "parent-request", "federation-parent");
        fixture
            .kernel
            .begin_session_request(&parent, OperationKind::ToolCall, true)?;
        fixture.kernel.evaluate_tool_call_with_nested_flow_client(
            &parent,
            &fixture.request,
            &mut NoopNestedFlowClient,
            None,
        )
    } else {
        fixture.kernel.evaluate_tool_call_blocking(&fixture.request)
    };
    assert!(result.as_ref().is_err_and(|error| error
        .to_string()
        .contains("participants do not match the admitted peer snapshot")));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(fixture.store.budget_store().count_open_holds()?, 0);
    assert_eq!(
        fixture
            .store
            .budget_store()
            .get_usage(&fixture.request.capability.id, 0)?
            .ok_or("usage")?
            .invocation_count,
        0
    );
    let state = fixture.store.state.lock().map_err(|_| "test lock")?;
    assert!(state.raw_outcome.is_none());
    Ok(())
}

#[test]
fn retained_federation_context_finalizing_recovery_survives_owner_rotation() -> TestResult {
    let fixture = fixture("retained-federation-finalizing")?;
    fixture.store.fail_next_terminal_projection();
    let result = fixture.kernel.evaluate_tool_call_blocking(&fixture.request);
    assert!(result.as_ref().is_err_and(|error| error
        .to_string()
        .contains("injected terminal projection failure")));
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let (mut kernel, admissions) = recovered_kernel(&fixture)?;
    let fence = StoreMutationFence {
        store_uuid: admission_test_fence().store_uuid,
        lease_id: "retained-federation-restarted-owner".into(),
        owner_epoch: 2,
    };
    fixture.store.rotate_fence(fence.clone());
    kernel.set_durable_admission_store(fixture.store.clone(), fixture.store.clone(), fence)?;
    // Startup counts the finalized operation and its receipt projection separately.
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 2);
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 0);
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let state = fixture.store.state.lock().map_err(|_| "test lock")?;
    let receipt = state.receipt.as_ref().ok_or("receipt")?;
    assert!(kernel.federation_dsse_envelope(&receipt.id).is_some());
    Ok(())
}
