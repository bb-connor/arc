use super::*;

#[path = "federation_context/evidence.rs"]
mod evidence;
#[path = "federation_context/recovery_isolation.rs"]
mod recovery_isolation;

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
        .begin_durable_tool_admission(request, &matching, current_unix_timestamp_ms())?
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
    assert!(kernel.dual_signed_receipt(&response.receipt.id).is_some());
    assert!(kernel
        .federation_dsse_envelope(&response.receipt.id)
        .is_some());
    assert!(response.receipt.verify_signature()?);
    let repeated = recover(&kernel, &fixture.request)?;
    assert_same_receipt(&response.receipt, &repeated.receipt);
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn retained_federation_context_is_private_and_cannot_be_removed_by_schema_downgrade() -> TestResult
{
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
    // The legacy federation-specific schema requires this field structurally.
    let mut legacy = raw.to_persisted();
    legacy.schema =
        crate::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_FEDERATION_CONTEXT_SCHEMA.into();
    legacy.receipt_signing_identity = None;
    assert!(RawInvocationOutcomeV1::from_persisted(legacy.clone()).is_ok());
    legacy.federation_context_json = None;
    assert!(RawInvocationOutcomeV1::from_persisted(legacy).is_err());
    let mut downgraded = raw.to_persisted();
    downgraded.schema = crate::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_REQUEST_SCHEMA.into();
    assert!(RawInvocationOutcomeV1::from_persisted(downgraded).is_err());

    // The signing schema also represents non-federated outcomes. Its optional
    // field is data, not authority: removing original context must fail against
    // the operation's exact committed blob before recovery or co-signing.
    let mut missing = raw.to_persisted();
    missing.federation_context_json = None;
    fixture
        .store
        .state
        .lock()
        .map_err(|_| "test lock")?
        .raw_outcome = Some(RawInvocationOutcomeV1::from_persisted(missing)?);
    let (kernel, admissions) = recovered_kernel(&fixture)?;
    assert!(recover(&kernel, &fixture.request)
        .is_err_and(|error| error.to_string().contains("outcome.raw_invocation_blob")));
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn security_release_requirement_and_federation_survive_either_codec_order() -> TestResult {
    let fixture = completed_fixture("federation-release-schema")?;
    let state = fixture.store.state.lock().map_err(|_| "test lock")?;
    let original = state.raw_outcome.as_ref().ok_or("raw outcome")?;
    let federation = original
        .federation_context_json()
        .ok_or("federation")?
        .to_owned();
    let mut persisted = original.to_persisted();
    persisted.security_invocation_context = Some(SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("codec-tenant")?,
            chio_security_types::ports::SessionId::new("codec-session")?,
            chio_security_types::PrincipalId::new(fixture.request.agent_id.clone())?,
            chio_security_types::ports::IsolationEpochId::new("codec-epoch")?,
            chio_security_types::ports::LineageId::new(fixture.request.capability.id.clone())?,
            1,
        ),
    ));
    // Exercise both legacy and frozen-signing codecs, not live release custody.
    for signed in [false, true] {
        let mut candidate = persisted.clone();
        let expected_schema = if signed {
            // A signing-aware outcome requires an explicit release disposition
            // whenever it contains security context, including a false value.
            candidate.security_release_required = Some(false);
            crate::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_SIGNING_IDENTITY_SCHEMA
        } else {
            candidate.receipt_signing_identity = None;
            candidate.schema =
                crate::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_FEDERATION_CONTEXT_SCHEMA.into();
            crate::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_SECURITY_RELEASE_SCHEMA
        };
        let raw = RawInvocationOutcomeV1::from_persisted(candidate)?;
        for required in [false, true] {
            let release_first = raw
                .clone()
                .with_security_release_requirement(required)?
                .with_federation_context_json(Some(federation.clone()))?;
            let federation_first = raw
                .clone()
                .with_federation_context_json(Some(federation.clone()))?
                .with_security_release_requirement(required)?;
            let blob = release_first.canonical_blob()?;
            assert_eq!(blob.bytes(), federation_first.canonical_blob()?.bytes());
            let decoded = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())?;
            assert_eq!(decoded.requires_security_release()?, required);
            assert_eq!(decoded.federation_context_json(), Some(federation.as_str()));
            assert_eq!(
                decoded.receipt_signing_identity(),
                raw.receipt_signing_identity()
            );
            assert_eq!(decoded.to_persisted().schema, expected_schema);
        }
    }
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
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
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
    assert!(kernel.dual_signed_receipt(&receipt.id).is_some());
    assert!(kernel.federation_dsse_envelope(&receipt.id).is_some());
    Ok(())
}
