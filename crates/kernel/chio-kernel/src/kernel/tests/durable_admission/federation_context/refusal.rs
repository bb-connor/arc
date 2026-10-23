use super::*;

struct RefusingFederatedServer {
    invocations: Arc<AtomicU64>,
    admissions: Arc<dashmap::DashMap<String, ReceiptFederationAdmission>>,
    original: Arc<Mutex<Option<ReceiptFederationAdmission>>>,
}

#[async_trait::async_trait]
impl ToolServerConnection for RefusingFederatedServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        assert_eq!(self.admissions.len(), 1);
        let original = self
            .admissions
            .iter()
            .next()
            .expect("admitted federation snapshot")
            .value()
            .clone();
        assert!(original.verified_treaty_material.is_some());
        *self.original.lock().expect("captured treaty lock") = Some(original);
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::ToolServerError(
            "federated mutation is refused".into(),
        ))
    }
}

struct RefusalFixture {
    fixture: Fixture,
    original: ReceiptFederationAdmission,
    receipt: ChioReceipt,
    operation: AdmissionOperationV1,
}

fn refusing_fixture(
    request_id: &str,
    cosign: bool,
) -> Result<RefusalFixture, Box<dyn std::error::Error>> {
    let mut fixture = fixture(request_id)?;
    let original = Arc::new(Mutex::new(None));
    fixture
        .kernel
        .register_tool_server(Box::new(RefusingFederatedServer {
            invocations: fixture.invocations.clone(),
            admissions: fixture.kernel.receipt_federation_admissions.clone(),
            original: original.clone(),
        }));
    let cosigns = Arc::new(AtomicU64::new(0));
    if cosign {
        fixture
            .kernel
            .set_federation_cosigner(Arc::new(InProcessCoSigner::new(
                "kernel.org-a",
                fixture.origin_keypair.clone(),
                fixture.kernel.config.keypair.public_key(),
            )));
    } else {
        fixture
            .kernel
            .set_federation_cosigner(Arc::new(CountingRejectingCosigner {
                calls: cosigns.clone(),
            }));
    }
    let result = fixture.kernel.evaluate_tool_call_blocking(&fixture.request);
    let operation = assert_original_unknown_incident(
        &fixture.store,
        &fixture.request,
        &unknown_after("transport_return", "CHIO-KERNEL-TOOL-SERVER"),
    );
    let receipt = fixture
        .store
        .state
        .lock()
        .map_err(|_| "admission state")?
        .receipt
        .clone()
        .ok_or("canonical refused receipt")?;
    let reason = format!(
        "bilateral co-sign failed: {}",
        BilateralCoSigningError::PeerRejected(
            "test cosigner should not be called before local durability".into(),
        )
    );
    if cosign {
        let response = result?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
        assert_eq!(
            response.reason.as_deref(),
            Some("dispatch outcome is unknown after transport_return: CHIO-KERNEL-TOOL-SERVER")
        );
        assert_same_receipt(&response.receipt, &receipt);
    } else {
        let error = result.expect_err("rejected co-signing withholds terminal delivery");
        assert_federation_failure(&error, &receipt.id, &reason);
        assert_eq!(cosigns.load(Ordering::SeqCst), 1);
    }
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.kernel.receipt_log().len(), 1);
    assert_eq!(
        fixture
            .kernel
            .federation_dsse_envelope(&receipt.id)
            .is_some(),
        cosign
    );
    let original = original
        .lock()
        .map_err(|_| "captured treaty lock")?
        .take()
        .ok_or("original treaty admission")?;
    Ok(RefusalFixture {
        fixture,
        original,
        receipt,
        operation,
    })
}

fn assert_federation_failure(error: &KernelError, receipt_id: &str, reason: &str) {
    assert!(
        matches!(error, KernelError::DeliveryFailedAfterReceipt {
        receipt_id: actual,
        step: crate::kernel::ReceiptDeliveryStep::Federation,
        source,
    } if actual == receipt_id && matches!(source.as_ref(), KernelError::Internal(detail)
        if detail == reason)),
        "{error:?}"
    );
}

#[test]
fn federated_unknown_refusal_replays_existing_bilateral_artifacts() -> TestResult {
    let mut case = refusing_fixture("federated-refusal-artifact-replay", true)?;
    let admissions = Arc::new(AtomicU64::new(0));
    case.fixture
        .kernel
        .set_runtime_admission_hook(Arc::new(RejectNewRuntimeAdmission(admissions.clone())));
    let cosigns = Arc::new(AtomicU64::new(0));
    case.fixture
        .kernel
        .set_federation_cosigner(Arc::new(CountingRejectingCosigner {
            calls: cosigns.clone(),
        }));
    let replay = recover(&case.fixture.kernel, &case.fixture.request)?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay.output.is_none());
    assert_eq!(
        replay.reason.as_deref(),
        Some("dispatch outcome is unknown after transport_return: CHIO-KERNEL-TOOL-SERVER")
    );
    assert_same_receipt(&replay.receipt, &case.receipt);
    let envelope = case
        .fixture
        .kernel
        .federation_dsse_envelope(&case.receipt.id)
        .ok_or("bilateral DSSE envelope")?;
    chio_federation::bilateral_dsse::verify_chio_bilateral_dsse_envelope(
        &envelope,
        &case.fixture.origin_keypair.public_key(),
        &case.fixture.kernel.config.keypair.public_key(),
    )?;
    let repeated = recover(&case.fixture.kernel, &case.fixture.request)?;
    assert_same_receipt(&repeated.receipt, &case.receipt);
    assert_eq!(cosigns.load(Ordering::SeqCst), 0);
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(case.fixture.store.operation(), case.operation);
    assert_eq!(case.fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(case.fixture.kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn restarted_unknown_refusal_requires_its_original_federation_treaty() -> TestResult {
    let case = refusing_fixture("federated-refusal-missing-original-treaty", false)?;
    let unrelated = refusing_fixture("federated-refusal-unrelated-treaty", true)?;
    let (kernel, admissions) = recovered_kernel(&case.fixture)?;
    for ambient in [None, Some(case.original), Some(unrelated.original)] {
        let _ambient = ambient.map(|snapshot| {
            kernel.scope_receipt_federation_admission_for_request(
                &case.fixture.request.request_id,
                snapshot,
            )
        });
        let error = recover(&kernel, &case.fixture.request)
            .expect_err("absent original treaty withholds federation delivery");
        assert_federation_failure(
            &error,
            &case.receipt.id,
            "terminal refusal original federation treaty is absent",
        );
        let stored = kernel
            .load_durable_admission_receipt(&case.receipt.id)?
            .ok_or("original canonical refusal")?;
        assert_same_receipt(&stored, &case.receipt);
        assert_eq!(case.fixture.store.operation(), case.operation);
        assert_eq!(kernel.receipt_log().len(), 1);
        assert!(kernel.federation_dsse_envelope(&case.receipt.id).is_none());
    }
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(case.fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn federated_refusal_replay_rejects_a_conflicting_dsse_envelope() -> TestResult {
    let case = refusing_fixture("federated-refusal-conflicting-artifact", true)?;
    let other = refusing_fixture("federated-refusal-other-artifact", true)?;
    let foreign = other
        .fixture
        .kernel
        .federation_dsse_envelope(&other.receipt.id)
        .ok_or("unrelated bilateral DSSE envelope")?;
    let now = case.fixture.kernel.trusted_now_millis()?.as_secs();
    let _ = case
        .fixture
        .kernel
        .federation_dsse_envelopes
        .lock()
        .map_err(|_| "DSSE cache lock")?
        .insert(case.receipt.id.clone(), foreign, now);
    let error = recover(&case.fixture.kernel, &case.fixture.request)
        .expect_err("conflicting bilateral body refuses delivery");
    assert_federation_failure(
        &error,
        &case.receipt.id,
        "terminal refusal federation artifact conflicts with its receipt",
    );
    assert_same_receipt(
        &case
            .fixture
            .kernel
            .load_durable_admission_receipt(&case.receipt.id)?
            .ok_or("canonical receipt")?,
        &case.receipt,
    );
    assert_eq!(case.fixture.store.operation(), case.operation);
    assert_eq!(case.fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(case.fixture.kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn federated_refusal_replay_rejects_a_poisoned_artifact_cache() -> TestResult {
    let case = refusing_fixture("federated-refusal-poisoned-cache", true)?;
    std::thread::scope(|scope| {
        let cache = &case.fixture.kernel.federation_dsse_envelopes;
        let poisoned = scope.spawn(move || {
            let _cache = cache.lock().expect("DSSE cache lock");
            panic!("injected federation cache poison");
        });
        let panic = poisoned.join().expect_err("injected cache lock panic");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"injected federation cache poison")
        );
    });
    let error = recover(&case.fixture.kernel, &case.fixture.request)
        .expect_err("poisoned federation cache refuses delivery");
    assert_federation_failure(
        &error,
        &case.receipt.id,
        "terminal refusal federation artifact cache is unavailable",
    );
    assert_same_receipt(
        &case
            .fixture
            .kernel
            .load_durable_admission_receipt(&case.receipt.id)?
            .ok_or("canonical receipt")?,
        &case.receipt,
    );
    assert_eq!(case.fixture.store.operation(), case.operation);
    assert_eq!(case.fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(case.fixture.kernel.receipt_log().len(), 1);
    Ok(())
}

#[test]
fn startup_recovery_terminalizes_a_federated_admission_without_its_original_treaty() -> TestResult {
    let fixture = fixture("federated-startup-recovery")?;
    let (kernel, admissions) = recovered_kernel(&fixture)?;
    let matching = resolve_required_matching_grants(
        &fixture.request.capability,
        &fixture.request.tool_name,
        &fixture.request.server_id,
        &fixture.request.arguments,
        fixture.request.model_metadata.as_ref(),
    )
    .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
    let admission = kernel
        .begin_durable_tool_admission(&fixture.request, &matching, current_unix_timestamp_ms())
        .map_err(|failure| *failure.error)?
        .ok_or("retained federated admission")?;
    drop(admission);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let receipt = fixture
        .store
        .state
        .lock()
        .map_err(|_| "admission state")?
        .receipt
        .clone()
        .ok_or("recovery refusal receipt")?;
    assert!(receipt.verify_integrity_embedded_key()?);
    assert!(kernel.federation_dsse_envelope(&receipt.id).is_none());
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    let error = recover(&kernel, &fixture.request)
        .expect_err("a caller replay withholds federation delivery without the treaty");
    assert_federation_failure(
        &error,
        &receipt.id,
        "terminal refusal original federation treaty is absent",
    );
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
