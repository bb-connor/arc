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
    let operation = assert_original_unknown_incident(&fixture.store, &fixture.request);
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
            Some("tool server error: federated mutation is refused")
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
        fixture.kernel.dual_signed_receipt(&receipt.id).is_some(),
        cosign
    );
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
        Some("tool server error: federated mutation is refused")
    );
    assert_same_receipt(&replay.receipt, &case.receipt);
    assert!(case
        .fixture
        .kernel
        .dual_signed_receipt(&case.receipt.id)
        .is_some());
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
        assert!(kernel.dual_signed_receipt(&case.receipt.id).is_none());
        assert!(kernel.federation_dsse_envelope(&case.receipt.id).is_none());
    }
    assert_eq!(admissions.load(Ordering::SeqCst), 0);
    assert_eq!(case.fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn federated_refusal_replay_rejects_a_conflicting_dual_receipt() -> TestResult {
    let case = refusing_fixture("federated-refusal-conflicting-artifact", true)?;
    let mut dual = case
        .fixture
        .kernel
        .dual_signed_receipt(&case.receipt.id)
        .ok_or("original bilateral receipt")?;
    dual.body.tool_name = "different-tool".into();
    let now = case.fixture.kernel.trusted_now_millis()?.as_secs();
    let _ = case
        .fixture
        .kernel
        .federation_dual_receipts
        .lock()
        .map_err(|_| "dual cache lock")?
        .insert(case.receipt.id.clone(), dual, now);
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
        let cache = &case.fixture.kernel.federation_dual_receipts;
        let poisoned = scope.spawn(move || {
            let _cache = cache.lock().expect("dual cache lock");
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
