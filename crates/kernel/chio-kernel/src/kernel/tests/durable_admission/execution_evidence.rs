//! Qualified-port signing fault tests, not physical store qualification.
use super::*;
use crate::admission_operation::AdmissionMutationSequencer;
use crate::{
    PaymentAdapter, PaymentAuthorization, PaymentAuthorizationState, PaymentAuthorizeRequest,
    PaymentError, PaymentRailMode, PaymentResult,
};
use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Ed25519Backend, SigningAlgorithm, SigningBackend, SigningOutcome};
use chio_core::{PublicKey, Signature};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct PendingPayment(Arc<AtomicUsize>);
impl PaymentAdapter for PendingPayment {
    fn rail_id(&self) -> &'static str {
        "execution-signing-test"
    }
    fn rail_mode(&self) -> Option<PaymentRailMode> {
        Some(PaymentRailMode::ReversibleHold)
    }
    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: format!("authorization:{}", request.reference),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({}),
        })
    }
    fn capture(&self, _: &str, _: u64, _: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(PaymentError::Unavailable(
            "execution signing test payment pending".into(),
        ))
    }
    fn release(&self, _: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable("unexpected release".into()))
    }
    fn refund(&self, _: &str, _: u64, _: &str, _: &str) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::Unavailable("unexpected refund".into()))
    }
}

struct Fixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    operation: AdmissionOperationV1,
    operations: Arc<TestAdmissionOperationStore>,
    outcomes: Arc<TestAdmissionOperationStore>,
    fence: StoreMutationFence,
    invocations: Arc<AtomicU64>,
    captures: Arc<AtomicUsize>,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".into(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".into(),
    });
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture_with_grants("execution-signing-request", vec![grant]);
    kernel.require_durable_request_retention();
    let captures = Arc::new(AtomicUsize::new(0));
    kernel.set_payment_adapter(Box::new(PendingPayment(captures.clone())));
    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::DurableAdmission(ref message)) if message.contains("execution signing test payment pending")),
        "{result:?}"
    );
    let operation = store.operation();
    let fence = store.fence.lock().map_err(|_| "fence lock")?.clone();
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(captures.load(Ordering::SeqCst), 1);
    assert!(store
        .lookup_execution_evidence(operation.binding().operation_id())?
        .is_none());
    Ok(Fixture {
        kernel,
        request,
        operation,
        operations: store.clone(),
        outcomes: store,
        fence,
        invocations,
        captures,
    })
}

impl TestAdmissionOperationStore {
    pub(super) fn retain_execution_evidence(
        &self,
        qualified: &crate::tool_outcome::QualifiedExecutionEvidenceV1,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
    ) -> Result<crate::tool_outcome::ExecutionEvidenceRecordV1, ToolOutcomeStoreError> {
        let record = qualified.record();
        let operation = self.operation();
        self.revalidate_recovery_claim(
            &operation,
            lease.untrusted_claim(),
            record.recorded_at_unix_ms(),
            record.store_fence(),
        )
        .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ToolOutcomeStoreError::Unavailable("state lock".into()))?;
        if state.claim.as_ref() != Some(lease.untrusted_claim()) {
            return Err(ToolOutcomeStoreError::Fenced);
        }
        let operation = state
            .operation
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let raw = state
            .raw_outcome
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let retained = state
            .retained_request
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let evaluation = state
            .post_return_evaluation
            .as_ref()
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        crate::tool_outcome::validate_execution_evidence_request(
            operation, retained, raw, evaluation,
        )
        .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        record
            .validate_against(
                operation,
                raw,
                state
                    .tool_outcome
                    .as_ref()
                    .ok_or(ToolOutcomeStoreError::NotFound)?,
                evaluation,
                state
                    .payment_journal
                    .as_ref()
                    .ok_or(ToolOutcomeStoreError::NotFound)?,
                state
                    .resolved_output
                    .as_ref()
                    .ok_or(ToolOutcomeStoreError::NotFound)?
                    .bytes(),
            )
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        if let Some(existing) = &state.execution_evidence {
            if existing != record {
                return Err(ToolOutcomeStoreError::Conflict);
            }
            return Ok(existing.clone());
        }
        state.execution_evidence = Some(record.clone());
        Ok(record.clone())
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Reenter,
    IdentityReenter,
    Expire,
    Panic,
    Replace,
    SourceChange,
    FenceChange,
}

struct SigningProbe {
    inner: Ed25519Backend,
    other: Ed25519Backend,
    sequencer: AdmissionMutationSequencer,
    mode: Mode,
    calls: AtomicUsize,
    reentries: AtomicUsize,
    advanced_clock: Mutex<Option<crate::FixedRuntimeScope>>,
    mutation_store: Arc<TestAdmissionOperationStore>,
}

impl SigningProbe {
    fn reenter(&self) -> Result<(), chio_core::Error> {
        let sequencer = self.sequencer.clone();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let acquired = sequencer.lock().is_ok();
            let _ = sender.send(acquired);
        });
        let acquired = receiver.recv_timeout(Duration::from_secs(2)).map_err(|_| {
            chio_core::Error::InvalidSignature("signer inherited mutation lock".into())
        })?;
        worker
            .join()
            .map_err(|_| chio_core::Error::InvalidSignature("reentry worker panicked".into()))?;
        assert!(acquired);
        self.reentries.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl SigningBackend for SigningProbe {
    fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm()
    }
    fn public_key(&self) -> PublicKey {
        if matches!(self.mode, Mode::IdentityReenter) {
            self.reenter()
                .expect("identity callback must run outside mutation lock");
        }
        self.inner.public_key()
    }
    fn sign_bytes(&self, _: &[u8]) -> Result<Signature, chio_core::Error> {
        Err(chio_core::Error::InvalidSignature(
            "unbound signing is forbidden".into(),
        ))
    }
    fn sign_bytes_for_identity(
        &self,
        key: &PublicKey,
        message: &[u8],
    ) -> Result<SigningOutcome, chio_core::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.reenter()?;
        match self.mode {
            Mode::Panic => panic!("execution signer callback failure"),
            Mode::Replace => self.other.sign_bytes_with_identity(message),
            Mode::Expire => {
                *self
                    .advanced_clock
                    .lock()
                    .map_err(|_| chio_core::Error::InvalidSignature("clock lock".into()))? =
                    Some(crate::scope_fixed_runtime_for_current_thread(
                        current_unix_timestamp() + 61,
                        [],
                    ));
                self.inner.sign_bytes_for_identity(key, message)
            }
            Mode::SourceChange => {
                let mut state = self.mutation_store.state.lock().map_err(|_| {
                    chio_core::Error::InvalidSignature("source mutation lock".into())
                })?;
                let retained = state.retained_request.as_ref().ok_or_else(|| {
                    chio_core::Error::InvalidSignature("original retained request missing".into())
                })?;
                let mut value: serde_json::Value =
                    serde_json::from_slice(retained.canonical_bytes())
                        .map_err(|error| chio_core::Error::InvalidSignature(error.to_string()))?;
                value["request"]["arguments"]["value"] =
                    serde_json::json!("changed-during-signing");
                let changed = crate::admission_operation::RetainedToolAdmissionRequestV1::from_canonical_bytes(
                    &canonical_json_bytes(&value)?,
                ).map_err(|error| chio_core::Error::InvalidSignature(error.to_string()))?;
                assert_ne!(changed.canonical_bytes(), retained.canonical_bytes());
                state.retained_request = Some(changed);
                drop(state);
                self.inner.sign_bytes_for_identity(key, message)
            }
            Mode::FenceChange => {
                let mut fence = self
                    .mutation_store
                    .fence
                    .lock()
                    .map_err(|_| chio_core::Error::InvalidSignature("fence mutation lock".into()))?
                    .clone();
                fence.owner_epoch += 1;
                self.mutation_store.rotate_fence(fence);
                self.inner.sign_bytes_for_identity(key, message)
            }
            Mode::Reenter | Mode::IdentityReenter => {
                self.inner.sign_bytes_for_identity(key, message)
            }
        }
    }
}

fn callback(mode: Mode) -> TestResult {
    let mut fixture = fixture()?;
    let before_journal = fixture.operations.load_payment_journal(
        fixture.operation.binding().operation_id().as_str(),
        &fixture.fence,
    )?;
    let before_receipts = fixture
        .kernel
        .receipt_log
        .lock()
        .map_err(|_| "receipt log lock")?
        .len();
    let before_request = fixture
        .operations
        .state
        .lock()
        .map_err(|_| "state lock")?
        .retained_request
        .as_ref()
        .ok_or("original retained request")?
        .canonical_bytes()
        .to_vec();
    let probe = Arc::new(SigningProbe {
        inner: Ed25519Backend::new(fixture.kernel.config.keypair.clone()),
        other: Ed25519Backend::generate(),
        sequencer: AdmissionMutationSequencer::for_fence(&fixture.fence)?,
        mode,
        calls: AtomicUsize::new(0),
        reentries: AtomicUsize::new(0),
        advanced_clock: Mutex::new(None),
        mutation_store: fixture.operations.clone(),
    });
    fixture.kernel.signing_authority.backend = probe.clone();
    let result = fixture
        .kernel
        .export_durable_execution_evidence(&fixture.request);
    drop(
        probe
            .advanced_clock
            .lock()
            .map_err(|_| "clock lock")?
            .take(),
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1, "{result:?}");
    assert!(probe.reentries.load(Ordering::SeqCst) >= 1);
    let projection = fixture
        .outcomes
        .lookup_execution_evidence(fixture.operation.binding().operation_id())?;
    match mode {
        Mode::Reenter | Mode::IdentityReenter => {
            let receipt = result?;
            assert!(receipt.verify_signature()?);
            assert_eq!(
                canonical_json_bytes(&projection.ok_or("missing projection")?.receipt()?)?,
                canonical_json_bytes(&receipt)?
            );
        }
        Mode::Expire => {
            assert!(
                matches!(result, Err(KernelError::DurableAdmission(_))),
                "{result:?}"
            );
            assert!(
                projection.is_none(),
                "expired original lease published evidence"
            );
        }
        Mode::SourceChange => {
            assert!(
                matches!(result, Err(KernelError::DurableAdmission(ref reason))
                if reason.contains("original operation changed during signing")),
                "{result:?}"
            );
            assert!(
                projection.is_none(),
                "changed retained source published evidence"
            );
            let state = fixture.operations.state.lock().map_err(|_| "state lock")?;
            assert_ne!(
                state
                    .retained_request
                    .as_ref()
                    .ok_or("changed retained request")?
                    .canonical_bytes(),
                before_request
            );
            assert_eq!(
                state.claim.as_ref().ok_or("original claim")?.store_fence(),
                &fixture.fence
            );
            assert_eq!(
                fixture
                    .kernel
                    .receipt_log
                    .lock()
                    .map_err(|_| "receipt log lock")?
                    .len(),
                before_receipts
            );
        }
        Mode::FenceChange => {
            assert!(
                matches!(result, Err(KernelError::DurableAdmission(ref reason))
                if reason.to_ascii_lowercase().contains("fenc")),
                "{result:?}"
            );
            assert!(
                projection.is_none(),
                "changed active fence published evidence"
            );
            assert_eq!(
                fixture
                    .operations
                    .fence
                    .lock()
                    .map_err(|_| "fence lock")?
                    .owner_epoch,
                fixture.fence.owner_epoch + 1
            );
            let state = fixture.operations.state.lock().map_err(|_| "state lock")?;
            assert_eq!(
                state.claim.as_ref().ok_or("original claim")?.store_fence(),
                &fixture.fence
            );
            assert_eq!(
                state
                    .retained_request
                    .as_ref()
                    .ok_or("retained request")?
                    .canonical_bytes(),
                before_request
            );
            assert_eq!(
                fixture
                    .kernel
                    .receipt_log
                    .lock()
                    .map_err(|_| "receipt log lock")?
                    .len(),
                before_receipts
            );
        }
        Mode::Panic | Mode::Replace => {
            assert!(
                matches!(result, Err(KernelError::ReceiptSigningFailed(_))),
                "{result:?}"
            );
            assert!(projection.is_none(), "failed signer published evidence");
        }
    }
    assert_eq!(
        fixture
            .operations
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(fixture.operation.clone())
    );
    assert_eq!(fixture.operations.payment_journal(), before_journal);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.captures.load(Ordering::SeqCst), 1);
    let _lock = probe.sequencer.lock()?;
    Ok(())
}

#[test]
fn execution_export_revalidates_original_lease_after_signer_callback() -> TestResult {
    callback(Mode::Expire)
}
#[test]
fn execution_export_signer_runs_outside_mutation_sequencer() -> TestResult {
    callback(Mode::Reenter)
}
#[test]
fn execution_export_identity_callback_runs_outside_mutation_sequencer() -> TestResult {
    callback(Mode::IdentityReenter)
}
#[test]
fn execution_export_contains_signer_panic_without_publishing() -> TestResult {
    callback(Mode::Panic)
}
#[test]
fn execution_export_rejects_signer_identity_substitution() -> TestResult {
    callback(Mode::Replace)
}

#[test]
fn execution_export_rejects_retained_request_change_during_signing() -> TestResult {
    callback(Mode::SourceChange)
}

#[test]
fn execution_export_rejects_fence_change_during_signing() -> TestResult {
    callback(Mode::FenceChange)
}

#[test]
fn execution_export_replays_original_receipt_after_signer_replacement() -> TestResult {
    let mut fixture = fixture()?;
    let original = fixture
        .kernel
        .export_durable_execution_evidence(&fixture.request)?;
    let replacement = Arc::new(SigningProbe {
        inner: Ed25519Backend::generate(),
        other: Ed25519Backend::generate(),
        sequencer: AdmissionMutationSequencer::for_fence(&fixture.fence)?,
        mode: Mode::Panic,
        calls: AtomicUsize::new(0),
        reentries: AtomicUsize::new(0),
        advanced_clock: Mutex::new(None),
        mutation_store: fixture.operations.clone(),
    });
    fixture.kernel.signing_authority.backend = replacement.clone();
    assert_ne!(
        fixture.kernel.receipt_signing_public_key(),
        original.kernel_key
    );
    let replay = fixture
        .kernel
        .export_durable_execution_evidence(&fixture.request)?;
    assert_eq!(replacement.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        canonical_json_bytes(&replay)?,
        canonical_json_bytes(&original)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.captures.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn execution_export_replay_respects_the_current_crypto_floor() -> TestResult {
    let mut fixture = fixture()?;
    let original = fixture
        .kernel
        .export_durable_execution_evidence(&fixture.request)?;
    fixture.kernel.signing_authority.floor = crate::KernelCryptoFloor::PqRequired;
    assert!(fixture
        .kernel
        .export_durable_execution_evidence(&fixture.request)
        .is_err());
    let retained = fixture
        .outcomes
        .lookup_execution_evidence(fixture.operation.binding().operation_id())?
        .ok_or("original projection")?;
    assert_eq!(
        canonical_json_bytes(&retained.receipt()?)?,
        canonical_json_bytes(&original)?
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.captures.load(Ordering::SeqCst), 1);
    Ok(())
}
