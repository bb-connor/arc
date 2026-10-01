//! Backend fault injection, not qualification of a deployed rotating keyring.

use super::*;
use crate::admission_operation::AdmissionMutationSequencer;
use chio_core::crypto::{Ed25519Backend, SigningAlgorithm, SigningBackend, SigningOutcome};
use chio_core::{PublicKey, Signature};
use std::sync::{mpsc, Mutex};

#[derive(Clone, Copy)]
enum Mode {
    Reenter,
    Panic,
    Replace,
    Expire,
}

struct SigningProbe {
    inner: Ed25519Backend,
    replacement: Ed25519Backend,
    sequencer: AdmissionMutationSequencer,
    mode: Mode,
    calls: AtomicUsize,
    entered: AtomicUsize,
    advanced_clock: Mutex<Option<crate::FixedRuntimeScope>>,
}

impl SigningBackend for SigningProbe {
    fn algorithm(&self) -> SigningAlgorithm {
        self.inner.algorithm()
    }
    fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }
    fn sign_bytes(&self, message: &[u8]) -> Result<Signature, chio_core::Error> {
        self.inner.sign_bytes(message)
    }

    fn sign_bytes_for_identity(
        &self,
        key: &PublicKey,
        message: &[u8],
    ) -> Result<SigningOutcome, chio_core::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let sequencer = self.sequencer.clone();
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let acquired = sequencer.lock().is_ok();
            let _ = send.send(acquired);
        });
        let acquired = receive
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| chio_core::Error::InvalidSignature(error.to_string()))?;
        worker
            .join()
            .map_err(|_| chio_core::Error::InvalidSignature("probe worker panicked".into()))?;
        assert!(acquired, "signer callback inherited a poisoned sequencer");
        self.entered.fetch_add(1, Ordering::SeqCst);
        match self.mode {
            Mode::Reenter => self.inner.sign_bytes_for_identity(key, message),
            Mode::Panic => panic!("signer fault after unlocked callback"),
            // Deliberately violate the backend contract with a valid signature
            // from another key. The core must independently reject the result.
            Mode::Replace => self.replacement.sign_bytes_with_identity(message),
            Mode::Expire => {
                let advanced = crate::scope_fixed_runtime_for_current_thread(
                    current_unix_timestamp() + 61,
                    [],
                );
                *self
                    .advanced_clock
                    .lock()
                    .map_err(|_| chio_core::Error::InvalidSignature("clock lock".into()))? =
                    Some(advanced);
                self.inner.sign_bytes_for_identity(key, message)
            }
        }
    }
}

fn signing_callback(mode: Mode) -> TestResult {
    let (mut kernel, request, store, invocations) = durable_admission_fixture("signing-callback");
    let sequencer =
        AdmissionMutationSequencer::for_fence(&*store.fence.lock().map_err(|_| "fence lock")?)?;
    let probe = Arc::new(SigningProbe {
        inner: Ed25519Backend::new(kernel.config.keypair.clone()),
        replacement: Ed25519Backend::new(Keypair::generate()),
        sequencer: sequencer.clone(),
        mode,
        calls: AtomicUsize::new(0),
        entered: AtomicUsize::new(0),
        advanced_clock: Mutex::new(None),
    });
    kernel.signing_authority.backend = probe.clone();
    // Finalize on this thread so the injected clock scope is restored here too.
    let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
    let context = kernel.freeze_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut mutation,
        input(&request),
    )?;
    let returned = kernel.record_durable_tool_return(
        &mut admission,
        DurableToolReturnInput {
            request: &request,
            output: &ToolServerOutput::Value(serde_json::json!({"done": true})),
            reported_cost: None,
            context: &context,
            elapsed: Duration::ZERO,
            trusted_now_unix_ms: current_unix_timestamp_ms(),
        },
    )?;
    let result = kernel.finalize_durable_tool_return_with_security_release(
        &mut admission,
        &request,
        &returned,
        None,
    );
    drop(
        probe
            .advanced_clock
            .lock()
            .map_err(|_| "clock lock")?
            .take(),
    );
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(probe.entered.load(Ordering::SeqCst), 1);
    let _guard = sequencer.lock()?;
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    match mode {
        Mode::Reenter => {
            let response = result?;
            assert_eq!(response.verdict, Verdict::Allow);
            assert!(response.receipt.verify_signature()?);
            assert_eq!(
                store.operation().state(),
                AdmissionOperationState::Completed
            );
        }
        Mode::Panic | Mode::Replace | Mode::Expire => {
            assert!(result.is_err(), "callback fault published a receipt");
            if matches!(mode, Mode::Expire) {
                assert!(
                    matches!(result, Err(KernelError::DurableAdmission(_))),
                    "expiry must fail at the original lease readback: {result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(KernelError::ReceiptSigningFailed(_))),
                    "signing failure must be contained: {result:?}"
                );
            }
            assert_eq!(
                store.operation().state(),
                AdmissionOperationState::Finalizing
            );
            assert!(store
                .state
                .lock()
                .map_err(|_| "state lock")?
                .receipt
                .is_none());
        }
    }
    Ok(())
}

#[test]
fn signer_can_reenter_without_holding_the_mutation_sequencer() -> TestResult {
    signing_callback(Mode::Reenter)
}

#[test]
fn signer_panic_preserves_finalizing_without_poisoning_the_sequencer() -> TestResult {
    signing_callback(Mode::Panic)
}

#[test]
fn signer_identity_substitution_cannot_publish_a_terminal() -> TestResult {
    signing_callback(Mode::Replace)
}

#[test]
fn signer_callback_cannot_extend_the_original_finalization_lease() -> TestResult {
    signing_callback(Mode::Expire)
}
