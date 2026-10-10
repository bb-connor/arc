//! Recovery refuses only a replaced original signer per operation. Signing
//! backend faults and malformed retained identities stay global failures.

use super::*;
use crate::admission_operation::{
    AdmissionRecoveryError, AdmissionRecoveryFailureKind, AdmissionRecoveryPhase,
};
use crate::tool_outcome::FrozenReceiptSigningIdentityV1;
use chio_core::crypto::{Ed25519Backend, SigningAlgorithm, SigningBackend};
use chio_core::{PublicKey, Signature};

const SIGNER_UNAVAILABLE: &str = "original receipt signing authority is unavailable";

type Fixture<T> = Result<T, Box<dyn std::error::Error>>;

/// The live finalization lease has lapsed, so a startup sweep visits the
/// retained operation while the returned scope is held.
fn finalizing(
    name: &str,
) -> Fixture<(
    ChioKernel,
    Arc<TestAdmissionOperationStore>,
    chio_test_support::clock::ClockScope,
)> {
    let (kernel, request, store, invocations) = durable_admission_fixture(name);
    let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
    let context = kernel.freeze_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut mutation,
        input(&request),
    )?;
    kernel.record_durable_tool_return(
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
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let lapsed = chio_test_support::clock::scope_unix_secs(current_unix_timestamp() + 61);
    Ok((kernel, store, lapsed))
}

fn recovery_status(
    store: &TestAdmissionOperationStore,
) -> Fixture<Option<crate::admission_operation::AdmissionRecoveryStatusV1>> {
    Ok(store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .recovery_status
        .clone())
}

fn assert_signer_unavailable(result: Result<(), KernelError>) {
    assert!(
        matches!(
            &result,
            Err(KernelError::AdmissionRecovery(failure))
                if matches!(
                    failure.as_ref(),
                    AdmissionRecoveryError::Item {
                        kind: AdmissionRecoveryFailureKind::ContractChanged,
                        detail,
                    } if detail == SIGNER_UNAVAILABLE
                )
        ),
        "replaced signer must be an item contract change: {result:?}"
    );
}

#[test]
fn replaced_signer_defers_until_the_original_authority_returns() -> TestResult {
    let (mut kernel, store, _lapsed) = finalizing("replaced-signer-deferral")?;
    let original_key = kernel.receipt_signing_public_key();
    replace_receipt_authority(&mut kernel);
    assert_ne!(kernel.receipt_signing_public_key(), original_key);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
    let status = recovery_status(&store)?.ok_or("replaced signer deferral")?;
    assert!(status.quarantined);
    assert_eq!(
        status.deferral.failure_kind,
        AdmissionRecoveryFailureKind::ContractChanged
    );
    assert_eq!(status.deferral.phase, AdmissionRecoveryPhase::Returned);
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

    kernel.signing_authority =
        crate::kernel::signing_authority::KernelSigningAuthority::classical(&kernel.config.keypair);
    let _due = chio_test_support::clock::scope_unix_secs(
        status.deferral.retry_not_before_unix_ms / 1_000 + 1,
    );
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert!(
        !recovery_status(&store)?
            .ok_or("clear tombstone")?
            .quarantined
    );
    let receipt = store
        .state
        .lock()
        .map_err(|_| "state lock")?
        .receipt
        .clone()
        .ok_or("original signer receipt")?;
    assert_eq!(receipt.kernel_key, original_key);
    Ok(())
}

#[derive(Clone, Copy)]
enum BackendFault {
    MisreportedAlgorithm,
    PanickingKey,
}

/// Selects a key other than the retained one, then fails identity selection.
struct FaultyBackend {
    inner: Ed25519Backend,
    fault: BackendFault,
}

impl SigningBackend for FaultyBackend {
    fn algorithm(&self) -> SigningAlgorithm {
        match self.fault {
            BackendFault::MisreportedAlgorithm => SigningAlgorithm::Hybrid,
            BackendFault::PanickingKey => self.inner.algorithm(),
        }
    }

    fn public_key(&self) -> PublicKey {
        match self.fault {
            BackendFault::MisreportedAlgorithm => self.inner.public_key(),
            BackendFault::PanickingKey => panic!("signing backend key selection fault"),
        }
    }

    fn sign_bytes(&self, message: &[u8]) -> Result<Signature, chio_core::Error> {
        self.inner.sign_bytes(message)
    }
}

fn backend_fault_stays_global(fault: BackendFault, expected: &str) -> TestResult {
    let (mut kernel, store, _lapsed) = finalizing("signer-backend-fault")?;
    kernel.signing_authority.backend = Arc::new(FaultyBackend {
        inner: Ed25519Backend::new(Keypair::generate()),
        fault,
    });
    let result = kernel.reconcile_recoverable_admissions();
    assert!(
        matches!(&result, Err(KernelError::ReceiptSigningFailed(detail)) if detail == expected),
        "backend fault must abort recovery: {result:?}"
    );
    assert_eq!(recovery_status(&store)?, None);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    Ok(())
}

#[test]
fn misreported_backend_algorithm_stays_global_with_a_replaced_signer() -> TestResult {
    backend_fault_stays_global(
        BackendFault::MisreportedAlgorithm,
        "receipt signing identity changed during selection",
    )
}

#[test]
fn panicking_backend_key_selection_stays_global() -> TestResult {
    backend_fault_stays_global(
        BackendFault::PanickingKey,
        "receipt identity callback panicked",
    )
}

#[test]
fn malformed_retained_identity_stays_global_before_signer_comparison() -> TestResult {
    let (kernel, _, _, _) = durable_admission_fixture("malformed-retained-signer");
    let current = kernel.freeze_receipt_signing_identity()?;
    let expected =
        crate::tool_outcome::ToolOutcomeError::Binding("raw.receipt_signing_floor").to_string();
    for key in [
        kernel.receipt_signing_public_key(),
        Keypair::generate().public_key(),
    ] {
        let mut value = serde_json::to_value(&current)?;
        value["public_key"] = serde_json::to_value(&key)?;
        value["crypto_floor"] = serde_json::json!("pq_required");
        let malformed: FrozenReceiptSigningIdentityV1 = serde_json::from_value(value)?;
        let result = kernel.require_original_receipt_signer(&malformed);
        assert!(
            matches!(&result, Err(KernelError::ReceiptSigningFailed(detail)) if *detail == expected),
            "malformed identity must stay global: {result:?}"
        );
    }
    let replaced = FrozenReceiptSigningIdentityV1::new(
        Keypair::generate().public_key(),
        current.crypto_floor(),
    )?;
    assert_signer_unavailable(kernel.require_original_receipt_signer(&replaced));
    kernel.require_original_receipt_signer(&current)?;
    Ok(())
}
