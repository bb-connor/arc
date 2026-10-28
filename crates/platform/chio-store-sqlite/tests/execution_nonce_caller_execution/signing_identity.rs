use super::*;
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_kernel::{HybridSigningConfig, KernelCryptoFloor};

fn caller_lifecycle_under(floor: KernelCryptoFloor) -> TestResult {
    let mut fixture = caller_fixture()?;
    fixture.signing = Some(HybridSigningConfig {
        crypto_floor: floor,
        pq_signing_seed: Some([79; 32]),
    });
    let runtime = fixture.open()?;
    let key = runtime.kernel.receipt_signing_public_key()?;
    let execution = reserve(&fixture, &runtime, "hybrid-caller-restart")?;
    assert!(execution.capability.verify_signature()?);
    assert_eq!(execution.capability.issuer, key);
    drop(runtime);
    let runtime = fixture.open()?;
    assert_eq!(runtime.kernel.receipt_signing_public_key()?, key);
    let settled = reconcile(&fixture, &runtime, &execution)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert_eq!(settled.terminal_state, OperationTerminalState::Completed);
    assert_eq!(settled.receipt.kernel_key, key);
    assert!(settled
        .receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::PqRequired)?);
    assert_state(&fixture, &execution, "completed")?;
    assert_eq!(grant_quota(&runtime, &execution)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let replay = reconcile(&fixture, &runtime, &execution)?;
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    Ok(())
}

#[test]
fn hybrid_nonce_caller_return_survives_restart() -> TestResult {
    caller_lifecycle_under(KernelCryptoFloor::AllowHybrid)
}

#[test]
fn pq_required_nonce_caller_return_survives_restart() -> TestResult {
    caller_lifecycle_under(KernelCryptoFloor::PqRequired)
}
