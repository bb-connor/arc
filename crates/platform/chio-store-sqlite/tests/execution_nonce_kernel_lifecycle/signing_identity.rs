use super::*;
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core::SigningAlgorithm;
use chio_kernel::{HybridSigningConfig, KernelCryptoFloor};
use std::sync::Arc;

fn durable_nonce_lifecycle_under(floor: KernelCryptoFloor) -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.signing = Some(HybridSigningConfig {
        crypto_floor: floor,
        pq_signing_seed: Some([77; 32]),
    });
    let runtime = fixture.open()?;
    let key = runtime.kernel.receipt_signing_public_key()?;
    assert_eq!(key.algorithm(), SigningAlgorithm::Hybrid);
    let request = fixture.request(&runtime, "durable-hybrid-signing")?;
    assert_eq!(request.capability.issuer, key);
    assert!(request.capability.verify_signature()?);
    let nonce = preflight(&runtime, &request)?;
    let (operation_id, _) =
        operation_state(&fixture, &request.request_id)?.ok_or("nonce operation")?;
    let operation_id =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(operation_id)?;
    chio_kernel::admission_operation::verify_operation_execution_nonce_at(
        &nonce,
        &operation_id,
        &key,
        &nonce.nonce.bound_to,
        nonce.nonce.issued_at,
    )?;
    assert_eq!(nonce.signature.algorithm(), SigningAlgorithm::Hybrid);
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_issuances")?,
        1
    );
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_reservations")?,
        0
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_state(&fixture, &request, "prepared")?;
    drop(runtime);

    let runtime = fixture.open()?;
    assert_eq!(runtime.kernel.receipt_signing_public_key()?, key);
    let redelivered = preflight(&runtime, &request)?;
    assert_eq!(redelivered, nonce);
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_issuances")?,
        1
    );
    let executed = execute(&runtime, &request, &redelivered)?;
    assert_eq!(executed.verdict, Verdict::Allow, "{:?}", executed.reason);
    assert_eq!(executed.receipt.kernel_key, key);
    assert!(executed
        .receipt
        .verify_signature_with_floor(ReceiptCryptoFloor::PqRequired)?);
    assert_state(&fixture, &request, "completed")?;
    assert_eq!(
        count_rows(&fixture, "admission_execution_nonce_reservations")?,
        1
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let connection = rusqlite::Connection::open(fixture.database())?;
    for table in [
        "admission_execution_nonce_issuances",
        "admission_execution_nonce_reservations",
    ] {
        let issuer: String =
            connection.query_row(&format!("SELECT issuer FROM {table}"), [], |row| row.get(0))?;
        assert_eq!(issuer, key.to_hex());
        assert!(issuer.len() > 64 && issuer.len() <= 4129);
    }
    let replay = execute(&runtime, &request, &redelivered)?;
    assert_eq!(replay.receipt.id, executed.receipt.id);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn durable_hybrid_nonce_survives_restart_and_completes() -> TestResult {
    durable_nonce_lifecycle_under(KernelCryptoFloor::AllowHybrid)
}

#[test]
fn durable_pq_required_nonce_survives_restart_and_completes() -> TestResult {
    durable_nonce_lifecycle_under(KernelCryptoFloor::PqRequired)
}

#[test]
fn changed_receipt_backend_refuses_before_durable_nonce_mutation() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.signing = Some(HybridSigningConfig {
        crypto_floor: KernelCryptoFloor::PqRequired,
        pq_signing_seed: Some([77; 32]),
    });
    let mut runtime = fixture.open()?;
    let request = fixture.request(&runtime, "changed-durable-signing")?;
    assert!(request.capability.verify_signature()?);
    let original_key = runtime.kernel.receipt_signing_public_key()?;
    let changed = HybridSigningConfig {
        crypto_floor: KernelCryptoFloor::PqRequired,
        pq_signing_seed: Some([78; 32]),
    };
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
    kernel.with_hybrid_signing_backend(
        &changed,
        b"durable-nonce-signing-quote",
        &support::AcceptedSigningQuote(fixture.signer.public_key()),
    )?;
    assert_ne!(kernel.receipt_signing_public_key()?, original_key);
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("changed backend admitted nonce")?;
    assert!(
        matches!(
            error,
            chio_kernel::KernelError::AdmissionRecovery(ref recovery)
                if matches!(recovery.as_ref(), chio_kernel::admission_operation::AdmissionRecoveryError::Item {
                    kind: chio_kernel::admission_operation::AdmissionRecoveryFailureKind::ContractChanged,
                    detail,
                } if detail == "durable admission signing identity changed")
        ),
        "{error}"
    );
    assert!(operation_state(&fixture, &request.request_id)?.is_none());
    for table in [
        "admission_nonce_preflight_holds",
        "admission_execution_nonce_issuances",
        "admission_execution_nonce_reservations",
        "budget_authorization_holds",
    ] {
        assert_eq!(count_rows(&fixture, table)?, 0);
    }
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let kernel = Arc::get_mut(&mut runtime.kernel).ok_or("unique kernel")?;
    kernel.with_hybrid_signing_backend(
        fixture.signing.as_ref().ok_or("original signing config")?,
        b"durable-nonce-signing-quote",
        &support::AcceptedSigningQuote(fixture.signer.public_key()),
    )?;
    let nonce = preflight(&runtime, &request)?;
    let (operation_id, _) =
        operation_state(&fixture, &request.request_id)?.ok_or("nonce operation")?;
    let operation_id =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(operation_id)?;
    chio_kernel::admission_operation::verify_operation_execution_nonce_at(
        &nonce,
        &operation_id,
        &original_key,
        &nonce.nonce.bound_to,
        nonce.nonce.issued_at,
    )?;
    Ok(())
}
