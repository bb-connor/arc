use super::*;
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core::SigningAlgorithm;
use chio_kernel::{HybridSigningConfig, KernelCryptoFloor};

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
    assert!(nonce.verify_signed_by(&key));
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
