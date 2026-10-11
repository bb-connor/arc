use super::*;
use chio_core::{PublicKey, SigningAlgorithm, SigningBackend};
use chio_kernel::boot::{KernelSelfQuoteOutcome, KernelSelfQuoteVerifier};
use chio_kernel::{HybridSigningConfig, KernelCryptoFloor};

struct QuoteVerifier(PublicKey);
impl KernelSelfQuoteVerifier for QuoteVerifier {
    fn verify_self_quote(&self, quote: &[u8], key: &PublicKey) -> KernelSelfQuoteOutcome {
        assert_eq!(quote, b"payload-maintenance-hybrid-quote");
        assert_eq!(key, &self.0);
        KernelSelfQuoteOutcome::accepted()
    }
}

fn configure_hybrid(kernel: &mut ChioKernel) -> Result<Box<dyn SigningBackend>, Box<dyn Error>> {
    let verifier = QuoteVerifier(kernel.public_key());
    Ok(kernel.with_hybrid_signing_backend(
        &HybridSigningConfig {
            crypto_floor: KernelCryptoFloor::AllowHybrid,
            pq_signing_seed: Some([61; 32]),
        },
        b"payload-maintenance-hybrid-quote",
        &verifier,
    )?)
}

#[test]
fn compacted_payload_holds_actual_boot_selected_hybrid_receipt_and_cold_replay() -> TestResult {
    let initial = chio_test_support::clock::unix_seconds();
    let _time = chio_test_support::clock::scope_unix_secs(initial);
    let directory = private_tempdir()?;
    let database = directory.path().join("hybrid-held-maintenance.db");
    let runtime =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let calls = Arc::new(AtomicU64::new(0));
    let mut kernel = configured_kernel(&runtime, calls.clone())?;
    let backend = configure_hybrid(&mut kernel)?;
    let request = request_with_credentials(
        &kernel,
        &runtime.kernel_keypair(),
        "hybrid-held-maintenance",
    )?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(response.receipt.kernel_key, backend.public_key());
    assert_ne!(response.receipt.kernel_key, kernel.public_key());
    assert_eq!(response.receipt.algorithm, Some(SigningAlgorithm::Hybrid));
    assert!(response.receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowHybrid
    )?);
    let metadata = receipt_operation(&response.receipt)?;
    let authority = runtime.local_authority_store().ok_or("missing authority")?;
    let outcome = authority
        .tool_outcome_store()
        .lookup_by_operation(&metadata.operation_id)?
        .ok_or("missing outcome")?;
    let digest = outcome.raw_output_digest().as_str().to_owned();
    let _advanced = chio_test_support::clock::scope_unix_secs(initial + 60);
    runtime.start_terminal_payload_maintenance(test_maintenance_config())?;
    let health = wait_for_health(&runtime, |health| health.ticks_completed > 0)?;
    assert!(raw_payload_present(&database, &digest)?, "a real boot-selected hybrid signer remains held until erased-identity replay is supported: {health:?}");
    assert!(health
        .last_page
        .as_ref()
        .is_some_and(|page| page.retained_unsupported > 0));
    assert_eq!(
        health.lifecycle,
        TerminalPayloadMaintenanceLifecycle::Degraded
    );
    runtime.shutdown_terminal_payload_maintenance()?;
    drop(authority);
    drop(backend);
    drop(kernel);
    drop(runtime);
    let reopened =
        DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
    let mut recovered = configured_kernel(&reopened, calls.clone())?;
    configure_hybrid(&mut recovered)?;
    let replay = recovered.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
