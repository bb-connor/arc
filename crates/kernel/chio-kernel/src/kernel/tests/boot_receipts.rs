//! Boot-selected receipt authority through production signing and replay paths.

use super::*;
use crate::boot::{KernelSelfQuoteOutcome, KernelSelfQuoteVerifier};
#[cfg(feature = "pq")]
use chio_core::SigningAlgorithm;
use chio_core::{PublicKey, SigningBackend};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const CONTENT: &[u8] = br#"{"result":"boot-receipt"}"#;

struct QuoteVerifier(PublicKey);

impl KernelSelfQuoteVerifier for QuoteVerifier {
    fn verify_self_quote(&self, quote: &[u8], key: &PublicKey) -> KernelSelfQuoteOutcome {
        assert_eq!(quote, b"boot-receipt-quote");
        assert_eq!(key, &self.0);
        KernelSelfQuoteOutcome::accepted()
    }
}

fn configure(
    kernel: &mut ChioKernel,
    floor: KernelCryptoFloor,
) -> TestResult<Box<dyn SigningBackend>> {
    let verifier = QuoteVerifier(kernel.config.keypair.public_key());
    Ok(kernel.with_hybrid_signing_backend(
        &HybridSigningConfig {
            crypto_floor: floor,
            pq_signing_seed: Some([61; 32]),
        },
        b"boot-receipt-quote",
        &verifier,
    )?)
}

fn params(content: &[u8]) -> TestResult<ReceiptParams<'static>> {
    Ok(ReceiptParams {
        request_id: Some("boot-receipt-request"),
        capability_id: "boot-receipt-capability",
        tool_name: "read_file",
        server_id: "srv-a",
        decision: Decision::Allow,
        action: ToolCallAction::from_parameters(serde_json::json!({"path": "/allowed"}))?,
        content_hash: sha256_hex(CONTENT),
        canonical_content: content.to_vec(),
        metadata: None,
        timestamp: 1_800_000_000,
        trust_level: chio_core::receipt::kinds::TrustLevel::Mediated,
        tenant_id: None,
    })
}

fn original_signing_body(receipt: &ChioReceipt) -> TestResult<ChioReceiptBody> {
    let mut body = receipt.body();
    body.id = body
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.get(chio_core::receipt::signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY)
        })
        .and_then(serde_json::Value::as_str)
        .ok_or("receipt omitted original signing nonce")?
        .to_owned();
    Ok(body)
}

#[test]
fn classical_inline_and_channel_receipts_remain_identical() -> TestResult {
    let mut kernel = make_kernel(make_config());
    configure(&mut kernel, KernelCryptoFloor::AllowClassical)?;
    let inline = kernel.build_and_sign_receipt(params(CONTENT)?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let channel = runtime.block_on(
        kernel.sign_receipt_via_channel(original_signing_body(&inline)?, CONTENT.to_vec()),
    )?;
    assert!(canonical_json_bytes(&inline)? == canonical_json_bytes(&channel)?);
    assert!(inline.verify_signature()?);
    runtime.block_on(kernel.shutdown());
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_inline_receipt_uses_boot_verified_authority() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let receipt = kernel.build_and_sign_receipt(params(CONTENT)?)?;
    assert!(
        receipt.kernel_key == backend.public_key(),
        "inline signer ignored boot authority"
    );
    assert_eq!(receipt.algorithm, Some(SigningAlgorithm::Hybrid));
    assert!(receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired,
    )?);
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_channel_receipt_uses_boot_verified_authority() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let body = kernel.build_and_sign_receipt(params(CONTENT)?)?.body();
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let body = ChioReceiptBody {
        kernel_key: backend.public_key(),
        ..body
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let receipt = runtime.block_on(kernel.sign_receipt_via_channel(body, CONTENT.to_vec()))?;
    assert_eq!(receipt.kernel_key, backend.public_key());
    assert_eq!(receipt.algorithm, Some(SigningAlgorithm::Hybrid));
    assert!(receipt.verify_signature()?);
    runtime.block_on(kernel.shutdown());
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_durable_dispatch_and_replay_retain_original_receipt() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("boot-receipt-replay");
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let first = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(first.verdict, Verdict::Allow, "{:?}", first.reason);
    assert!(
        first.receipt.kernel_key == backend.public_key(),
        "dispatch ignored boot authority"
    );
    assert!(first.receipt.verify_signature()?);
    let second = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(second.verdict, Verdict::Allow, "{:?}", second.reason);
    assert_eq!(
        canonical_json_bytes(&first.receipt)?,
        canonical_json_bytes(&second.receipt)?
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn pq_required_capability_dispatch_produces_pq_receipt() -> TestResult {
    let (mut kernel, mut request, _, invocations) = durable_admission_fixture("boot-pq-dispatch");
    let backend = configure(&mut kernel, KernelCryptoFloor::PqRequired)?;
    let mut capability = request.capability.body();
    capability.issuer = backend.public_key();
    kernel.config.ca_public_keys.push(backend.public_key());
    request.capability = CapabilityToken::sign_with_backend(capability, backend.as_ref())?;
    let first = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(first.verdict, Verdict::Allow, "{:?}", first.reason);
    assert!(first.receipt.kernel_key == backend.public_key());
    assert!(first.receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired,
    )?);
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert!(canonical_json_bytes(&first.receipt)? == canonical_json_bytes(&replay.receipt)?);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn pq_boot_denial_is_signed_without_dispatch() -> TestResult {
    let (mut kernel, request, _, invocations) = durable_admission_fixture("boot-pq-denial");
    let backend = configure(&mut kernel, KernelCryptoFloor::PqRequired)?;
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.kernel_key == backend.public_key());
    assert!(response.receipt.verify_signature_with_floor(
        chio_core::receipt::crypto_floor::ReceiptCryptoFloor::PqRequired,
    )?);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_inline_signer_refuses_changed_content() -> TestResult {
    let mut kernel = make_kernel(make_config());
    configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let error = kernel
        .build_and_sign_receipt(params(b"different output")?)
        .err()
        .ok_or("inline signer accepted changed content")?;
    assert!(
        matches!(error, KernelError::ReceiptSigningFailed(reason) if reason.contains("WYSIWYS refused"))
    );
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_channel_and_budget_fallback_refuse_changed_content() -> TestResult {
    for max_stream_total_bytes in [1, 1024] {
        let mut config = make_config();
        config.max_stream_total_bytes = max_stream_total_bytes;
        let mut kernel = make_kernel(config);
        configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
        let body = original_signing_body(&kernel.build_and_sign_receipt(params(CONTENT)?)?)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let error = runtime
            .block_on(kernel.sign_receipt_via_channel(body, b"different output".to_vec()))
            .err()
            .ok_or("channel signer accepted changed content")?;
        assert!(
            matches!(error, KernelError::ReceiptSigningFailed(reason) if reason.contains("WYSIWYS refused"))
        );
        assert_eq!(
            kernel.signing_task_handle().is_spawned(),
            max_stream_total_bytes > 1
        );
        runtime.block_on(kernel.shutdown());
    }
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_budget_fallback_preserves_authority_and_byte_identity() -> TestResult {
    let mut config = make_config();
    config.max_stream_total_bytes = 1;
    let mut kernel = make_kernel(config);
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let inline = kernel.build_and_sign_receipt(params(CONTENT)?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let channel = runtime.block_on(
        kernel.sign_receipt_via_channel(original_signing_body(&inline)?, CONTENT.to_vec()),
    )?;
    assert!(
        !kernel.signing_task_handle().is_spawned(),
        "oversized preimage must use the bounded-memory fallback"
    );
    assert!(channel.kernel_key == backend.public_key());
    assert!(channel.verify_signature()?);
    // ML-DSA uses randomized signatures. Both paths must bind the same canonical
    // body, not manufacture an identical fresh signature.
    assert!(canonical_json_bytes(&inline.body())? == canonical_json_bytes(&channel.body())?);
    runtime.block_on(kernel.shutdown());
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_channel_refuses_stale_classical_identity() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let body = original_signing_body(&kernel.build_and_sign_receipt(params(CONTENT)?)?)?;
    configure(&mut kernel, KernelCryptoFloor::PqRequired)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let error = runtime
        .block_on(kernel.sign_receipt_via_channel(body, CONTENT.to_vec()))
        .err()
        .ok_or("channel fell back to the classical authority")?;
    assert!(
        matches!(error, KernelError::ReceiptSigningFailed(reason) if reason.contains("kernel_key"))
    );
    runtime.block_on(kernel.shutdown());
    Ok(())
}

#[test]
fn boot_reconfiguration_preserves_channel_shutdown() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let body = original_signing_body(&kernel.build_and_sign_receipt(params(CONTENT)?)?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(kernel.shutdown());
    configure(&mut kernel, KernelCryptoFloor::AllowClassical)?;
    let error = runtime
        .block_on(kernel.sign_receipt_via_channel(body, CONTENT.to_vec()))
        .err()
        .ok_or("boot configuration reopened a shut down signing queue")?;
    assert!(matches!(error, KernelError::Internal(reason) if reason.contains("shut down")));
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn dropped_boot_handle_preserves_receipt_authority_without_issuer_trust() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let classical = kernel.public_key();
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let key = backend.public_key();
    drop(backend);
    assert!(kernel.receipt_signing_public_key() == key);
    assert!(kernel.public_key() == classical);
    assert!(!kernel.capability_issuer_is_trusted(&key));
    let receipt = kernel.build_and_sign_receipt(params(CONTENT)?)?;
    assert!(receipt.kernel_key == key);
    assert!(receipt.verify_signature()?);
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn retained_hybrid_receipt_requires_original_authority_without_redispatch() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("boot-receipt-authority-replay");
    configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let first = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(first.verdict, Verdict::Allow);
    configure(&mut kernel, KernelCryptoFloor::AllowClassical)?;
    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert!(canonical_json_bytes(&first.receipt)? == canonical_json_bytes(&replay.receipt)?);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_full_queue_fallback_uses_same_authority() -> TestResult {
    use std::future::Future;
    use std::task::{Context, Poll, Wake, Waker};
    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    let mut kernel = make_kernel(make_config());
    kernel.signing_task = Arc::new(
        crate::kernel::signing_task::SigningTaskHandle::with_backend_and_limits(
            Arc::clone(&kernel.signing_authority.backend),
            1,
            0,
            CONTENT.len() * 4,
        ),
    );
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    assert_eq!(kernel.signing_task_handle().capacity(), 1);
    let inline = kernel.build_and_sign_receipt(params(CONTENT)?)?;
    let body = original_signing_body(&inline)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut first = Box::pin(kernel.sign_receipt_via_channel(body.clone(), CONTENT.to_vec()));
        assert!(matches!(first.as_mut().poll(&mut context), Poll::Pending));
        let mut second = Box::pin(kernel.sign_receipt_via_channel(body, CONTENT.to_vec()));
        let Poll::Ready(result) = second.as_mut().poll(&mut context) else {
            return Err("full queue parked instead of using the bounded-memory fallback".into());
        };
        let fallback = result?;
        let queued = first.await?;
        assert!(fallback.kernel_key == backend.public_key());
        assert!(queued.kernel_key == backend.public_key());
        assert!(fallback.verify_signature()? && queued.verify_signature()?);
        assert!(canonical_json_bytes(&fallback.body())? == canonical_json_bytes(&queued.body())?);
        kernel.shutdown().await;
        TestResult::Ok(())
    })
}

#[cfg(feature = "pq")]
#[test]
fn failed_boot_quote_preserves_running_receipt_signer() -> TestResult {
    struct RejectedQuote;
    impl KernelSelfQuoteVerifier for RejectedQuote {
        fn verify_self_quote(&self, _: &[u8], _: &PublicKey) -> KernelSelfQuoteOutcome {
            KernelSelfQuoteOutcome::rejected("test rejected quote")
        }
    }
    let mut kernel = make_kernel(make_config());
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let inline = kernel.build_and_sign_receipt(params(CONTENT)?)?;
    let body = original_signing_body(&inline)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(kernel.sign_receipt_via_channel(body.clone(), CONTENT.to_vec()))?;
    assert!(kernel.signing_task_handle().is_spawned());
    let previous_task = Arc::clone(&kernel.signing_task);
    assert!(kernel
        .with_hybrid_signing_backend(
            &HybridSigningConfig {
                crypto_floor: KernelCryptoFloor::PqRequired,
                pq_signing_seed: Some([62; 32])
            },
            b"rejected quote",
            &RejectedQuote,
        )
        .is_err());
    assert!(Arc::ptr_eq(&previous_task, &kernel.signing_task));
    assert_eq!(
        kernel.capability_crypto_floor,
        KernelCryptoFloor::AllowHybrid
    );
    let receipt = runtime.block_on(kernel.sign_receipt_via_channel(body, CONTENT.to_vec()))?;
    assert!(receipt.kernel_key == backend.public_key());
    assert!(receipt.verify_signature()?);
    runtime.block_on(kernel.shutdown());
    Ok(())
}

#[cfg(feature = "pq")]
#[test]
fn failed_receipt_signing_recovers_tool_outcome_without_redispatch() -> TestResult {
    struct UnavailableSigner(PublicKey);
    impl SigningBackend for UnavailableSigner {
        fn algorithm(&self) -> SigningAlgorithm {
            self.0.algorithm()
        }
        fn public_key(&self) -> PublicKey {
            self.0.clone()
        }
        fn sign_bytes(&self, _: &[u8]) -> Result<chio_core::Signature, chio_core::Error> {
            Err(chio_core::Error::InvalidSignature(
                "injected signing outage".into(),
            ))
        }
    }
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("boot-receipt-signing-recovery");
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    kernel.signing_authority.backend = Arc::new(UnavailableSigner(backend.public_key()));
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .err()
        .ok_or("unavailable receipt signer fell back to another authority")?;
    assert!(
        matches!(error, KernelError::ReceiptSigningFailed(reason) if reason.contains("injected signing outage"))
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_ne!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let recovered = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(recovered.verdict, Verdict::Allow, "{:?}", recovered.reason);
    assert!(recovered.receipt.kernel_key == backend.public_key());
    assert!(recovered.receipt.verify_signature()?);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert!(canonical_json_bytes(&recovered.receipt)? == canonical_json_bytes(&replay.receipt)?);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    Ok(())
}

#[test]
fn capability_only_floor_setter_does_not_reconfigure_receipt_authority() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let previous_key = kernel.receipt_signing_public_key();
    kernel.set_capability_crypto_floor(KernelCryptoFloor::PqRequired);
    let receipt = kernel.build_and_sign_receipt(params(CONTENT)?)?;
    assert!(receipt.kernel_key == previous_key);
    assert!(receipt.verify_signature()?);
    assert_eq!(
        kernel.signing_authority.floor,
        KernelCryptoFloor::AllowClassical
    );
    Ok(())
}

#[cfg(all(feature = "pq", feature = "finding-market"))]
fn pool_mutation() -> crate::finding_pool::FindingPoolMutation {
    use crate::finding_pool::*;
    FindingPoolMutation {
        schema: FINDING_POOL_MUTATION_SCHEMA_V1.into(),
        kind: FindingPoolMutationKind::ExpiredRelease,
        purchase_id: "boot-receipt-purchase".into(),
        tenant_id: Some("boot-receipt-tenant".into()),
        allocation_id: "boot-receipt-allocation".into(),
        allocation_envelope_sha256: "a".repeat(64),
        amount_units: "25".into(),
        currency: "USD".into(),
        state: FindingPoolDebitState::Released,
        reserved_after_units: "0".into(),
        spent_after_units: "0".into(),
        remaining_after_units: "75".into(),
        occurred_at_unix_ms: "1800000000000".into(),
        durable_admission_operation_id: Some("boot-receipt-operation".into()),
    }
}

#[cfg(all(feature = "pq", feature = "finding-market"))]
#[test]
fn hybrid_boot_preserves_separate_pool_receipt_authority() -> TestResult {
    let mut kernel = make_kernel(make_config());
    let pool_key = CoreKeypair::from_seed(&[63; 32]);
    kernel.set_finding_pool_receipt_authority(pool_key.clone())?;
    let backend = configure(&mut kernel, KernelCryptoFloor::AllowHybrid)?;
    let receipt = kernel.build_finding_pool_mutation_receipt(&pool_mutation())?;
    assert!(receipt.kernel_key == pool_key.public_key());
    assert!(receipt.kernel_key != backend.public_key());
    assert_eq!(receipt.tenant_id.as_deref(), Some("boot-receipt-tenant"));
    assert!(receipt.verify_signature()?);
    Ok(())
}

#[cfg(all(feature = "pq", feature = "finding-market"))]
#[test]
fn pq_boot_refuses_classical_pool_authority_without_substitution() -> TestResult {
    let mut kernel = make_kernel(make_config());
    kernel.set_finding_pool_receipt_authority(CoreKeypair::from_seed(&[63; 32]))?;
    configure(&mut kernel, KernelCryptoFloor::PqRequired)?;
    let error = kernel
        .build_finding_pool_mutation_receipt(&pool_mutation())
        .err()
        .ok_or("PQ profile accepted or substituted the classical pool signer")?;
    assert!(
        matches!(error, KernelError::ReceiptSigningFailed(reason) if reason.contains("boot signing floor"))
    );
    Ok(())
}
