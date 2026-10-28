//! Execution nonces are signed by the boot-selected receipt authority.

use super::*;
use crate::boot::{KernelSelfQuoteOutcome, KernelSelfQuoteVerifier};
use crate::execution_nonce::SignedExecutionNonce;
use chio_core::{PublicKey, SigningAlgorithm, SigningBackend};
use chio_core_types::receipt::authoritative_spend::{
    is_authoritative_spend_receipt, NotAuthoritativeReason, PresentedNonceView,
};

struct AcceptedQuote;

impl KernelSelfQuoteVerifier for AcceptedQuote {
    fn verify_self_quote(&self, quote: &[u8], _: &PublicKey) -> KernelSelfQuoteOutcome {
        assert_eq!(quote, b"nonce-signer-quote");
        KernelSelfQuoteOutcome::accepted()
    }
}

/// Boot `floor` and return the receipt signing backend it installed.
fn install_floor(kernel: &mut ChioKernel, floor: KernelCryptoFloor) -> Box<dyn SigningBackend> {
    kernel
        .with_hybrid_signing_backend(
            &HybridSigningConfig {
                crypto_floor: floor,
                pq_signing_seed: Some([73; 32]),
            },
            b"nonce-signer-quote",
            &AcceptedQuote,
        )
        .unwrap()
}

/// A capability the booted floor admits: under a hybrid floor the token is
/// reissued by the boot backend and that backend is trusted as an issuer.
fn admitted_capability(
    kernel: &mut ChioKernel,
    backend: &dyn SigningBackend,
    floor: KernelCryptoFloor,
    capability: CapabilityToken,
) -> CapabilityToken {
    if !floor.allows_hybrid() {
        return capability;
    }
    let issuer = backend.public_key().unwrap();
    let mut body = capability.body();
    body.issuer = issuer.clone();
    kernel.config.ca_public_keys.push(issuer);
    CapabilityToken::sign_with_backend(body, backend).unwrap()
}

fn expected_algorithm(floor: KernelCryptoFloor) -> SigningAlgorithm {
    if floor.allows_hybrid() {
        SigningAlgorithm::Hybrid
    } else {
        SigningAlgorithm::Ed25519
    }
}

/// The same nonce body carrying only the kernel's classical Ed25519 signature.
fn classical_only(kernel: &ChioKernel, nonce: &SignedExecutionNonce) -> SignedExecutionNonce {
    SignedExecutionNonce {
        nonce: nonce.nonce.clone(),
        signature: kernel
            .config
            .keypair
            .sign_wrapped(
                crate::execution_nonce::EXECUTION_NONCE_SCHEMA,
                &chio_core::canonical::CanonicalBytes::from_serializable(&nonce.nonce).unwrap(),
            )
            .unwrap(),
    }
}

fn assert_signed_by_receipt_authority(
    nonce: &SignedExecutionNonce,
    receipt_key: &PublicKey,
    floor: KernelCryptoFloor,
) {
    assert_eq!(nonce.signature.algorithm(), expected_algorithm(floor));
    assert!(nonce.verify_signed_by(receipt_key));
}

fn reconcile_is_authoritative_under(floor: KernelCryptoFloor) {
    let (mut kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let backend = install_floor(&mut kernel, floor);
    let receipt_key = backend.public_key().unwrap();
    let cap = admitted_capability(&mut kernel, backend.as_ref(), floor, cap);
    let request = reserve_request("req-signer-reconcile", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(
        authorized.verdict,
        Verdict::Allow,
        "{:?}",
        authorized.reason
    );
    assert_eq!(authorized.receipt.kernel_key, receipt_key);
    let nonce = *authorized.execution_nonce.clone().unwrap();
    assert_signed_by_receipt_authority(&nonce, &receipt_key, floor);

    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let classical = classical_only(&kernel, &nonce);
    if floor.allows_hybrid() {
        let error = kernel
            .reconcile_reserved_authorization_by_nonce(&classical, &request.arguments, &realized)
            .unwrap_err();
        assert!(
            matches!(
                &error,
                KernelError::Internal(message)
                    if message == "reconcile-by-nonce rejected the nonce: execution nonce signature is invalid"
            ),
            "{error:?}"
        );
    }
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &request.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);
    assert_eq!(reconciled.receipt.kernel_key, receipt_key);

    let admitted = [receipt_key];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
    if floor.allows_hybrid() {
        assert_eq!(
            is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &classical),
            Err(NotAuthoritativeReason::NonceSignatureInvalid)
        );
    }
}

fn ordinary_allow_nonce_is_signed_under(floor: KernelCryptoFloor) {
    let (mut kernel, agent_kp, scope, _cfg) = kernel_with_nonce();
    let backend = install_floor(&mut kernel, floor);
    let receipt_key = backend.public_key().unwrap();
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), scope, 3600)
        .unwrap();
    let cap = admitted_capability(&mut kernel, backend.as_ref(), floor, cap);
    let request = make_request("req-signer-allow", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(response.receipt.kernel_key, receipt_key);
    let nonce = *response.execution_nonce.clone().unwrap();
    assert_signed_by_receipt_authority(&nonce, &receipt_key, floor);

    let binding = binding_for_request(&cap, &request);
    if floor.allows_hybrid() {
        assert!(matches!(
            kernel.verify_presented_execution_nonce(&classical_only(&kernel, &nonce), &binding),
            Err(ExecutionNonceError::InvalidSignature)
        ));
    }
    kernel
        .verify_presented_execution_nonce(&nonce, &binding)
        .unwrap();
}

fn monetary_completion_nonce_is_signed_under(floor: KernelCryptoFloor) {
    let mut kernel = make_kernel(make_monetary_config());
    let backend = install_floor(&mut kernel, floor);
    let receipt_key = backend.public_key().unwrap();
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let cap = admitted_capability(&mut kernel, backend.as_ref(), floor, cap);
    let request = reserve_request("req-signer-monetary", &cap, &agent_kp);
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(response.receipt.kernel_key, receipt_key);
    let nonce = response.execution_nonce.as_deref().unwrap();
    assert_signed_by_receipt_authority(nonce, &receipt_key, floor);
}

fn strict_presented_nonce_is_admitted_under(floor: KernelCryptoFloor) {
    let (mut kernel, agent_kp, scope, cfg) = kernel_with_nonce();
    let backend = install_floor(&mut kernel, floor);
    install_strict_nonce_store(&mut kernel);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), scope, 3600)
        .unwrap();
    let cap = admitted_capability(&mut kernel, backend.as_ref(), floor, cap);
    let mut request = make_request("req-signer-strict", &cap, "read_file", "srv-a");
    let nonce = mint_nonce_for_request(&kernel, &cap, &request, &cfg);
    if floor.allows_hybrid() {
        request.execution_nonce = Some(classical_only(&kernel, &nonce));
        let denied = kernel.evaluate_tool_call_blocking(&request).unwrap();
        assert_eq!(denied.verdict, Verdict::Deny);
    }
    request.execution_nonce = Some(nonce);
    let admitted = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(admitted.verdict, Verdict::Allow, "{:?}", admitted.reason);
}

#[test]
fn classical_floor_signs_execution_nonces_with_the_receipt_authority() {
    reconcile_is_authoritative_under(KernelCryptoFloor::AllowClassical);
    ordinary_allow_nonce_is_signed_under(KernelCryptoFloor::AllowClassical);
    monetary_completion_nonce_is_signed_under(KernelCryptoFloor::AllowClassical);
    strict_presented_nonce_is_admitted_under(KernelCryptoFloor::AllowClassical);
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_floor_signs_execution_nonces_with_the_receipt_authority() {
    reconcile_is_authoritative_under(KernelCryptoFloor::AllowHybrid);
    ordinary_allow_nonce_is_signed_under(KernelCryptoFloor::AllowHybrid);
    monetary_completion_nonce_is_signed_under(KernelCryptoFloor::AllowHybrid);
    strict_presented_nonce_is_admitted_under(KernelCryptoFloor::AllowHybrid);
}

#[cfg(feature = "pq")]
#[test]
fn pq_floor_signs_execution_nonces_with_the_receipt_authority() {
    reconcile_is_authoritative_under(KernelCryptoFloor::PqRequired);
    ordinary_allow_nonce_is_signed_under(KernelCryptoFloor::PqRequired);
    monetary_completion_nonce_is_signed_under(KernelCryptoFloor::PqRequired);
    strict_presented_nonce_is_admitted_under(KernelCryptoFloor::PqRequired);
}
