use super::*;

#[test]
fn durable_nonce_identity_unreadable_signer_refuses_attachment() {
    let mut kernel = make_kernel(make_config());
    let fence = admission_test_fence();
    let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel.signing_authority.backend =
        Arc::new(crate::authority::tests::UnreadableSelectorBackend(
            chio_core::crypto::Ed25519Backend::new(Keypair::from_seed(&[63; 32])),
        ));
    let result = kernel.set_durable_admission_store(store.clone(), store, fence);
    assert_eq!(
        result,
        Err(crate::admission_operation::AdmissionOperationError::ReceiptSigningIdentityUnavailable)
    );
    assert!(!kernel.has_durable_admission_store());
}

#[test]
fn durable_nonce_identity_below_floor_refuses_attachment() {
    let mut kernel = make_kernel(make_config());
    let fence = admission_test_fence();
    let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel.signing_authority.floor = KernelCryptoFloor::PqRequired;
    let result = kernel.set_durable_admission_store(store.clone(), store, fence);
    assert_eq!(
        result,
        Err(crate::admission_operation::AdmissionOperationError::ReceiptSigningIdentityUnavailable)
    );
    assert!(!kernel.has_durable_admission_store());
}

#[test]
fn durable_nonce_identity_readable_classical_signer_attaches(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let fence = admission_test_fence();
    let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel.set_durable_admission_store(store.clone(), store, fence)?;
    assert!(kernel.has_durable_admission_store());
    Ok(())
}
