use super::*;

#[test]
fn merkle_release_refuses_anchor_receipt_from_untrusted_kernel_key() {
    let proof = sample_primary_proof();
    let mut dispatch = sample_dispatch();
    dispatch.escrow_id =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let mut config = sample_config();
    config.chain_id = dispatch.chain_id.clone();
    config.escrow_contract = dispatch.escrow_contract.clone();
    align_config_to_anchor_proof(&mut config, &proof);
    prepare_merkle_release(
        &config,
        &dispatch,
        &proof,
        &sample_anchor_content_binding(),
        EscrowExecutionAmount::Full,
    )
    .test_expect("a receipt from a trusted kernel key should prepare");

    config.kernel_authority.trusted_keys = vec![instruction_keypair().public_key()];
    assert_ne!(proof.receipt.kernel_key, instruction_keypair().public_key());
    let error = prepare_merkle_release(
        &config,
        &dispatch,
        &proof,
        &sample_anchor_content_binding(),
        EscrowExecutionAmount::Full,
    )
    .test_expect_err("an untrusted kernel key should block merkle release prep");
    assert!(
        matches!(
            &error,
            SettlementError::Verification(message)
                if message == "receipt kernel_key is not a trusted settlement kernel key"
        ),
        "{error:?}"
    );
}
