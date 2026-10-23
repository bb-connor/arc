use super::*;

#[tokio::test]
async fn dual_sign_release_refuses_receipt_from_untrusted_kernel_key() {
    let dual_dispatch = hex_dispatch();
    let mut config = sample_config();
    config.chain_id = dual_dispatch.chain_id.clone();
    config.escrow_contract = dual_dispatch.escrow_contract.clone();
    let receipt = sample_receipt(
        &instruction_keypair(),
        "cap-dual-untrusted",
        "rcpt-dual-untrusted",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    let error = prepare_dual_sign_release(
        &config,
        &dual_dispatch,
        &receipt,
        &DualSignReleaseInput::new(
            "0x1000000000000000000000000000000000000000000000000000000000000002",
            dual_dispatch.settlement_amount.clone(),
        ),
    )
    .await
    .test_expect_err("an untrusted kernel key should block dual-sign prep");
    assert!(
        matches!(
            &error,
            SettlementError::Verification(message)
                if message == "receipt kernel_key is not a trusted settlement kernel key"
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn dual_sign_release_refuses_receipt_from_rotated_out_kernel_key() {
    let dual_dispatch = hex_dispatch();
    let mut config = sample_config();
    config.chain_id = dual_dispatch.chain_id.clone();
    config.escrow_contract = dual_dispatch.escrow_contract.clone();
    let receipt = sample_receipt(
        &operator_keypair(),
        "cap-dual-rotated",
        "rcpt-dual-rotated",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    let input = DualSignReleaseInput::new(
        "0x1000000000000000000000000000000000000000000000000000000000000002",
        dual_dispatch.settlement_amount.clone(),
    );
    config.kernel_authority.trusted_keys = vec![
        operator_keypair().public_key(),
        instruction_keypair().public_key(),
    ];
    assert!(config.kernel_authority.trusts(&receipt.kernel_key));
    config.kernel_authority.trusted_keys = vec![instruction_keypair().public_key()];

    let error = prepare_dual_sign_release(&config, &dual_dispatch, &receipt, &input)
        .await
        .test_expect_err("a rotated-out kernel key should block dual-sign prep");
    assert!(
        matches!(
            &error,
            SettlementError::Verification(message)
                if message == "receipt kernel_key is not a trusted settlement kernel key"
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn dual_sign_release_refuses_trusted_kernel_key_over_foreign_signature() {
    let dual_dispatch = hex_dispatch();
    let mut config = sample_config();
    config.chain_id = dual_dispatch.chain_id.clone();
    config.escrow_contract = dual_dispatch.escrow_contract.clone();
    let mut receipt = sample_receipt(
        &instruction_keypair(),
        "cap-dual-relabelled",
        "rcpt-dual-relabelled",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    receipt.kernel_key = operator_keypair().public_key();
    let error = prepare_dual_sign_release(
        &config,
        &dual_dispatch,
        &receipt,
        &DualSignReleaseInput::new(
            "0x1000000000000000000000000000000000000000000000000000000000000002",
            dual_dispatch.settlement_amount.clone(),
        ),
    )
    .await
    .test_expect_err("a relabelled kernel key should block dual-sign prep");
    assert!(
        matches!(
            &error,
            SettlementError::Verification(message)
                if message == "receipt signature verification failed"
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn dual_sign_release_accepts_receipt_from_any_trusted_kernel_key() {
    let dual_dispatch = hex_dispatch();
    let operator_private_key = "0x1000000000000000000000000000000000000000000000000000000000000002";
    let registry_block_hash = "0xefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
    let server = MockJsonRpcServer::spawn(vec![
        rpc_result(json!({
            "number": "0x65",
            "hash": registry_block_hash,
            "timestamp": "0x6553f100"
        })),
        rpc_result(json!(encode_hex(
            IChioIdentityRegistry::getOperatorCall::abi_encode_returns(
                &IChioIdentityRegistry::OperatorRecord {
                    edKeyHash: parse_b256_hex(
                        &dual_dispatch.operator_key_hash,
                        "dual_dispatch.operator_key_hash",
                    )
                    .test_unwrap(),
                    settlementKey: signer_address_from_private_key(operator_private_key)
                        .test_unwrap(),
                    registeredAt: 7,
                    operatorEpoch: 1,
                    active: true,
                },
            )
        ))),
        rpc_result(json!({
            "number": "0x65",
            "hash": registry_block_hash,
            "timestamp": "0x6553f100"
        })),
    ]);
    let mut config = sample_config_with_rpc_url(server.base_url());
    config.chain_id = dual_dispatch.chain_id.clone();
    config.escrow_contract = dual_dispatch.escrow_contract.clone();
    config.kernel_authority.trusted_keys = vec![
        instruction_keypair().public_key(),
        operator_keypair().public_key(),
    ];
    let receipt = sample_receipt(
        &operator_keypair(),
        "cap-dual-trusted",
        "rcpt-dual-trusted",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    let release = prepare_dual_sign_release(
        &config,
        &dual_dispatch,
        &receipt,
        &DualSignReleaseInput::new(
            operator_private_key,
            dual_dispatch.settlement_amount.clone(),
        ),
    )
    .await
    .test_expect("a receipt from a trusted kernel key should prepare");
    assert_eq!(release.call.to_address, config.escrow_contract);
    assert_eq!(release.observed_amount, dual_dispatch.settlement_amount);
    server.join();
}

#[tokio::test]
async fn dual_sign_release_rejects_identity_registry_key_hash_mismatch() {
    let dual_dispatch = hex_dispatch();
    let operator_private_key = "0x1000000000000000000000000000000000000000000000000000000000000002";
    let registry_block_hash = "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    let server = MockJsonRpcServer::spawn(vec![
        rpc_result(json!({
            "number": "0x65",
            "hash": registry_block_hash,
            "timestamp": "0x6553f100"
        })),
        rpc_result(json!(encode_hex(
            IChioIdentityRegistry::getOperatorCall::abi_encode_returns(
                &IChioIdentityRegistry::OperatorRecord {
                    edKeyHash: B256::from([0x99; 32]),
                    settlementKey: signer_address_from_private_key(operator_private_key)
                        .test_unwrap(),
                    registeredAt: 1,
                    operatorEpoch: 1,
                    active: true,
                },
            )
        ))),
        rpc_result(json!({
            "number": "0x65",
            "hash": registry_block_hash,
            "timestamp": "0x6553f100"
        })),
    ]);
    let mut config = sample_config_with_rpc_url(server.base_url());
    config.chain_id = dual_dispatch.chain_id.clone();
    config.escrow_contract = dual_dispatch.escrow_contract.clone();
    let receipt = sample_receipt(
        &operator_keypair(),
        "cap-dual-mismatch",
        "rcpt-dual-mismatch",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    let error = prepare_dual_sign_release(
        &config,
        &dual_dispatch,
        &receipt,
        &DualSignReleaseInput::new(
            operator_private_key,
            dual_dispatch.settlement_amount.clone(),
        ),
    )
    .await
    .test_expect_err("registry key hash mismatch should block dual-sign prep");
    assert!(error.to_string().contains("operator key hash"));
    server.join();
}

#[tokio::test]
async fn dual_sign_release_rejects_unpinned_registry_block() {
    let dual_dispatch = hex_dispatch();
    let operator_private_key = "0x1000000000000000000000000000000000000000000000000000000000000002";
    let server = MockJsonRpcServer::spawn(vec![rpc_result(json!({
        "number": "0x65",
        "timestamp": "0x6553f100"
    }))]);
    let mut config = sample_config_with_rpc_url(server.base_url());
    config.chain_id = dual_dispatch.chain_id.clone();
    config.escrow_contract = dual_dispatch.escrow_contract.clone();
    let receipt = sample_receipt(
        &operator_keypair(),
        "cap-dual-unpinned",
        "rcpt-dual-unpinned",
        dual_dispatch.settlement_amount.units,
        &dual_dispatch.beneficiary_address,
    );
    let error = prepare_dual_sign_release(
        &config,
        &dual_dispatch,
        &receipt,
        &DualSignReleaseInput::new(
            operator_private_key,
            dual_dispatch.settlement_amount.clone(),
        ),
    )
    .await
    .test_expect_err("missing registry block hash should block dual-sign prep");
    assert!(error.to_string().contains("block missing hash"));
    server.join();
}
