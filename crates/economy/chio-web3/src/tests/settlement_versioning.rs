use super::*;

const RETIRED_DISPATCH_SCHEMA: &str = "chio.web3-settlement-dispatch.v2";
const RETIRED_RECEIPT_SCHEMA: &str = "chio.web3-settlement-execution-receipt.v2";

#[test]
fn web3_settlement_dispatch_refuses_retired_schema() {
    let mut dispatch = sample_dispatch();
    dispatch.schema = RETIRED_DISPATCH_SCHEMA.to_string();
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch, &capital_authority()),
        Err(Web3ContractError::UnsupportedSchema(schema)) if schema == RETIRED_DISPATCH_SCHEMA
    ));
}

#[test]
fn web3_settlement_receipt_refuses_retired_receipt_and_dispatch_schemas() {
    let mut receipt = sample_execution_receipt();
    receipt.schema = RETIRED_RECEIPT_SCHEMA.to_string();
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt, &capital_authority()),
        Err(Web3ContractError::UnsupportedSchema(schema)) if schema == RETIRED_RECEIPT_SCHEMA
    ));

    let mut receipt = sample_execution_receipt();
    receipt.dispatch.schema = RETIRED_DISPATCH_SCHEMA.to_string();
    assert!(matches!(
        validate_web3_settlement_execution_receipt(&receipt, &capital_authority()),
        Err(Web3ContractError::UnsupportedSchema(schema)) if schema == RETIRED_DISPATCH_SCHEMA
    ));
}

#[test]
fn public_settlement_proof_refuses_retired_receipt_schema() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.schema = RETIRED_RECEIPT_SCHEMA.to_string();
    bundle.settlement_receipt.dispatch.schema = RETIRED_DISPATCH_SCHEMA.to_string();
    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message == "public settlement proof requires v1 receipt and dispatch schemas"
    ));
}

#[test]
fn web3_settlement_dispatch_without_token_or_operator_key_does_not_deserialize() {
    for field in ["settlement_token_address", "operator_key_hash"] {
        let mut value = serde_json::to_value(sample_dispatch()).unwrap();
        value.as_object_mut().unwrap().remove(field);
        let error = serde_json::from_value::<Web3SettlementDispatchArtifact>(value)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), format!("missing field `{field}`"));
    }
}

#[test]
fn web3_settlement_dispatch_refuses_zero_operator_key_hash() {
    let mut dispatch = sample_dispatch();
    dispatch.operator_key_hash = Hash::zero().to_hex_prefixed();
    assert!(matches!(
        validate_web3_settlement_dispatch(&dispatch, &capital_authority()),
        Err(Web3ContractError::InvalidSettlement(message))
            if message == "web3 settlement dispatch operator_key_hash must not be zero"
    ));
}
